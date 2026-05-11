//								-*- C++ -*-
// This file is part of the aMule Project.
//
// Copyright (c) 2026 aMule Team ( admin@amule.org / http://www.amule.org )
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
//

#include "UtpLayer.h"

#ifdef ENABLE_NAT_T

#include "UtpEnvironment.h"

#include <utp.h>

#include <algorithm>
#include <cstring>
#include <mutex>

// Out-of-class definitions for the constexpr static members.
// Required pre-C++17 when these are ODR-used (e.g. taking their
// address or binding to a reference, which our test fixture does
// implicitly through ASSERT_EQUALS). C++17 makes static constexpr
// members implicitly inline; defining them here costs nothing and
// stays portable to the older standards the project supports.
constexpr std::size_t CUtpLayer::kWriteBufferCapacity;
constexpr std::size_t CUtpLayer::kReadBufferCapacity;

CUtpLayer::CUtpLayer(utp_context* ctx)
	: m_ctx(ctx)
	, m_socket(NULL)
	, m_connected(false)
	, m_writable(false)
	, m_closed(false)
{
	// Pre-reserve capacity to avoid reallocations during steady-state
	// traffic. erase-from-front in the drain path still costs O(n),
	// but the practical n is bounded by 16 KiB so memmoves of that
	// size at packet rate are noise next to libutp's own work.
	m_writeBuf.reserve(kWriteBufferCapacity);
	m_readBuf.reserve(kReadBufferCapacity);
}

CUtpLayer::~CUtpLayer()
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());

	if (m_socket != NULL) {
		// Detach userdata before close so any callback libutp might
		// fire during the close (state change to DESTROYING etc.) can
		// no longer dereference this layer — matches eMuleAI's
		// UtpSocket.cpp:1490 pattern.
		utp_set_userdata(m_socket, NULL);
		utp_close(m_socket);
		m_socket = NULL;
	}
}

bool CUtpLayer::Connect(const struct sockaddr* to, socklen_t to_len)
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());

	if (m_ctx == NULL || m_socket != NULL || m_closed ||
	    to == NULL || to_len == 0) {
		return false;
	}

	m_socket = utp_create_socket(m_ctx);
	if (m_socket == NULL) {
		return false;
	}
	utp_set_userdata(m_socket, this);

	int rc = utp_connect(m_socket, to, to_len);
	if (rc != 0) {
		// Roll back: utp_connect rejected the address. libutp's
		// socket allocation is undone via utp_close; userdata is
		// cleared so we won't get back-callbacks against a layer
		// that never made it onto the wire.
		utp_set_userdata(m_socket, NULL);
		utp_close(m_socket);
		m_socket = NULL;
		return false;
	}

	return true;
}

std::int64_t CUtpLayer::Send(const void* buf, std::size_t count)
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());

	if (m_closed || buf == NULL || count == 0) {
		return 0;
	}

	const std::size_t available = kWriteBufferCapacity - m_writeBuf.size();
	const std::size_t to_buffer = std::min(count, available);
	if (to_buffer == 0) {
		// Buffer full. Caller must wait for OnStateChange(WRITABLE)
		// to drain capacity before retrying.
		return 0;
	}

	const std::uint8_t* p = static_cast<const std::uint8_t*>(buf);
	m_writeBuf.insert(m_writeBuf.end(), p, p + to_buffer);

	// Opportunistic drain — if libutp's CWND has room right now,
	// push some bytes immediately rather than waiting for the next
	// WRITABLE callback. The plan-Q5 "internal write buffer" pattern.
	if (m_writable && m_socket != NULL) {
		DrainWriteBufferLocked();
	}

	return static_cast<std::int64_t>(to_buffer);
}

std::int64_t CUtpLayer::Recv(void* buf, std::size_t count)
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());

	if (buf == NULL || count == 0 || m_readBuf.empty()) {
		return 0;
	}

	const std::size_t to_copy = std::min(count, m_readBuf.size());
	std::memcpy(buf, m_readBuf.data(), to_copy);
	m_readBuf.erase(m_readBuf.begin(),
	                m_readBuf.begin() + static_cast<std::ptrdiff_t>(to_copy));
	return static_cast<std::int64_t>(to_copy);
}

void CUtpLayer::Close()
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());

	if (m_closed) {
		return;
	}
	m_closed = true;
	m_writable = false;

	if (m_socket != NULL) {
		utp_set_userdata(m_socket, NULL);
		utp_close(m_socket);
		m_socket = NULL;
	}
}

bool CUtpLayer::IsClosed() const
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
	return m_closed;
}

bool CUtpLayer::IsConnected() const
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
	return m_connected;
}

bool CUtpLayer::IsWritable() const
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
	return m_writable;
}

std::size_t CUtpLayer::WriteBufferSize() const
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
	return m_writeBuf.size();
}

std::size_t CUtpLayer::ReadBufferSize() const
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
	return m_readBuf.size();
}

// --- Callback dispatch (caller holds RuntimeLock) --------------------

void CUtpLayer::OnStateChange(int new_state)
{
	// Lock NOT acquired here — caller (libutp via UtpCallbacks) holds it.
	switch (new_state) {
		case UTP_STATE_CONNECT:
		case UTP_STATE_WRITABLE:
			m_connected = true;
			m_writable  = true;
			DrainWriteBufferLocked();
			break;

		case UTP_STATE_EOF:
			// Remote side cleanly closed. We're not writable any more
			// but the app may still drain residual bytes from the read
			// buffer; only set closed once the read buffer is empty
			// and the caller acknowledges via its own Recv loop. For
			// now, stop accepting writes — Recv continues to work.
			m_writable = false;
			break;

		case UTP_STATE_DESTROYING:
			// libutp is freeing the socket. Drop our reference. The
			// layer object itself stays alive (owned by the caller);
			// it just becomes a buffer-only zombie until destroyed.
			m_socket   = NULL;
			m_writable = false;
			m_closed   = true;
			break;

		default:
			// Unknown state — defensively ignore.
			break;
	}
}

void CUtpLayer::OnRead(const std::uint8_t* data, std::size_t len)
{
	// Lock NOT acquired here — caller (libutp via UtpCallbacks) holds it.
	if (data == NULL || len == 0) {
		return;
	}

	const std::size_t available = kReadBufferCapacity - m_readBuf.size();
	const std::size_t to_copy = std::min(len, available);
	if (to_copy > 0) {
		m_readBuf.insert(m_readBuf.end(), data, data + to_copy);
	}

	// Tell libutp we consumed the delivery. If we couldn't take all
	// of it (buffer was full), the next OnGetReadBufferSize will
	// return 0 and libutp will apply backpressure on the sender.
	if (m_socket != NULL) {
		utp_read_drained(m_socket);
	}
}

void CUtpLayer::OnError(int /*error_code*/)
{
	// Lock NOT acquired here — caller (libutp via UtpCallbacks) holds it.
	m_closed   = true;
	m_writable = false;
}

std::size_t CUtpLayer::OnGetReadBufferSize() const
{
	// Lock NOT acquired here — caller (libutp via UtpCallbacks) holds it.
	return kReadBufferCapacity - m_readBuf.size();
}

void CUtpLayer::DrainWriteBufferLocked()
{
	// Caller (any path that reaches this) must hold RuntimeLock.
	while (!m_writeBuf.empty() && m_socket != NULL && m_writable && !m_closed) {
		const ssize_t wrote = utp_write(m_socket,
		                                m_writeBuf.data(),
		                                m_writeBuf.size());
		if (wrote <= 0) {
			// libutp's CWND is full or it refused for some other
			// reason. Mark non-writable; the next UTP_STATE_WRITABLE
			// callback will retry the drain. Bytes stay buffered.
			m_writable = false;
			return;
		}
		m_writeBuf.erase(m_writeBuf.begin(),
		                 m_writeBuf.begin() + static_cast<std::ptrdiff_t>(wrote));
	}
}

#endif // ENABLE_NAT_T
