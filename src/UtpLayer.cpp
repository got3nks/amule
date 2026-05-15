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

#include "UtpCallbacks.h"
#include "UtpEncryption.h"
#include "UtpEnvironment.h"
#include "UtpLayerRegistry.h"

#include <utp.h>

#include <algorithm>
#include <cstring>
#include <mutex>

// Out-of-class definitions for the constexpr static members.
// Required pre-C++17 when these are ODR-used (e.g. binding to a
// reference through ASSERT_EQUALS). C++17 makes static constexpr
// members implicitly inline; defining them here stays portable.
constexpr std::size_t   CUtpLayer::kWriteBufferCapacity;
constexpr std::size_t   CUtpLayer::kReadBufferCapacity;
constexpr std::size_t   CUtpLayer::kUserHashSize;
constexpr std::uint64_t CUtpLayer::kKeyFrameTimeoutMs;

CUtpLayer::CUtpLayer(utp_context* ctx)
	: m_ctx(ctx)
	, m_socket(NULL)
	, m_state(State::INIT)
	, m_writable(false)
	, m_peer_addr_len(0)
	, m_initiator(true)
{
	std::memset(m_our_hash,  0, sizeof(m_our_hash));
	std::memset(m_peer_hash, 0, sizeof(m_peer_hash));
	// Pre-reserve to avoid reallocations during steady-state traffic.
	m_writeBuf.reserve(kWriteBufferCapacity);
	m_readBuf.reserve(kReadBufferCapacity);
}

CUtpLayer::~CUtpLayer()
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
	// Drop our registry entry before tearing down libutp resources.
	// A concurrent inbound dispatch that snapshotted our pointer
	// from FindByPeerHash before we entered the dtor is the layer
	// owner's responsibility to coordinate — see UtpLayerRegistry's
	// lifetime contract comment.
	UtpLayerRegistry::Unregister(this);
	TeardownSocketLocked();
}

bool CUtpLayer::Connect(const std::uint8_t our_hash[kUserHashSize],
                        const std::uint8_t peer_hash[kUserHashSize],
                        const struct sockaddr* peer_addr,
                        socklen_t addr_len,
                        bool initiator)
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());


	if (m_state != State::INIT ||
	    our_hash == NULL || peer_hash == NULL ||
	    peer_addr == NULL || addr_len == 0) {
		return false;
	}

	// Only the initiator sends a Key Frame on Connect — paired with
	// libutp's ST_SYN. The endpoint's Connect just registers the layer
	// so the inbound Key Frame from the initiator can be dispatched.
	// If the endpoint also sent a Key Frame, it would race with the
	// HOLEPUNCH burst the responder fires: the initiator could receive
	// the endpoint's Key Frame BEFORE its own OnInboundHolePunch match
	// has created its CUtpLayer, and drop it as "no layer registered."
	// eMuleAI emits the Key Frame only from CClientUDPSocket::SendUtpPacket
	// when packet type == 4 (ST_SYN), which only the initiator sends.
	if (initiator) {
		std::vector<std::uint8_t> key_frame;
		if (!UtpEncryption::WrapKeyFrame(our_hash, peer_hash, key_frame)) {
			return false;
		}
		if (!UtpCallbacks::SendRaw(key_frame.data(), key_frame.size(),
		                           peer_addr, addr_len)) {
			return false;
		}
	}

	// Record hashes + address for use in OnPeerKeyFrame, then enter
	// KEY_FRAME_SENT. The transition is intentionally last so any
	// failure above leaves the layer in INIT and the caller can
	// retry / fall back to TCP without an inconsistent state.
	std::memcpy(m_our_hash,  our_hash,  kUserHashSize);
	std::memcpy(m_peer_hash, peer_hash, kUserHashSize);
	m_peer_addr.assign(reinterpret_cast<const std::uint8_t*>(peer_addr),
	                   reinterpret_cast<const std::uint8_t*>(peer_addr) + addr_len);
	m_peer_addr_len        = addr_len;
	m_connect_started_at   = std::chrono::steady_clock::now();
	m_initiator            = initiator;
	m_state                = State::KEY_FRAME_SENT;

	// Publish in the process-wide registry under BOTH the peer's user
	// hash (used by the inbound Key Frame dispatch in
	// CClientUDPSocket::OnPacketReceived → OnPeerKeyFrame) AND the
	// peer's sockaddr (used by UtpCallbacks::on_sendto to find the
	// layer for outbound wrapping — libutp's send_to_addr path
	// passes a NULL socket pointer so we can't dispatch via
	// utp_get_userdata). The dtor unregisters both before freeing
	// layer state.
	UtpLayerRegistry::Register(m_peer_hash, this, peer_addr, addr_len);

	// Initiator: fire utp_connect immediately, don't wait for the
	// endpoint's Key Frame (the endpoint doesn't send one — see above).
	// Matches eMuleAI's flow: the endpoint just registers a passive
	// uTP socket and the initiator's SYN drives the handshake. The
	// Key Frame went out a few lines above (the `if (initiator)`
	// Key-Frame block); the SYN goes out now via utp_connect →
	// libutp → on_sendto.
	if (initiator) {
		if (m_ctx != NULL) {
			m_socket = utp_create_socket(m_ctx);
			if (m_socket != NULL) {
				utp_set_userdata(m_socket, this);
				int rc = utp_connect(m_socket,
					reinterpret_cast<const struct sockaddr*>(m_peer_addr.data()),
					m_peer_addr_len);
				if (rc == 0) {
					m_state = State::UTP_CONNECTING;
				} else {
					TeardownSocketLocked();
					m_state = State::FAILED;
				}
			} else {
				m_state = State::FAILED;
			}
		} else {
			m_state = State::FAILED;
		}
	} else {
	}

	return true;
}

bool CUtpLayer::OnPeerKeyFrame(const std::uint8_t sender_hash[kUserHashSize])
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());

	if (m_state != State::KEY_FRAME_SENT || sender_hash == NULL) {
		return false;
	}

	// Validate the embedded hash matches the peer we recorded on
	// Connect. A mismatch usually means the inbound dispatch routed
	// the Key Frame to the wrong layer (multiple connects in flight)
	// — leave us in KEY_FRAME_SENT so the correct dispatch can still
	// occur if/when the right Key Frame arrives.
	if (std::memcmp(sender_hash, m_peer_hash, kUserHashSize) != 0) {
		return false;
	}

	// Phase B8 responder path: we don't drive the uTP handshake; we
	// wait for libutp's UTP_ON_ACCEPT callback to deliver the
	// initiator's SYN, which OnUtpAccept will turn into a bound
	// socket. Just record the state transition.
	if (!m_initiator) {
		m_state = State::UTP_CONNECTING;
		return true;
	}

	// Initiator path: bring up the libutp side — create the socket,
	// register `this` so the static callbacks can dispatch into us,
	// then utp_connect fires the SYN through on_sendto.
	if (m_ctx == NULL) {
		m_state = State::FAILED;
		return true;
	}

	m_socket = utp_create_socket(m_ctx);
	if (m_socket == NULL) {
		m_state = State::FAILED;
		return true;
	}
	utp_set_userdata(m_socket, this);

	const struct sockaddr* peer = reinterpret_cast<const struct sockaddr*>(
		m_peer_addr.data());
	int rc = utp_connect(m_socket, peer, m_peer_addr_len);
	if (rc != 0) {
		// Roll back the socket allocation; never publish a broken layer.
		TeardownSocketLocked();
		m_state = State::FAILED;
		return true;
	}

	m_state = State::UTP_CONNECTING;
	return true;
}

void CUtpLayer::OnUtpAccept(utp_socket* accepted_socket)
{
	// Lock NOT acquired here — caller (libutp via UtpCallbacks::on_accept)
	// holds RuntimeLock around the utp_process_udp call that triggered
	// this on_accept invocation.

	if (accepted_socket == NULL) {
		return;
	}

	// Defensive: we already own a socket somehow (state transition
	// race?). Reject the new one rather than leaking the existing.
	if (m_socket != NULL) {
		utp_close(accepted_socket);
		return;
	}

	m_socket = accepted_socket;
	utp_set_userdata(m_socket, this);

	// libutp does NOT fire UTP_STATE_CONNECT on the responder side —
	// that callback is gated on CS_SYN_SENT → CS_CONNECTED, which
	// only the initiator does (utp_internal.cpp:2164). The responder
	// silently transitions CS_SYN_RECV → CS_CONNECTED on first
	// ST_DATA arrival (utp_internal.cpp:2160) with no callback. So
	// from the application's perspective, OnUtpAccept firing IS the
	// "connected" signal: libutp has accepted the SYN, sent its
	// ST_STATE response, and we're free to receive (and send, once
	// libutp's window allows). Transition straight to CONNECTED;
	// m_writable becomes true here too so any buffered Send() drains.
	m_state    = State::CONNECTED;
	m_writable = true;
	DrainWriteBufferLocked();
}

bool CUtpLayer::CheckTimeout(std::uint64_t elapsed_ms)
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());

	if (m_state == State::KEY_FRAME_SENT && elapsed_ms >= kKeyFrameTimeoutMs) {
		m_state    = State::FAILED;
		m_writable = false;
		return true;
	}
	return false;
}

bool CUtpLayer::CheckTimeoutNow()
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());

	if (m_state != State::KEY_FRAME_SENT) {
		// Fast path: timeouts only matter in KEY_FRAME_SENT. Saves
		// the steady_clock read for the common case where most
		// layers in the registry are in CONNECTED state.
		return false;
	}

	const auto now     = std::chrono::steady_clock::now();
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
		now - m_connect_started_at).count();
	if (elapsed >= static_cast<std::int64_t>(kKeyFrameTimeoutMs)) {
		m_state    = State::FAILED;
		m_writable = false;
		return true;
	}
	return false;
}

std::int64_t CUtpLayer::Send(const void* buf, std::size_t count)
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());


	if (m_state == State::CLOSED || m_state == State::FAILED ||
	    buf == NULL || count == 0) {
		return 0;
	}

	const std::size_t available = kWriteBufferCapacity - m_writeBuf.size();
	const std::size_t to_buffer = std::min(count, available);
	if (to_buffer == 0) {
		return 0;
	}

	const std::uint8_t* p = static_cast<const std::uint8_t*>(buf);
	m_writeBuf.insert(m_writeBuf.end(), p, p + to_buffer);

	if (m_writable && m_socket != NULL) {
		DrainWriteBufferLocked();
	}

	return static_cast<std::int64_t>(to_buffer);
}

std::int64_t CUtpLayer::Recv(void* buf, std::size_t count)
{
	std::function<void()> cb_to_fire;
	std::int64_t copied;
	{
		std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());

		if (buf == NULL || count == 0 || m_readBuf.empty()) {
			return 0;
		}

		const std::size_t to_copy = std::min(count, m_readBuf.size());
		std::memcpy(buf, m_readBuf.data(), to_copy);
		m_readBuf.erase(m_readBuf.begin(),
		                m_readBuf.begin() + static_cast<std::ptrdiff_t>(to_copy));
		copied = static_cast<std::int64_t>(to_copy);

		// Mirror LibSocketAsio's PostReadEvent(1): if the read buffer
		// still has bytes after this pop, schedule another OnReceive.
		// CEMSocket::OnReceive's do-while exits after each complete
		// packet (pendingHeaderSize resets to 0), so multi-packet uTP
		// frames need the caller re-entered. Without this, packet #2+
		// in the same frame stays in m_readBuf indefinitely.
		if (!m_readBuf.empty()) {
			cb_to_fire = m_data_available_cb;
		}
	}
	if (cb_to_fire) {
		cb_to_fire();
	}
	return copied;
}

void CUtpLayer::Close()
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());

	if (m_state == State::CLOSED) {
		return;
	}
	m_state    = State::CLOSED;
	m_writable = false;
	TeardownSocketLocked();
}

CUtpLayer::State CUtpLayer::GetState() const
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
	return m_state;
}

bool CUtpLayer::IsClosed() const
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
	return m_state == State::CLOSED || m_state == State::FAILED;
}

bool CUtpLayer::IsConnected() const
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
	return m_state == State::CONNECTED;
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

bool CUtpLayer::GetPeerHash(std::uint8_t out[kUserHashSize]) const
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
	if (m_state == State::INIT) {
		// Connect() never ran; peer_hash is the zero buffer from the
		// ctor. Reporting "no peer hash yet" lets callers (e.g.
		// on_sendto) drop rather than wrap with a garbage key.
		return false;
	}
	std::memcpy(out, m_peer_hash, kUserHashSize);
	return true;
}

// Calling libutp's utp_get_delays/utp_get_stats from inside a callback
// (OnRead/OnSendto runs under RuntimeLock + libutp's internal state at
// that moment) reliably crashes both initiator and responder. So skip
// those and just dump our own state — packet timing comes from strace.
static void PHASE_F_DUMP_STATS(utp_socket* sock, const char* tag,
                               std::size_t writebuf, std::size_t readbuf)
{
}

void CUtpLayer::OnSendto(const std::uint8_t* buf, std::size_t len,
                         const struct sockaddr* to, socklen_t to_len)
{
	// Lock NOT acquired here — caller (libutp via UtpCallbacks) holds it.
	// Only dump stats once we're past the initial SYN — m_socket isn't
	// fully wired until utp_connect returns, and utp_get_delays asserts
	// on CS_UNINITIALIZED sockets.
	if (m_state == State::CONNECTED) {
		PHASE_F_DUMP_STATS(m_socket, "OnSendto", m_writeBuf.size(), m_readBuf.size());
	}
	if (buf == NULL || len == 0 || to == NULL || to_len == 0) {
		return;
	}

	// Wrap with [0xB2, 0x00, encrypt-or-plaintext(packet, peer_hash)].
	// The encrypt delegate decides between ciphertext and plaintext
	// based on whether our publicIP is known (opportunistic
	// encryption — see UtpEncryption.h for rationale). If the delegate
	// itself fails (not installed, allocator error, etc.) the packet
	// is dropped — we never emit a half-wrapped frame.
	std::vector<std::uint8_t> wrapped;
	if (!UtpEncryption::WrapUtpFrame(buf, len, m_peer_hash, wrapped)) {
		return;
	}
	UtpCallbacks::SendRaw(wrapped.data(), wrapped.size(), to, to_len);
}

// --- Callback dispatch (caller holds RuntimeLock) --------------------

void CUtpLayer::OnStateChange(int new_state)
{
	// Lock NOT acquired here — caller (libutp via UtpCallbacks) holds it.
	switch (new_state) {
		case UTP_STATE_CONNECT:
		case UTP_STATE_WRITABLE:
			// First CONNECT/WRITABLE completes the handshake; further
			// WRITABLE events just keep refilling the CWND.
			if (m_state == State::UTP_CONNECTING ||
			    m_state == State::KEY_FRAME_SENT ||
			    m_state == State::INIT) {
				m_state = State::CONNECTED;
			}
			m_writable = true;
			DrainWriteBufferLocked();
			break;

		case UTP_STATE_EOF:
			// Remote side cleanly closed. Stop accepting writes but
			// keep Recv functional until the app drains residual
			// bytes from the read buffer.
			m_writable = false;
			break;

		case UTP_STATE_DESTROYING:
			// libutp is freeing the socket. Drop our reference and
			// mark the layer permanently dead. The CUtpLayer object
			// itself stays alive (owned by the caller); it just
			// becomes a buffer-only zombie until destroyed.
			m_socket   = NULL;
			m_writable = false;
			m_state    = State::CLOSED;
			break;

		default:
			break;
	}
}

void CUtpLayer::OnRead(const std::uint8_t* data, std::size_t len)
{
	if (m_state == State::CONNECTED) {
		PHASE_F_DUMP_STATS(m_socket, "OnRead", m_writeBuf.size(), m_readBuf.size());
	}
	// Lock NOT acquired here — caller (libutp via UtpCallbacks) holds it.
	if (data == NULL || len == 0) {
		return;
	}

	const std::size_t available = kReadBufferCapacity - m_readBuf.size();
	const std::size_t to_copy = std::min(len, available);
	if (to_copy > 0) {
		m_readBuf.insert(m_readBuf.end(), data, data + to_copy);
	}

	if (m_socket != NULL) {
		utp_read_drained(m_socket);
	}

	// Phase E3: notify the owning CClientTCPSocket (or test stub) that
	// fresh bytes are in the read buffer. Callback runs while we still
	// hold libutp's RuntimeLock; production wires it to a same-tread
	// async post (CoreNotify_LibSocketReceive), so the callback returns
	// immediately and the real OnReceive dispatch happens on the
	// main thread. Re-entrant libutp calls from the callback would
	// deadlock — contract documented at SetDataAvailableCallback.
	if (to_copy > 0 && m_data_available_cb) {
		m_data_available_cb();
	}
}

void CUtpLayer::SetDataAvailableCallback(DataAvailableCallback cb)
{
	std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
	m_data_available_cb = std::move(cb);
}

void CUtpLayer::OnError(int /*error_code*/)
{
	// Lock NOT acquired here — caller (libutp via UtpCallbacks) holds it.
	m_state    = State::FAILED;
	m_writable = false;
}

std::size_t CUtpLayer::OnGetReadBufferSize() const
{
	// Lock NOT acquired here — caller (libutp via UtpCallbacks) holds it.
	return kReadBufferCapacity - m_readBuf.size();
}

void CUtpLayer::DrainWriteBufferLocked()
{
	while (!m_writeBuf.empty() && m_socket != NULL && m_writable &&
	       m_state != State::CLOSED && m_state != State::FAILED) {
		const ssize_t wrote = utp_write(m_socket,
		                                m_writeBuf.data(),
		                                m_writeBuf.size());
		if (wrote <= 0) {
			// libutp's CWND is full or it refused. Mark non-writable;
			// the next UTP_STATE_WRITABLE callback retries the drain.
			m_writable = false;
			return;
		}
		m_writeBuf.erase(m_writeBuf.begin(),
		                 m_writeBuf.begin() + static_cast<std::ptrdiff_t>(wrote));
	}
}

void CUtpLayer::TeardownSocketLocked()
{
	if (m_socket != NULL) {
		// Detach userdata before close so any callback libutp might
		// fire during the close (state change to DESTROYING etc.)
		// can no longer dereference this layer — matches eMuleAI's
		// UtpSocket.cpp:1490 pattern.
		utp_set_userdata(m_socket, NULL);
		utp_close(m_socket);
		m_socket = NULL;
	}
}

#endif // ENABLE_NAT_T
