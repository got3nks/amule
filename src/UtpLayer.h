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

#ifndef UTPLAYER_H
#define UTPLAYER_H

#include "config.h"

#ifdef ENABLE_NAT_T

// Phase B3 of the NAT-T port (see .archive/eMuleAI-nat-t-implementation-plan.md
// cluster 6, sub-commit B3). One CUtpLayer wraps one libutp connection
// (the utp_socket) plus the application-side write buffer and read
// buffer that adapt libutp's async windowing model to the synchronous
// "Send buf / Recv buf" API CUpDownClient expects.
//
// Lifecycle (outbound case, the only one supported in Phase B):
//
//   layer = new CUtpLayer(ctx);           // no socket yet
//   layer->Connect(&peer_addr, sizeof);   // creates socket, utp_connect
//   layer->Send(payload, n);              // buffer + opportunistic flush
//   ... time passes; libutp drives the handshake ...
//   layer->OnStateChange(UTP_STATE_CONNECT);   // via callback
//   layer->OnStateChange(UTP_STATE_WRITABLE);  // drains buffered data
//   layer->OnRead(data, len);             // via callback, buffers inbound
//   layer->Recv(outbuf, n);               // app reads from read buffer
//   layer->Close();                       // utp_close (FIN)
//   delete layer;                         // dtor cleans up
//
// Threading: public methods (Send/Recv/Close/Connect/IsXxx) acquire
// UtpEnvironment::RuntimeLock. Callback-side methods (OnStateChange /
// OnRead / OnError / OnGetReadBufferSize) assume the lock is already
// held — they are invoked by the static UtpCallbacks functions which
// run while libutp's caller (utp_process_udp / utp_check_timeouts /
// etc.) is inside UtpEnvironment::RuntimeLock. Callback methods must
// NOT re-acquire the lock (std::mutex is non-recursive).
//
// CUtpLayer is intentionally testable without a real connection:
// the buffer logic works whether or not Connect() has been called.
// Tests construct a layer, exercise Send/Recv/OnRead/OnStateChange,
// and never touch the wire — the per-buffer invariants are all that
// matter at this phase.

#include <cstddef>
#include <cstdint>
#include <vector>

struct sockaddr;
typedef unsigned int socklen_t;

struct struct_utp_context;
typedef struct struct_utp_context utp_context;
struct UTPSocket;
typedef struct UTPSocket utp_socket;

class CUtpLayer
{
public:
	// Maximum outbound bytes buffered between Send() and libutp's
	// CWND-allowed drain. eMuleAI uses 16 KiB; we match (plan Q5).
	static constexpr std::size_t kWriteBufferCapacity = 16 * 1024;

	// Maximum inbound bytes buffered between libutp's on_read
	// delivery and the app's Recv(). 64 KiB is comfortably above
	// the largest single-MTU delivery libutp can produce, leaving
	// headroom for a few packets of jitter buffer.
	static constexpr std::size_t kReadBufferCapacity = 64 * 1024;

	// Constructor takes the utp_context the layer's eventual socket
	// will live under. The context is borrowed, not owned: it must
	// outlive the layer. Pass UtpEnvironment::GetContext() in
	// production; tests pass their own test-local context.
	//
	// No utp_socket is created here — Connect() does that. This
	// makes the constructor side-effect-free, which keeps tests of
	// the buffer logic simple (construct + Send/OnRead without
	// involving the wire).
	explicit CUtpLayer(utp_context* ctx);

	~CUtpLayer();

	// Disable copy/move — the utp_socket userdata pointer holds a
	// raw reference to `this`, so the layer's address must not
	// change after Connect().
	CUtpLayer(const CUtpLayer&) = delete;
	CUtpLayer& operator=(const CUtpLayer&) = delete;
	CUtpLayer(CUtpLayer&&) = delete;
	CUtpLayer& operator=(CUtpLayer&&) = delete;

	// Initiate the libutp connect handshake.
	//
	// Returns true if utp_create_socket succeeded and utp_connect was
	// accepted. The connection is *not* yet established when this
	// returns — completion is signalled by OnStateChange(UTP_STATE_CONNECT)
	// firing later via the libutp callback path. Pre-CONNECT bytes
	// passed to Send() sit in the write buffer and are released to
	// libutp once the WRITABLE state arrives.
	//
	// Returns false on programming-error paths: layer already closed,
	// already connected, NULL context, libutp allocation failure, or
	// utp_connect rejecting the address.
	bool Connect(const struct sockaddr* to, socklen_t to_len);

	// Buffer up to count bytes for outbound transmission. Returns
	// the number of bytes accepted into the buffer (0..count).
	//
	// If the buffer is full at call time, returns 0 (the caller must
	// retry later — typically after waiting for an EVT_WRITABLE-style
	// signal which libutp gives us via OnStateChange). This is the
	// "short-write" semantics the plan calls out (Q5).
	//
	// Bytes are flushed to libutp opportunistically: immediately
	// (this call) when the layer is in a writable state, otherwise
	// on the next OnStateChange(UTP_STATE_WRITABLE).
	std::int64_t Send(const void* buf, std::size_t count);

	// Copy up to count bytes from the read buffer into buf, returning
	// the number copied (0..count). Returns 0 if no data is
	// available; non-blocking. The buffer is drained FIFO.
	std::int64_t Recv(void* buf, std::size_t count);

	// Mark the layer closed and request libutp to FIN the connection.
	// Subsequent Send/Recv return 0. The libutp socket may still be
	// alive briefly while the FIN propagates; final destruction is
	// signalled by OnStateChange(UTP_STATE_DESTROYING).
	void Close();

	// Inspection / test-helper accessors. All take the runtime lock.
	bool IsClosed() const;
	bool IsConnected() const;     // ever transitioned to CONNECT/WRITABLE
	bool IsWritable() const;      // currently writable
	std::size_t WriteBufferSize() const;
	std::size_t ReadBufferSize() const;

	// --- libutp callback dispatch -----------------------------------
	//
	// These four methods are invoked by the static callbacks in
	// UtpCallbacks.cpp via utp_get_userdata(socket). They run on the
	// thread that's already inside a libutp API call, with
	// UtpEnvironment::RuntimeLock already held. They must NOT
	// re-acquire the lock.

	// Reacts to UTP_STATE_CONNECT / WRITABLE / EOF / DESTROYING.
	// CONNECT and WRITABLE set the writable flag and drain the
	// outbound buffer. DESTROYING is libutp's "the socket is being
	// freed" signal — the layer detaches its socket pointer.
	void OnStateChange(int new_state);

	// Receives len bytes from libutp. The data is copied into the
	// read buffer (up to kReadBufferCapacity) and utp_read_drained
	// is called so libutp's flow control progresses. If the read
	// buffer is already full, libutp will be told (via the next
	// OnGetReadBufferSize call) that we have no room — that is the
	// path that applies backpressure.
	void OnRead(const std::uint8_t* data, std::size_t len);

	// Connection-level error: refused / reset / timed-out. The layer
	// marks itself closed; the app will discover via IsClosed().
	void OnError(int error_code);

	// libutp asks how much room remains in the read buffer.
	// Returning 0 here causes libutp to apply backpressure.
	std::size_t OnGetReadBufferSize() const;

private:
	// Attempt to push the head of the write buffer through utp_write.
	// Called with the runtime lock already held. Stops when libutp's
	// CWND fills up (returns short or zero); the leftover bytes stay
	// in the buffer until the next WRITABLE callback.
	void DrainWriteBufferLocked();

	utp_context* m_ctx;           // borrowed, not owned
	utp_socket*  m_socket;        // owned by libutp; we hold a ref
	std::vector<std::uint8_t> m_writeBuf;
	std::vector<std::uint8_t> m_readBuf;
	bool m_connected;             // true after first CONNECT/WRITABLE
	bool m_writable;              // currently writable (CWND has room)
	bool m_closed;                // Close() called, EOF received, or
	                              // OnError fired, or socket destroyed
};

#endif // ENABLE_NAT_T

#endif // UTPLAYER_H
