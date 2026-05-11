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

// Phase B3 / B6 of the NAT-T port (see .archive/eMuleAI-nat-t-implementation-plan.md
// cluster 6, sub-commits B3 + B6). One CUtpLayer wraps one libutp
// connection plus the application-side write buffer (16 KiB) and
// read buffer (64 KiB) that adapt libutp's async windowing model to
// the synchronous "Send buf / Recv buf" API CUpDownClient expects.
//
// Lifecycle / state machine (outbound case, the only one supported
// in Phase B):
//
//   layer = new CUtpLayer(ctx);                         // state = INIT
//   layer->Connect(our_hash, peer_hash, peer_addr, ..); // → KEY_FRAME_SENT
//                                                       // (Key Frame sent)
//   ... peer's Key Frame arrives over the wire ...
//   layer->OnPeerKeyFrame(sender_hash);                 // → UTP_CONNECTING
//                                                       // (utp_connect fired,
//                                                       //  libutp SYN out)
//   layer->OnStateChange(UTP_STATE_CONNECT);            // → CONNECTED
//   layer->Send(payload, n);                            // app-level writes
//   layer->OnRead(data, len);                           // app-level reads
//   layer->Recv(outbuf, n);
//   layer->Close();                                     // → CLOSED
//   delete layer;
//
//   Off-the-happy-path:
//   - Timeout (no peer Key Frame in kKeyFrameTimeoutMs):    → FAILED
//   - libutp error (UTP_ECONNREFUSED / RESET / TIMEDOUT):   → FAILED
//   - libutp UTP_STATE_DESTROYING:                          → CLOSED
//
// Threading: public methods (Connect / OnPeerKeyFrame / Send / Recv /
// Close / CheckTimeout / IsXxx accessors / GetState) acquire
// UtpEnvironment::RuntimeLock. libutp-callback dispatch methods
// (OnStateChange / OnRead / OnError / OnGetReadBufferSize) assume
// the lock is already held — they are invoked by the static
// UtpCallbacks functions which run while libutp's caller is inside
// UtpEnvironment::RuntimeLock. Callback methods must NOT re-acquire
// the lock (std::mutex is non-recursive).

#include <chrono>
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
	// Per-connection state machine. See the file-header comment for
	// the transition diagram.
	enum class State : int {
		INIT             = 0,  // before Connect()
		KEY_FRAME_SENT   = 1,  // our Key Frame sent; waiting for peer's
		UTP_CONNECTING   = 2,  // peer Key Frame received; utp_connect
		                       // fired; waiting for UTP_STATE_CONNECT
		CONNECTED        = 3,  // UTP_STATE_CONNECT or WRITABLE seen
		FAILED           = 4,  // timeout or libutp error
		CLOSED           = 5,  // Close() or UTP_STATE_DESTROYING
	};

	// Maximum outbound bytes buffered between Send() and libutp's
	// CWND-allowed drain. eMuleAI uses 16 KiB; we match (plan Q5).
	static constexpr std::size_t kWriteBufferCapacity = 16 * 1024;

	// Maximum inbound bytes buffered between libutp's on_read
	// delivery and the app's Recv(). 64 KiB is comfortably above
	// the largest single-MTU delivery libutp can produce, leaving
	// headroom for a few packets of jitter buffer.
	static constexpr std::size_t kReadBufferCapacity = 64 * 1024;

	// User hash size (CMD4Hash) — duplicated locally so this header
	// doesn't pull in CMD4Hash.h. Must match
	// UtpEncryption::kUserHashSize and UtpKeyFrame::kUserHashSize.
	static constexpr std::size_t kUserHashSize = 16;

	// Time the layer is allowed to spend in KEY_FRAME_SENT before
	// CheckTimeout transitions to FAILED. 12 s matches the plan's
	// RENDEZVOUSFALLBACKDELAY (Cluster 9, Phase E2) — the policy is
	// "if the peer Key Frame doesn't arrive in 12 seconds, give up
	// and fall back to TCP". The matching wxTimer that drives
	// CheckTimeout periodically lives in Phase B7.
	static constexpr std::uint64_t kKeyFrameTimeoutMs = 12000;

	explicit CUtpLayer(utp_context* ctx);
	~CUtpLayer();

	// Disable copy/move — the utp_socket userdata pointer holds a
	// raw reference to `this`, so the layer's address must not
	// change after Connect().
	CUtpLayer(const CUtpLayer&) = delete;
	CUtpLayer& operator=(const CUtpLayer&) = delete;
	CUtpLayer(CUtpLayer&&) = delete;
	CUtpLayer& operator=(CUtpLayer&&) = delete;

	// Initiate the NAT-T handshake:
	//   1. Build and send a Key Frame to peer (via
	//      UtpEncryption::WrapKeyFrame using peer_hash as the key,
	//      then UtpCallbacks' SendRaw helper).
	//   2. Record our_hash, peer_hash, peer_addr for later steps.
	//   3. Transition INIT → KEY_FRAME_SENT.
	//
	// Returns false on prerequisite failures:
	//   - Layer already past INIT.
	//   - NULL pointers, zero-length address.
	//   - WrapKeyFrame fails (no encrypt delegate, etc.).
	//   - SendRaw fails (no sendto delegate, etc.).
	bool Connect(const std::uint8_t our_hash[kUserHashSize],
	             const std::uint8_t peer_hash[kUserHashSize],
	             const struct sockaddr* peer_addr, socklen_t addr_len);

	// Called by the inbound-dispatch path (CClientUDPSocket) when a
	// sub-byte-0xFF Key Frame arrives whose sender_hash matches
	// (one of) the layers waiting in KEY_FRAME_SENT. The current
	// Phase B6 wiring only verifies the embedded sender_hash equals
	// the peer_hash we recorded in Connect; layer-routing (which
	// layer's OnPeerKeyFrame to call, when multiple layers exist)
	// is solved upstream — this method just refuses to advance on a
	// hash mismatch.
	//
	// On match: creates a utp_socket via utp_create_socket, attaches
	// `this` as utp_set_userdata, calls utp_connect against the
	// recorded peer_addr, transitions KEY_FRAME_SENT → UTP_CONNECTING.
	//
	// Returns true iff a state transition occurred.
	bool OnPeerKeyFrame(const std::uint8_t sender_hash[kUserHashSize]);

	// Manual time-based timeout driver. `elapsed_ms` is the time
	// since Connect() was called, in milliseconds — kept for tests
	// that need deterministic clock control. Production code uses
	// CheckTimeoutNow() (below) instead.
	//
	// Effect: if state is KEY_FRAME_SENT and elapsed_ms >=
	// kKeyFrameTimeoutMs, transition to FAILED.
	//
	// Returns true iff a state transition occurred.
	bool CheckTimeout(std::uint64_t elapsed_ms);

	// Steady-clock variant: computes elapsed_ms from the timestamp
	// Connect() recorded internally, then delegates to CheckTimeout.
	// This is what UtpTimer drives from its 50 ms tick. Returns true
	// iff a state transition occurred; returns false (no-op) if
	// Connect() was never called.
	bool CheckTimeoutNow();

	// Buffer up to count bytes for outbound transmission. Returns
	// the number of bytes accepted into the buffer (0..count).
	std::int64_t Send(const void* buf, std::size_t count);

	// Copy up to count bytes from the read buffer into buf, returning
	// the number copied. Non-blocking; FIFO drain.
	std::int64_t Recv(void* buf, std::size_t count);

	// Mark the layer closed (state → CLOSED) and request libutp to
	// FIN the connection. Idempotent.
	void Close();

	// State inspection / test-helper accessors. All take the runtime
	// lock.
	State       GetState() const;
	bool        IsClosed()   const;  // CLOSED or FAILED
	bool        IsConnected() const; // CONNECTED
	bool        IsWritable()  const;
	std::size_t WriteBufferSize() const;
	std::size_t ReadBufferSize()  const;

	// Copy the peer's recorded user hash into `out` (must point at
	// kUserHashSize bytes). Returns true if Connect() has been called
	// (the hash is set) and the copy succeeded. Used by
	// UtpCallbacks::on_sendto to wrap outbound uTP frames with
	// UtpEncryption::WrapUtpFrame.
	bool GetPeerHash(std::uint8_t out[kUserHashSize]) const;

	// Called by UtpCallbacks::on_sendto when libutp wants to emit
	// bytes for this layer's socket. Wraps the bytes via
	// UtpEncryption::WrapUtpFrame (using the recorded peer_hash as
	// the encryption key) and pushes the resulting envelope through
	// UtpCallbacks::SendRaw. If the wrap fails (no encrypt delegate,
	// etc.), the packet is silently dropped — mandatory-encryption
	// guarantee.
	//
	// Lock NOT acquired here (caller — libutp via UtpCallbacks —
	// already holds RuntimeLock).
	void OnSendto(const std::uint8_t* buf, std::size_t len,
	              const struct sockaddr* to, socklen_t to_len);

	// --- libutp callback dispatch -----------------------------------
	//
	// Invoked by the static UtpCallbacks functions via
	// utp_get_userdata(socket). Run with RuntimeLock already held;
	// must NOT re-acquire it.

	void OnStateChange(int new_state);
	void OnRead(const std::uint8_t* data, std::size_t len);
	void OnError(int error_code);
	std::size_t OnGetReadBufferSize() const;

private:
	// Drain the write buffer through utp_write while libutp has CWND
	// room. Caller holds RuntimeLock.
	void DrainWriteBufferLocked();

	// Detach and close the libutp socket (utp_set_userdata to NULL,
	// utp_close). Caller holds RuntimeLock. Idempotent.
	void TeardownSocketLocked();

	utp_context* m_ctx;            // borrowed, not owned
	utp_socket*  m_socket;         // owned by libutp; we hold a ref

	State m_state;
	bool  m_writable;              // libutp CWND has room; orthogonal to State

	// Hashes + address recorded by Connect for later validation /
	// libutp dispatch in OnPeerKeyFrame. Sized to kUserHashSize each;
	// the address is stored in a sockaddr_storage-sized buffer so
	// either V4 or V6 can be saved (in practice Phase B is V4-only).
	std::uint8_t  m_our_hash[kUserHashSize];
	std::uint8_t  m_peer_hash[kUserHashSize];
	std::vector<std::uint8_t> m_peer_addr;  // raw sockaddr bytes
	socklen_t                 m_peer_addr_len;

	std::vector<std::uint8_t> m_writeBuf;
	std::vector<std::uint8_t> m_readBuf;

	// Timestamp recorded when Connect() transitions to KEY_FRAME_SENT.
	// Used by CheckTimeoutNow() to compute elapsed_ms from steady_clock.
	// Default-constructed value (epoch) indicates "Connect not called
	// yet" — CheckTimeoutNow short-circuits in that case so the
	// per-tick sweep in UtpTimer doesn't fire timeouts on layers that
	// haven't started a handshake.
	std::chrono::steady_clock::time_point m_connect_started_at;
};

#endif // ENABLE_NAT_T

#endif // UTPLAYER_H
