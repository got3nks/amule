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

#include "UtpCallbacks.h"

#ifdef ENABLE_NAT_T

#include <utp.h>

namespace UtpCallbacks {

namespace {

// Per-process sendto delegate. libutp invokes our on_sendto callback
// during outbound packet emission (utp_connect, utp_write triggers,
// retransmits, FIN/RST emission). The delegate is the only thing that
// turns those bytes into actual UDP packets on the wire.
//
// Set/read concurrency: the delegate is set once at startup (before
// any libutp activity, from the main thread) and read from within
// libutp callbacks (which already hold UtpEnvironment::RuntimeLock).
// The variables are therefore single-writer-multiple-reader after
// startup. No additional synchronization is added here — installing a
// delegate while libutp is concurrently invoking the previous one
// would be a use-after-free risk regardless of any local lock here.
SendtoFn g_sendto_fn = NULL;
void*    g_sendto_userdata = NULL;

// Default read-buffer size advertised to libutp via
// UTP_GET_READ_BUFFER_SIZE. 16 KiB matches eMuleAI's per-socket write
// buffer cap (see Phase B3 design Q5 in the plan). When CUtpLayer
// arrives in B3 the per-socket dispatch will instead consult the
// layer's own remaining-buffer capacity; until then this constant
// keeps libutp's congestion control from starving outbound writes.
constexpr int kDefaultReadBufferSize = 16 * 1024;

// --- The five callbacks ---------------------------------------------
//
// All five run inline on the thread that's already inside a libutp API
// call (utp_process_udp / utp_check_timeouts / utp_issue_deferred_acks
// / utp_write etc.). The caller holds UtpEnvironment::RuntimeLock for
// the duration of that API call, so the callbacks must NOT try to
// re-acquire RuntimeLock — that would deadlock on a non-recursive
// mutex. Long-running work belongs out-of-line via a posted event;
// callbacks must return quickly.

uint64_t on_state_change(utp_callback_arguments* a)
{
	// a->socket: the utp_socket whose state changed (may be NULL for
	//            context-level events, defensively check).
	// a->state:  one of UTP_STATE_CONNECT / WRITABLE / EOF / DESTROYING.
	//
	// Phase B2 stub: log only. B3 dispatches to CUtpLayer via
	// utp_get_userdata(a->socket) (the layer registers itself there
	// when it creates a libutp socket).
	(void)a;
	return 0;
}

uint64_t on_read(utp_callback_arguments* a)
{
	// a->socket: source socket
	// a->buf, a->len: payload bytes libutp has accumulated for us
	//
	// We MUST call utp_read_drained at the end to tell libutp the
	// bytes were consumed; otherwise libutp will keep replaying the
	// same buffer and stall the read side. B3 will push the bytes
	// into the CUtpLayer's read queue; for B2 we just drain so the
	// libutp state machine progresses (important if a test wires up
	// a peer pair against an unconfigured stub layer).
	if (a != NULL && a->socket != NULL) {
		utp_read_drained(a->socket);
	}
	return 0;
}

uint64_t on_sendto(utp_callback_arguments* a)
{
	// libutp gave us an outbound uTP packet, fully formed, ready for
	// UDP transmission. Forward to whoever owns the UDP transport.
	if (a == NULL || a->buf == NULL || a->len == 0 ||
	    a->address == NULL || a->address_len == 0) {
		// Malformed callback payload — refuse to forward garbage.
		return 0;
	}

	SendtoFn fn       = g_sendto_fn;
	void*    userdata = g_sendto_userdata;
	if (fn == NULL) {
		// No delegate installed — drop. Either nobody has wired up
		// the UDP transport yet (early startup) or this is a test
		// that explicitly doesn't care about outbound packets.
		return 0;
	}

	fn(userdata, a->buf, a->len, a->address, a->address_len);
	return 0;
}

uint64_t on_error(utp_callback_arguments* a)
{
	// a->socket: the connection that errored
	// a->error_code: UTP_ECONNREFUSED / UTP_ECONNRESET / UTP_ETIMEDOUT
	//
	// Phase B2 stub: log only. B3 dispatches to CUtpLayer to mark the
	// layer as dead so CUpDownClient (later) can clean up.
	(void)a;
	return 0;
}

uint64_t on_get_read_buffer_size(utp_callback_arguments* /*a*/)
{
	// libutp asks how much app-side buffer space remains for inbound
	// data. Returning 0 would tell libutp to stall the sender (apply
	// backpressure). Returning the full advertised buffer keeps the
	// flow open. B3 will query the per-socket CUtpLayer for its real
	// remaining capacity; until then we publish a constant ceiling.
	return (uint64_t)kDefaultReadBufferSize;
}

} // anonymous namespace

bool InstallOnContext(utp_context* ctx)
{
	if (ctx == NULL) {
		return false;
	}

	utp_set_callback(ctx, UTP_ON_STATE_CHANGE,      &on_state_change);
	utp_set_callback(ctx, UTP_ON_READ,              &on_read);
	utp_set_callback(ctx, UTP_SENDTO,               &on_sendto);
	utp_set_callback(ctx, UTP_ON_ERROR,             &on_error);
	utp_set_callback(ctx, UTP_GET_READ_BUFFER_SIZE, &on_get_read_buffer_size);

	return true;
}

void SetSendtoDelegate(SendtoFn fn, void* userdata)
{
	g_sendto_fn       = fn;
	g_sendto_userdata = userdata;
}

} // namespace UtpCallbacks

#endif // ENABLE_NAT_T
