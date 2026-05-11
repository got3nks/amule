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

#include "UtpLayer.h"

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
	// Phase B3: dispatch to CUtpLayer via utp_get_userdata(a->socket).
	// A NULL userdata means either (a) the socket was created outside
	// a CUtpLayer (e.g. in a test that exercises just the callback
	// wiring), or (b) the layer detached itself before close. Either
	// way, we silently skip.
	if (a == NULL || a->socket == NULL) {
		return 0;
	}
	CUtpLayer* layer = static_cast<CUtpLayer*>(utp_get_userdata(a->socket));
	if (layer != NULL) {
		layer->OnStateChange(a->state);
	}
	return 0;
}

uint64_t on_read(utp_callback_arguments* a)
{
	// a->socket: source socket
	// a->buf, a->len: payload bytes libutp has accumulated for us
	//
	// Phase B3: dispatch to CUtpLayer, which copies the bytes into
	// its read buffer and calls utp_read_drained itself. If no layer
	// is attached we must still drain so the libutp state machine
	// progresses (otherwise libutp would replay the same buffer
	// and stall the read side).
	if (a == NULL || a->socket == NULL) {
		return 0;
	}
	CUtpLayer* layer = static_cast<CUtpLayer*>(utp_get_userdata(a->socket));
	if (layer != NULL) {
		layer->OnRead(a->buf, a->len);
	} else {
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
	// Phase B3: dispatch to CUtpLayer so it can mark itself closed.
	if (a == NULL || a->socket == NULL) {
		return 0;
	}
	CUtpLayer* layer = static_cast<CUtpLayer*>(utp_get_userdata(a->socket));
	if (layer != NULL) {
		layer->OnError(a->error_code);
	}
	return 0;
}

uint64_t on_get_read_buffer_size(utp_callback_arguments* a)
{
	// libutp asks how much app-side buffer space remains for inbound
	// data. Returning 0 would tell libutp to stall the sender (apply
	// backpressure). Returning the full advertised buffer keeps the
	// flow open.
	//
	// Phase B3: when a CUtpLayer is attached, query its real
	// remaining capacity. With no layer (test setups, pre-B4 traffic
	// before key-frame exchange wires up a layer) fall back to the
	// kDefaultReadBufferSize constant — same as the Phase B2 behavior.
	if (a != NULL && a->socket != NULL) {
		CUtpLayer* layer = static_cast<CUtpLayer*>(utp_get_userdata(a->socket));
		if (layer != NULL) {
			return static_cast<uint64_t>(layer->OnGetReadBufferSize());
		}
	}
	return static_cast<uint64_t>(kDefaultReadBufferSize);
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

bool SendRaw(const std::uint8_t* buf, std::size_t len,
             const struct sockaddr* addr, socklen_t addr_len)
{
	SendtoFn fn       = g_sendto_fn;
	void*    userdata = g_sendto_userdata;
	if (fn == NULL || buf == NULL || len == 0 ||
	    addr == NULL || addr_len == 0) {
		return false;
	}

	fn(userdata, buf, len, addr, addr_len);
	return true;
}

} // namespace UtpCallbacks

#endif // ENABLE_NAT_T
