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

#include "NetworkInfo.h"
#include "UtpLayer.h"
#include "UtpLayerRegistry.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <random>
#include <sys/socket.h>

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

uint64 on_state_change(utp_callback_arguments* a)
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

uint64 on_read(utp_callback_arguments* a)
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

uint64 on_sendto(utp_callback_arguments* a)
{
	// libutp gave us an outbound uTP packet, fully formed, ready for
	// UDP transmission. Forward to whoever owns the UDP transport.
	if (a == NULL || a->buf == NULL || a->len == 0 ||
	    a->address == NULL || a->address_len == 0) {
		// Malformed callback payload — refuse to forward garbage.
		return 0;
	}

	// Phase B7.5: if a CUtpLayer is registered for this destination
	// address (the typical production path), let it wrap the bytes
	// with the [0xB2, 0x00, encrypted] envelope before they hit the
	// wire. The layer's OnSendto handles the WrapUtpFrame + SendRaw
	// chain using the peer's user hash it recorded on Connect().
	//
	// Why look up by address rather than by a->socket: libutp's
	// send_to_addr (utp_internal.cpp:712) is the function that
	// ultimately invokes our on_sendto, and it ALWAYS passes NULL
	// for the socket pointer in the callback args. So
	// utp_get_userdata(a->socket) is unusable — we have to route
	// via the destination address instead, which the layer
	// registered alongside its peer_hash in Connect().
	//
	// Fallback (no layer registered for this addr): pass through raw.
	// This path is hit by tests that exercise libutp directly via
	// utp_create_socket without going through a CUtpLayer (e.g.
	// UtpCallbacksTest's ConnectTriggersSendtoDelegate). Real NAT-T
	// traffic always has a registered layer, so the wrap always
	// happens in production.
	CUtpLayer* layer = UtpLayerRegistry::FindByPeerAddr(a->address, a->address_len);
	if (layer != NULL) {
		layer->OnSendto(a->buf, a->len, a->address, a->address_len);
		return 0;
	}

	SendtoFn fn       = g_sendto_fn;
	void*    userdata = g_sendto_userdata;
	if (fn == NULL) {
		return 0;
	}

	fn(userdata, a->buf, a->len, a->address, a->address_len);
	return 0;
}

uint64 on_accept(utp_callback_arguments* a)
{
	// libutp created a fresh utp_socket for an incoming SYN that
	// didn't match any existing connection in the context. Phase B8:
	// look up the layer registered for the source address (the
	// responder pre-registered itself via Connect()'s peer_addr key).
	// If found, hand the socket to the layer; otherwise reject via
	// utp_close — matches eMuleAI's UtpSocket.cpp:629 pattern.
	if (a == NULL || a->socket == NULL || a->address == NULL) {
		return 0;
	}

	CUtpLayer* layer = UtpLayerRegistry::FindByPeerAddr(a->address, a->address_len);
	if (layer == NULL) {
		// Unsolicited incoming connection — drop. libutp's contract
		// for the on_accept callback is that the socket is "owned"
		// by us after the callback fires; closing it tells libutp
		// to tear it down.
		utp_close(a->socket);
		return 0;
	}

	layer->OnUtpAccept(a->socket);
	return 0;
}

uint64 on_error(utp_callback_arguments* a)
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

uint64 on_get_read_buffer_size(utp_callback_arguments* a)
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

// Monotonic clock for libutp time queries. Matches eMuleAI's
// GetTickCount()/QueryPerformanceCounter pair semantically — RTO and
// LEDBAT delay-sample timestamps need a monotonic source that never
// goes backwards.
static uint64_t MonotonicNanos()
{
	return std::chrono::duration_cast<std::chrono::nanoseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
}

static uint64 on_get_milliseconds(utp_callback_arguments* /*a*/)
{
	return MonotonicNanos() / 1000000ULL;
}

static uint64 on_get_microseconds(utp_callback_arguments* /*a*/)
{
	return MonotonicNanos() / 1000ULL;
}

// Family lookup helper: peer's address family decides MTU and overhead.
// Falls back to IPv4 when the socket isn't connected yet.
static int FamilyForCallback(utp_callback_arguments* a)
{
	if (a != NULL && a->socket != NULL) {
		struct sockaddr_storage sa;
		std::memset(&sa, 0, sizeof(sa));
		socklen_t sl = sizeof(sa);
		if (utp_getpeername(a->socket, (struct sockaddr*)&sa, &sl) == 0) {
			return (sa.ss_family == AF_INET6) ? AF_INET6 : AF_INET;
		}
	}
	return AF_INET;
}

static uint64 on_get_udp_mtu(utp_callback_arguments* a)
{
	// libutp expects the UDP-payload MTU (after IP+UDP headers stripped).
	// Use NetworkInfo::PathMtu when we have a usable ifindex; otherwise
	// fall back to family-aware defaults that match eMuleAI.
	int family = FamilyForCallback(a);

	if (a != NULL && a->socket != NULL) {
		struct sockaddr_storage sa;
		std::memset(&sa, 0, sizeof(sa));
		socklen_t sl = sizeof(sa);
		if (utp_getpeername(a->socket, (struct sockaddr*)&sa, &sl) == 0) {
			uint32_t ifindex = 0;
			uint16_t path_mtu = 0;
			if (NetworkInfo::BestInterfaceFor(*(struct sockaddr*)&sa, sl,
			                                  path_mtu, ifindex)
			    && path_mtu > 0) {
				const uint16_t overhead = (family == AF_INET6) ? 48 : 28;
				if (path_mtu > overhead) {
					return static_cast<uint64>(path_mtu - overhead);
				}
			}
		}
	}

	// Fallback: 1500-byte Ethernet MTU (IPv4) or 1280-byte IPv6 minimum.
	const uint16_t base_mtu  = (family == AF_INET6) ? 1280 : 1500;
	const uint16_t overhead  = (family == AF_INET6) ? 48 : 28;
	return static_cast<uint64>(base_mtu - overhead);
}

static uint64 on_get_udp_overhead(utp_callback_arguments* a)
{
	return (FamilyForCallback(a) == AF_INET6) ? 48ULL : 28ULL;
}

static uint64 on_get_random(utp_callback_arguments* /*a*/)
{
	static thread_local std::mt19937_64 rng{std::random_device{}()};
	return static_cast<uint64>(rng());
}

// UTP_LOG diagnostic. Gated by AMULE_UTP_DEBUG=1 in the environment so
// it stays silent in production runs; matches eMuleAI's pref-gated
// DebugLog behavior in spirit.
static uint64 on_log(utp_callback_arguments* a)
{
	static const bool enabled = (std::getenv("AMULE_UTP_DEBUG") != NULL);
	if (enabled && a != NULL && a->buf != NULL && a->len > 0) {
	}
	return 0;
}

// LEDBAT delay-sample hook + overhead-statistics hook are no-ops in
// eMuleAI too — they exist to prevent libutp's "callback not
// registered" fast-return path, which is what was silently breaking
// timing for us.
static uint64 on_delay_sample(utp_callback_arguments* /*a*/)
{
	return 0;
}

static uint64 on_overhead_statistics(utp_callback_arguments* /*a*/)
{
	return 0;
}

} // anonymous namespace

bool InstallOnContext(utp_context* ctx)
{
	if (ctx == NULL) {
		return false;
	}

	utp_set_callback(ctx, UTP_ON_STATE_CHANGE,        &on_state_change);
	utp_set_callback(ctx, UTP_ON_READ,                &on_read);
	utp_set_callback(ctx, UTP_SENDTO,                 &on_sendto);
	utp_set_callback(ctx, UTP_ON_ERROR,               &on_error);
	utp_set_callback(ctx, UTP_GET_READ_BUFFER_SIZE,   &on_get_read_buffer_size);
	utp_set_callback(ctx, UTP_ON_ACCEPT,              &on_accept);

	// Full callback set matching eMuleAI's UtpSocket.cpp:1515-1528.
	// Without these, libutp's get-callbacks (millis, micros, mtu,
	// overhead, random) return 0 — RTO timers fire on time=0, LEDBAT
	// delay-sample timestamps are 0, CWND math breaks, retransmits
	// stall the connection within a few packets. Registering even the
	// no-op ones (delay_sample, overhead_statistics) keeps libutp out
	// of the "callback not registered" fast-return branches.
	utp_set_callback(ctx, UTP_GET_MILLISECONDS,       &on_get_milliseconds);
	utp_set_callback(ctx, UTP_GET_MICROSECONDS,       &on_get_microseconds);
	utp_set_callback(ctx, UTP_GET_UDP_MTU,            &on_get_udp_mtu);
	utp_set_callback(ctx, UTP_GET_UDP_OVERHEAD,       &on_get_udp_overhead);
	utp_set_callback(ctx, UTP_GET_RANDOM,             &on_get_random);
	utp_set_callback(ctx, UTP_LOG,                    &on_log);
	utp_set_callback(ctx, UTP_ON_DELAY_SAMPLE,        &on_delay_sample);
	utp_set_callback(ctx, UTP_ON_OVERHEAD_STATISTICS, &on_overhead_statistics);

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
