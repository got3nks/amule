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

#ifndef UTPCALLBACKS_H
#define UTPCALLBACKS_H

#include "config.h"

#ifdef ENABLE_NAT_T

// Phase B2 of the NAT-T port (see .archive/eMuleAI-nat-t-implementation-plan.md
// cluster 6, sub-commit B2). The five libutp callbacks aMule must
// install on its global utp_context:
//
//   UTP_ON_STATE_CHANGE       — connect/writable/eof/destroying notifications
//   UTP_ON_READ               — libutp delivered bytes for the app to consume
//   UTP_SENDTO                — libutp wants to send a UDP packet
//   UTP_ON_ERROR              — connection-level error (refused/reset/timed-out)
//   UTP_GET_READ_BUFFER_SIZE  — libutp asks how much room the app has
//
// State-change / read / error / get-read-buffer-size callbacks dispatch
// via `utp_get_userdata(socket)` which will be a CUtpLayer* once that
// class arrives in B3. For now those paths gracefully handle a NULL
// userdata (B2 has no CUtpLayer yet — wiring will happen in B3).
//
// Sendto is different: it operates at the context level, not per-socket,
// so its target (the actual UDP transport) is plugged via the delegate
// API below. eMuleAI uses `utp_context_get_userdata(ctx)` to recover
// CClientUDPSocket and calls its SendUtpPacket method; this port uses
// a plain function pointer + opaque userdata so the test harness can
// intercept outbound packets without needing a real socket.

#include <cstddef>
#include <cstdint>

struct sockaddr;
typedef unsigned int socklen_t;

struct struct_utp_context;
typedef struct struct_utp_context utp_context;

namespace UtpCallbacks {

// Function-pointer signature for the sendto delegate. libutp gives us
// fully-formed uTP packets ready for UDP transmission; the delegate's
// job is exactly to push those bytes out a UDP socket.
//
//   userdata: the opaque pointer set via SetSendtoDelegate (typically
//             CClientUDPSocket* in production; a test capture struct
//             in unit tests).
//   buf, len: the uTP packet bytes (already encoded by libutp).
//   addr, addr_len: the destination address libutp wants to send to.
typedef void (*SendtoFn)(void* userdata,
                         const uint8_t* buf, size_t len,
                         const struct sockaddr* addr, socklen_t addr_len);

// Install all five callbacks on the given context. Idempotent —
// re-installing on the same context just overwrites the prior callback
// pointers with the same values. Returns true on success; the only
// failure mode is a NULL context, in which case it returns false
// without touching anything.
bool InstallOnContext(utp_context* ctx);

// Register the sendto delegate. Until set, the on_sendto callback
// silently drops every outbound packet — this is the safe default for
// processes that haven't yet wired up their UDP transport (and the
// safe behavior for tests that don't care about outbound packets).
//
// Pass (NULL, NULL) to clear the delegate. Both arguments must be
// either both non-NULL or both NULL — passing a non-NULL function with
// a NULL userdata is fine if the function doesn't dereference it.
void SetSendtoDelegate(SendtoFn fn, void* userdata);

} // namespace UtpCallbacks

#endif // ENABLE_NAT_T

#endif // UTPCALLBACKS_H
