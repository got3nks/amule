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

#ifndef UTPENVIRONMENT_H
#define UTPENVIRONMENT_H

#include "config.h"

#ifdef ENABLE_NAT_T

// Phase B1 of the NAT-T port (see .archive/eMuleAI-nat-t-implementation-plan.md
// cluster 6, sub-commit B1). Owns the single global libutp context and
// the runtime mutex that serializes all libutp API calls.
//
// Lifecycle: CClientUDPSocket::CClientUDPSocket() calls Init() once at
// daemon startup; CClientUDPSocket::~CClientUDPSocket() calls Shutdown()
// at daemon teardown. There is one context for the whole process —
// matches eMuleAI's design (single utp_context owned by the UDP socket
// because all NAT-T traffic flows over aMule's single Kad UDP port).
//
// Threading: the runtime lock is held only during the libutp API call
// itself (utp_process_udp, utp_check_timeouts, utp_issue_deferred_acks,
// utp_write, utp_close, etc.). Higher-level state (CUpDownClient,
// CClientList) stays main-thread-only; events from the worker thread are
// posted to the main thread. The lock is therefore held for microseconds
// per call, not for whole packet-processing pipelines.

#include <mutex>

struct struct_utp_context;
typedef struct struct_utp_context utp_context;

namespace UtpEnvironment {

// Initialise the global libutp context. Idempotent: a second Init()
// while a context already exists is a no-op (does not destroy and
// recreate; just returns the existing one). Returns the live context
// pointer, or NULL if utp_init failed.
//
// Callable from any thread. The first call wins; concurrent callers
// receive the same context.
utp_context* Init();

// Destroy the global libutp context. Idempotent: Shutdown() with no
// context is a no-op. After this call, GetContext() returns NULL until
// the next Init().
//
// Callers must guarantee that no other thread is inside a libutp call
// (i.e. holding RuntimeLock()) when Shutdown() is invoked. The Init/
// Shutdown pair brackets the entire process lifetime of NAT-T, so this
// is satisfied trivially when called from CClientUDPSocket dtor.
void Shutdown();

// Returns the current global utp_context, or NULL if not initialised.
// Safe to call from any thread; the pointer itself is stable between
// Init() and Shutdown() (the underlying libutp state must still be
// accessed under RuntimeLock()).
utp_context* GetContext();

// The runtime mutex serializing all libutp API calls. Lock around every
// utp_* call site. eMuleAI uses a single global CCriticalSection for
// this; std::mutex gives us the same semantics with portable RAII via
// std::lock_guard.
std::mutex& RuntimeLock();

} // namespace UtpEnvironment

#endif // ENABLE_NAT_T

#endif // UTPENVIRONMENT_H
