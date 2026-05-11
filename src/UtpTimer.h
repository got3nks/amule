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

#ifndef UTPTIMER_H
#define UTPTIMER_H

#include "config.h"

#ifdef ENABLE_NAT_T

// Phase B7 of the NAT-T port (see .archive/eMuleAI-nat-t-implementation-plan.md
// cluster 6, sub-commit B7). Periodic driver for libutp's internal
// retransmit / state machinery.
//
// libutp doesn't drive its own clock — the application must call
// `utp_check_timeouts(ctx)` periodically (canonical interval: 50 ms,
// matching eMuleAI). Without these ticks, lost packets never
// retransmit and connections stall. Same for `utp_issue_deferred_acks`:
// libutp queues ACKs to coalesce them, and they sit there until we
// tell it to flush.
//
// This module is a self-contained ticker: one std::thread sleeping in
// 50 ms increments, locking `UtpEnvironment::RuntimeLock` around the
// libutp call. Choosing std::thread over wxTimer means the unit test
// doesn't need a wx event loop running — important because the test
// binary is a bare ctest target, not a full app process.
//
// Lifecycle: CClientUDPSocket ctor calls Start(); dtor calls Stop().
// Both are idempotent; both block until the worker is fully up / down.

#include <cstdint>

namespace UtpTimer {

// Canonical tick interval. Tests use this constant to compute
// expected tick counts in a sampled interval.
constexpr int kTickIntervalMs = 50;

// Start the periodic tick loop. Idempotent — second call while
// already running is a no-op.
//
// If `UtpEnvironment::GetContext()` is NULL when a tick fires (e.g.
// utp_init has not yet been called), that tick safely skips the
// libutp work and increments the tick counter anyway. This is how
// tests count timer fires without needing a live utp_context.
void Start();

// Stop and join the tick loop. Blocks until the worker exits.
// Idempotent: Stop() with no running worker is a no-op.
void Stop();

// Number of times the tick callback has fired since the last Start().
// Reset to zero on each Start(). Atomic; safe to read from any
// thread. Used by UtpTimerTest to verify the tick cadence.
std::uint64_t GetTickCount();

// True if the worker thread is currently running (between Start and
// the matching Stop). Mostly diagnostic; tests use GetTickCount() to
// observe liveness instead.
bool IsRunning();

} // namespace UtpTimer

#endif // ENABLE_NAT_T

#endif // UTPTIMER_H
