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

#include "UtpTimer.h"

#ifdef ENABLE_NAT_T

#include "UtpEnvironment.h"
#include "UtpLayer.h"
#include "UtpLayerRegistry.h"

#include <utp.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace UtpTimer {

namespace {

// File-scope state. g_state_lock orders Start/Stop against each other
// so two concurrent Start callers don't race to spawn duplicate
// workers; g_worker holds the spawned thread; g_should_stop is the
// flag the worker polls each tick. g_wakeup_cv lets Stop() interrupt
// the 50 ms sleep so shutdown doesn't have to wait a full tick.
std::mutex                g_state_lock;
std::thread               g_worker;
std::atomic<bool>         g_should_stop{false};
std::atomic<std::uint64_t> g_tick_count{0};
std::mutex                g_wakeup_lock;
std::condition_variable   g_wakeup_cv;

void Tick()
{
	// Part 1: libutp's own machinery under the runtime lock.
	{
		std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
		utp_context* ctx = UtpEnvironment::GetContext();
		if (ctx != NULL) {
			utp_check_timeouts(ctx);
			utp_issue_deferred_acks(ctx);
		}
	}

	// Part 2: Phase B7.5 F4 — sweep registered CUtpLayer instances
	// for connect-flow timeouts (KEY_FRAME_SENT layers past the 12 s
	// deadline transition to FAILED). Runs OUTSIDE the runtime lock
	// because each layer's CheckTimeoutNow re-acquires the lock
	// itself; doing this under the runtime lock would deadlock on
	// the non-recursive mutex.
	UtpLayerRegistry::ForEach([](CUtpLayer* layer) {
		layer->CheckTimeoutNow();
	});

	// Always increment, even when ctx is NULL — the counter is the
	// timer's liveness signal. Tests check this value to verify the
	// cadence is correct without needing a live utp_context.
	g_tick_count.fetch_add(1, std::memory_order_relaxed);
}

void WorkerLoop()
{
	while (!g_should_stop.load(std::memory_order_acquire)) {
		// Wait the tick interval — but use a condition variable
		// instead of plain sleep so Stop() can wake us early. The
		// cv predicate is just the stop flag.
		std::unique_lock<std::mutex> lk(g_wakeup_lock);
		const bool stop_requested = g_wakeup_cv.wait_for(
			lk,
			std::chrono::milliseconds(kTickIntervalMs),
			[]() { return g_should_stop.load(std::memory_order_acquire); });
		if (stop_requested) {
			break;
		}
		lk.unlock();  // release before taking the runtime lock

		Tick();
	}
}

} // anonymous namespace

void Start()
{
	std::lock_guard<std::mutex> lock(g_state_lock);

	if (g_worker.joinable()) {
		// Already running — idempotent no-op.
		return;
	}

	g_should_stop.store(false, std::memory_order_release);
	g_tick_count.store(0, std::memory_order_relaxed);
	g_worker = std::thread(&WorkerLoop);
}

void Stop()
{
	std::lock_guard<std::mutex> lock(g_state_lock);

	if (!g_worker.joinable()) {
		return;
	}

	{
		std::lock_guard<std::mutex> wlk(g_wakeup_lock);
		g_should_stop.store(true, std::memory_order_release);
	}
	g_wakeup_cv.notify_all();

	g_worker.join();
}

std::uint64_t GetTickCount()
{
	return g_tick_count.load(std::memory_order_relaxed);
}

bool IsRunning()
{
	std::lock_guard<std::mutex> lock(g_state_lock);
	return g_worker.joinable();
}

} // namespace UtpTimer

#endif // ENABLE_NAT_T
