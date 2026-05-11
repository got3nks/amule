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

// Tests for Phase B7 of the NAT-T port — the periodic libutp tick
// driver. Plan spec: "install timer, wait 250 ms, assert
// `utp_check_timeouts` was called approximately 5 times (allow ±2
// for jitter)."
//
// We can't directly observe `utp_check_timeouts` invocations (it's a
// libutp internal), but the timer's tick counter is the direct proxy
// — it's incremented inside the same callback that calls
// utp_check_timeouts, so a correct count implies the correct number
// of invocations. The tests run without a live utp_context (no
// UtpEnvironment::Init), which exercises the "context NULL → skip
// libutp work, still tick the counter" path documented in the
// header.

#include <muleunit/test.h>

#include "UtpTimer.h"

#ifdef ENABLE_NAT_T

#include <chrono>
#include <thread>

using namespace muleunit;

DECLARE(UtpTimer)
END_DECLARE;


// The headline test: 250 ms of real time at the 50 ms tick interval
// should yield approximately 5 ticks. The ±2 tolerance absorbs OS
// scheduling jitter, condition-variable wakeup latency, and
// startup-cost on the first tick.
TEST(UtpTimer, TicksApproximatelyFiveTimesIn250ms)
{
	// Defensive: ensure no prior test left the timer running.
	UtpTimer::Stop();

	UtpTimer::Start();
	ASSERT_TRUE(UtpTimer::IsRunning());

	std::this_thread::sleep_for(std::chrono::milliseconds(250));

	UtpTimer::Stop();
	ASSERT_FALSE(UtpTimer::IsRunning());

	const std::uint64_t count = UtpTimer::GetTickCount();
	// Expected: 5 ticks at 50 ms intervals over 250 ms. Allow ±2 for
	// real-world scheduler jitter (CI runners can be slow on first
	// tick; some OSes coalesce condition_variable wake-ups).
	ASSERT_TRUE(count >= 3);
	ASSERT_TRUE(count <= 7);
}


// Start counter must reset on each Start. Without this, a long-lived
// test process accumulates ticks across cases and the "approximately
// N ticks" assertions become flaky.
TEST(UtpTimer, StartResetsTickCount)
{
	UtpTimer::Stop();

	UtpTimer::Start();
	std::this_thread::sleep_for(std::chrono::milliseconds(120));
	UtpTimer::Stop();

	const std::uint64_t first_run_count = UtpTimer::GetTickCount();
	ASSERT_TRUE(first_run_count >= 1);

	// Restart — counter must reset to 0.
	UtpTimer::Start();
	// Read the counter immediately (before any ticks fire).
	// Race window: the first tick can't fire in < kTickIntervalMs,
	// so we have ~50 ms of safe headroom here.
	const std::uint64_t fresh_count = UtpTimer::GetTickCount();
	UtpTimer::Stop();

	ASSERT_EQUALS((std::uint64_t)0, fresh_count);
}


// Start() while already running must be a no-op (no second worker
// thread spawned, no counter reset).
TEST(UtpTimer, DoubleStartIsIdempotent)
{
	UtpTimer::Stop();

	UtpTimer::Start();
	ASSERT_TRUE(UtpTimer::IsRunning());

	// Let one tick fire so the counter is non-zero.
	std::this_thread::sleep_for(std::chrono::milliseconds(80));

	const std::uint64_t before = UtpTimer::GetTickCount();
	ASSERT_TRUE(before >= 1);

	UtpTimer::Start();  // second call — must not reset or duplicate
	ASSERT_TRUE(UtpTimer::IsRunning());
	const std::uint64_t after = UtpTimer::GetTickCount();
	// Counter must NOT have been reset to zero by the second Start.
	// (It may have advanced if a tick happened between reads — that's
	// fine; we only assert it didn't go backward.)
	ASSERT_TRUE(after >= before);

	UtpTimer::Stop();
}


// Stop() without a running worker must be a no-op (not crash, not
// leave the next Start broken). Critical because CClientUDPSocket's
// dtor calls Stop unconditionally even when Start was never reached.
TEST(UtpTimer, StopWithoutStartIsNoop)
{
	UtpTimer::Stop();  // ensure baseline
	ASSERT_FALSE(UtpTimer::IsRunning());

	UtpTimer::Stop();  // second call — must not crash
	ASSERT_FALSE(UtpTimer::IsRunning());

	// And after that, Start still works normally.
	UtpTimer::Start();
	ASSERT_TRUE(UtpTimer::IsRunning());
	UtpTimer::Stop();
}


// Stop() must wake the worker promptly via the condition variable —
// not wait a full tick interval. 50 ms ticks are short enough that
// the difference doesn't show up in obvious latency, but the test
// asserts that Stop returns within < 2 ticks of being called even
// if it was issued just after a tick fired.
TEST(UtpTimer, StopReturnsPromptly)
{
	UtpTimer::Stop();

	UtpTimer::Start();
	// Wait long enough for the worker to be sleeping in its
	// condition_variable wait, not in the middle of a tick.
	std::this_thread::sleep_for(std::chrono::milliseconds(10));

	const auto t0 = std::chrono::steady_clock::now();
	UtpTimer::Stop();
	const auto elapsed = std::chrono::steady_clock::now() - t0;

	// Should be much less than a full tick. Generous bound:
	// 2 ticks (100 ms) is "definitely something is wrong" territory.
	ASSERT_TRUE(elapsed < std::chrono::milliseconds(2 * UtpTimer::kTickIntervalMs));
}

#else

using namespace muleunit;
DECLARE(UtpTimer)
END_DECLARE;

TEST(UtpTimer, FeatureDisabled)
{
	ASSERT_TRUE(true);
}

#endif // ENABLE_NAT_T
