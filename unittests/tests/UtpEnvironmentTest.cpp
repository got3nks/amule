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

// Tests for Phase B1 of the NAT-T port — the global libutp context
// owner. Verifies the four claims the production code makes:
//
//   1. Init() returns a non-NULL context on a fresh process.
//   2. GetContext() agrees with Init() and returns NULL after Shutdown().
//   3. A second Init() while a context is live is idempotent — it
//      returns the same pointer, does not leak a second context.
//   4. RuntimeLock() returns a usable std::mutex that can be locked
//      and unlocked.
//
// The test is gated on ENABLE_NAT_T because UtpEnvironment is itself
// gated on it. With ENABLE_NAT_T=OFF the test is registered as a tiny
// "always passes" smoke so the cmake plumbing has something to compile
// regardless of feature flag — same approach LibUtpLinkTest takes
// implicitly via the CMakeLists.txt conditional.

#include <muleunit/test.h>

// Bring in config.h via the project headers, which is where ENABLE_NAT_T
// lives. The test target's include path puts CMAKE_BINARY_DIR ahead of
// the source tree, so this resolves to the freshly-generated config.h.
#include "UtpEnvironment.h"

#ifdef ENABLE_NAT_T

#include <atomic>
#include <thread>
#include <utp.h>

using namespace muleunit;

DECLARE(UtpEnvironment)
END_DECLARE;


// Init must return a non-NULL utp_context on a fresh process, and
// GetContext() must immediately agree with the returned pointer.
// Roundtrip a userdata sentinel through the live context to prove
// libutp is actually live (not a NULL-equivalent stub).
TEST(UtpEnvironment, InitReturnsLiveContext)
{
	utp_context* ctx = UtpEnvironment::Init();
	ASSERT_TRUE(ctx != NULL);
	ASSERT_TRUE(UtpEnvironment::GetContext() == ctx);

	// Confirm the context is actually a live libutp context, not just
	// a non-NULL sentinel — set+read userdata round-trip.
	int sentinel = 12345;
	utp_context_set_userdata(ctx, &sentinel);
	int* readback = static_cast<int*>(utp_context_get_userdata(ctx));
	ASSERT_TRUE(readback != NULL);
	ASSERT_EQUALS(12345, *readback);

	UtpEnvironment::Shutdown();
	ASSERT_TRUE(UtpEnvironment::GetContext() == NULL);
}


// Calling Init() twice while a context is live must return the same
// context pointer — i.e. the second Init is a no-op, not a leak of a
// second context. After Shutdown(), a fresh Init() may return a
// different pointer (libutp's allocator decides), but the second call
// in a sequence Init→Init→Shutdown must match the first.
TEST(UtpEnvironment, DoubleInitIsIdempotent)
{
	utp_context* first = UtpEnvironment::Init();
	ASSERT_TRUE(first != NULL);

	utp_context* second = UtpEnvironment::Init();
	ASSERT_TRUE(second == first);

	// Single Shutdown must clear regardless of how many Init() calls
	// preceded it — there's no internal refcount.
	UtpEnvironment::Shutdown();
	ASSERT_TRUE(UtpEnvironment::GetContext() == NULL);
}


// Shutdown() with no live context must be a no-op (not crash, not
// double-free). Important because CClientUDPSocket's dtor calls it
// unconditionally even when Init() may have failed.
TEST(UtpEnvironment, ShutdownWithoutInitIsNoop)
{
	// Make sure no context is live (defensive — tests may run in any order).
	UtpEnvironment::Shutdown();
	ASSERT_TRUE(UtpEnvironment::GetContext() == NULL);

	// Second Shutdown — still a no-op.
	UtpEnvironment::Shutdown();
	ASSERT_TRUE(UtpEnvironment::GetContext() == NULL);
}


// The runtime lock is a real std::mutex that lock_guard works with.
// Three checks: (1) try_lock from a worker thread fails while the main
// thread holds the lock — proves it's actually a mutex, not a no-op;
// (2) try_lock from a worker succeeds after the guard scope exits —
// proves the previous holder really released it; (3) the same mutex
// instance is returned on every call (it's the same singleton).
TEST(UtpEnvironment, RuntimeLockAcquireRelease)
{
	std::mutex& m = UtpEnvironment::RuntimeLock();

	// Same instance on every call — it's a singleton.
	ASSERT_TRUE(&m == &UtpEnvironment::RuntimeLock());

	// While the main thread holds the lock, a worker's try_lock must
	// fail. std::atomic<bool> communicates the worker's result back.
	std::atomic<bool> worker_got_lock_while_held(true);
	{
		std::lock_guard<std::mutex> g(m);
		std::thread worker([&]() {
			if (m.try_lock()) {
				m.unlock();
				worker_got_lock_while_held.store(true);
			} else {
				worker_got_lock_while_held.store(false);
			}
		});
		worker.join();
	}
	ASSERT_FALSE(worker_got_lock_while_held.load());

	// After the guard's scope ends, the mutex is released — a worker
	// must now be able to acquire it via try_lock.
	std::atomic<bool> worker_got_lock_after_release(false);
	std::thread reacquire([&]() {
		if (m.try_lock()) {
			m.unlock();
			worker_got_lock_after_release.store(true);
		}
	});
	reacquire.join();
	ASSERT_TRUE(worker_got_lock_after_release.load());
}

#else

// ENABLE_NAT_T=OFF: nothing to test. Register a single tautological
// case so ctest has something to run for this binary.
using namespace muleunit;
DECLARE(UtpEnvironment)
END_DECLARE;

TEST(UtpEnvironment, FeatureDisabled)
{
	ASSERT_TRUE(true);
}

#endif // ENABLE_NAT_T
