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

// Smoke test for Phase A1 of the NAT-T port: verifies that the vendored
// libutp library at utp/ builds, links, and exposes its public API
// correctly via #include <utp.h>. Does NOT test the protocol — that's
// covered by later phases. This test exists so a misconfigured cmake
// (missing source file, broken include path, POSIX define missing)
// fails the test suite rather than waiting for downstream CUtpLayer
// integration to surface the issue.

#include <muleunit/test.h>
#include <utp.h>

using namespace muleunit;

DECLARE(LibUtpLink)
END_DECLARE;


// Trivial wrapper around utp_init to fail with a useful error if the
// library isn't wired through cmake properly. If this test fails to
// LINK, that's the actual diagnostic — the assertion body is paranoia.
TEST(LibUtpLink, ContextInitAndDestroy)
{
	// utp_init takes the protocol version (2 = current libutp).
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	// Destroy without leaking. utp_destroy is the inverse of utp_init;
	// calling it on a context produced by utp_init must not crash.
	utp_destroy(ctx);
}


// Verify that utp_context_get_userdata returns NULL on a freshly-created
// context (haven't called utp_context_set_userdata yet), and that the
// userdata round-trips after being set. This validates that the static-
// library link is real (not just compile-time stubs). We compare the
// dereferenced sentinel value rather than the pointer directly to avoid
// pulling wxString::Format(void*) into muleunit's ASSERT_EQUALS path.
TEST(LibUtpLink, UserdataRoundTrip)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	ASSERT_TRUE(utp_context_get_userdata(ctx) == NULL);

	int sentinel = 42;
	utp_context_set_userdata(ctx, &sentinel);

	int* readback = static_cast<int*>(utp_context_get_userdata(ctx));
	ASSERT_TRUE(readback != NULL);
	ASSERT_EQUALS(42, *readback);

	utp_destroy(ctx);
}
