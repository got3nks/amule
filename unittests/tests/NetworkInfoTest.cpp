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

// Phase A2 of the NAT-T port: tests for the cross-platform network-
// introspection shim. We test against the loopback interface only —
// it's always present, doesn't require internet connectivity, and
// gives the same results in any environment (CI, dev machine, etc.).
//
// All real-world tests of "best interface for a public IP" would need
// internet access and would be flaky in restricted environments.
// Loopback is sufficient to validate that the POSIX implementation
// wiring is correct.

#include <muleunit/test.h>
#include "NetworkInfo.h"

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__) || \
    defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#	define NATT_NETWORKINFOTEST_POSIX 1
#	include <sys/socket.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#else
#	include <winsock2.h>
#	include <ws2tcpip.h>
#endif
#include <cstring>

using namespace muleunit;

DECLARE(NetworkInfo)
END_DECLARE;


// PathMtu(0) is documented as "invalid ifindex"; must return 0 rather
// than something garbage from the OS.
TEST(NetworkInfo, PathMtuRejectsInvalidIfindex)
{
	ASSERT_EQUALS((int)0, (int)NetworkInfo::PathMtu(0));
}


// PathMtu against a deliberately huge ifindex (~4 billion) should return
// 0 rather than crash or return uninitialized memory. Validates the
// if_indextoname failure path.
TEST(NetworkInfo, PathMtuRejectsBogusIfindex)
{
	ASSERT_EQUALS((int)0, (int)NetworkInfo::PathMtu(0xFFFFFFFFu));
}


// Self-consistency check on POSIX: querying for the route to 127.0.0.1
// must succeed (loopback is always available), return a non-zero
// ifindex, and the returned MTU must be plausible (between 1280 — the
// IPv6 minimum we'd ever consider serving — and 65535 — the IP packet
// header field maximum).
//
// On Windows builds (currently stub), this test reports failure for
// BestInterfaceFor; that's expected and we assert false there.
TEST(NetworkInfo, BestInterfaceForLoopbackV4)
{
	struct sockaddr_in target;
	std::memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	target.sin_port = htons(12345);
	target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1

	uint16_t mtu = 0;
	uint32_t ifindex = 0;
	bool ok = NetworkInfo::BestInterfaceFor(
		reinterpret_cast<struct sockaddr&>(target),
		sizeof(target),
		mtu, ifindex);

#if NATT_NETWORKINFOTEST_POSIX
	// POSIX: loopback must resolve.
	ASSERT_TRUE(ok);
	ASSERT_TRUE(ifindex != 0);
	ASSERT_TRUE(mtu >= 1280);
	ASSERT_TRUE(mtu <= 65535);
	// Self-consistency: PathMtu(returned-ifindex) returns the same value.
	ASSERT_EQUALS(mtu, NetworkInfo::PathMtu(ifindex));
#else
	// Windows stub: always false. mtu/ifindex must be 0.
	ASSERT_FALSE(ok);
	ASSERT_EQUALS((int)0, (int)mtu);
	ASSERT_EQUALS((int)0, (int)ifindex);
#endif
}


// Unsupported address families (AF_UNIX etc.) must be cleanly rejected.
TEST(NetworkInfo, BestInterfaceForRejectsBadFamily)
{
	struct sockaddr_in target;
	std::memset(&target, 0, sizeof(target));
	target.sin_family = AF_UNSPEC;  // explicitly unspecified

	uint16_t mtu = 0;
	uint32_t ifindex = 0;
	bool ok = NetworkInfo::BestInterfaceFor(
		reinterpret_cast<struct sockaddr&>(target),
		sizeof(target),
		mtu, ifindex);

	ASSERT_FALSE(ok);
	ASSERT_EQUALS((int)0, (int)mtu);
	ASSERT_EQUALS((int)0, (int)ifindex);
}
