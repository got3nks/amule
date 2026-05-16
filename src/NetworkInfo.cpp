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

#include "NetworkInfo.h"

#include <cstring>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__) || \
    defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#	define NATT_NETWORKINFO_POSIX 1
#endif

#if NATT_NETWORKINFO_POSIX

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unistd.h>

namespace NetworkInfo {

uint16_t PathMtu(uint32_t ifindex)
{
	if (ifindex == 0) {
		return 0;
	}

	char ifname[IF_NAMESIZE];
	if (::if_indextoname(ifindex, ifname) == nullptr) {
		return 0;
	}

	// SIOCGIFMTU needs a socket; the family doesn't matter for ioctl
	// dispatch — any AF_INET DGRAM works on every POSIX I've checked.
	int sk = ::socket(AF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		return 0;
	}

	struct ifreq req;
	std::memset(&req, 0, sizeof(req));
	std::strncpy(req.ifr_name, ifname, IF_NAMESIZE - 1);

	int rc = ::ioctl(sk, SIOCGIFMTU, &req);
	::close(sk);

	if (rc < 0) {
		return 0;
	}

	int mtu = req.ifr_mtu;
	if (mtu <= 0) {
		return 0;
	}
	// Linux loopback typically advertises MTU 65536 — one above what
	// fits in uint16_t. Clamp at 65535 (also the UDP datagram size
	// ceiling, so callers can't use a larger value anyway) rather
	// than rejecting the interface outright.
	if (mtu > 65535) {
		mtu = 65535;
	}
	return static_cast<uint16_t>(mtu);
}

bool BestInterfaceFor(const struct sockaddr& remote, socklen_t remote_len,
                      uint16_t& out_mtu, uint32_t& out_ifindex)
{
	out_mtu = 0;
	out_ifindex = 0;

	const int family = remote.sa_family;
	if (family != AF_INET && family != AF_INET6) {
		return false;
	}

	// UDP connect: this doesn't send a packet; it sets the socket's
	// default destination and forces the kernel to pick a local
	// interface for the route. After this, getsockname tells us which
	// local IP the kernel chose, which we can match back to an
	// interface via getifaddrs.
	int sk = ::socket(family, SOCK_DGRAM, 0);
	if (sk < 0) {
		return false;
	}

	if (::connect(sk, &remote, remote_len) < 0) {
		::close(sk);
		return false;
	}

	// Read back the local IP the kernel bound.
	union {
		struct sockaddr  generic;
		struct sockaddr_in  in4;
		struct sockaddr_in6 in6;
	} local;
	std::memset(&local, 0, sizeof(local));
	socklen_t local_len = sizeof(local);

	if (::getsockname(sk, &local.generic, &local_len) < 0) {
		::close(sk);
		return false;
	}
	::close(sk);

	// Walk the interface list and find the one whose primary address
	// matches the locally-bound IP from getsockname.
	struct ifaddrs* ifap = nullptr;
	if (::getifaddrs(&ifap) != 0 || ifap == nullptr) {
		return false;
	}

	uint32_t ifindex = 0;
	for (struct ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == nullptr) continue;
		if (ifa->ifa_addr->sa_family != family) continue;

		bool match = false;
		if (family == AF_INET) {
			auto* a = reinterpret_cast<const struct sockaddr_in*>(ifa->ifa_addr);
			match = (a->sin_addr.s_addr == local.in4.sin_addr.s_addr);
		} else {
			auto* a = reinterpret_cast<const struct sockaddr_in6*>(ifa->ifa_addr);
			match = (std::memcmp(&a->sin6_addr, &local.in6.sin6_addr,
			                     sizeof(a->sin6_addr)) == 0);
		}

		if (match) {
			ifindex = ::if_nametoindex(ifa->ifa_name);
			break;
		}
	}

	::freeifaddrs(ifap);

	if (ifindex == 0) {
		return false;
	}

	uint16_t mtu = PathMtu(ifindex);
	if (mtu == 0) {
		return false;
	}

	out_ifindex = ifindex;
	out_mtu = mtu;
	return true;
}

} // namespace NetworkInfo

#else // !POSIX (Windows, etc.)

// Stub: the Windows implementation using GetBestRoute2 +
// GetIpInterfaceEntry from iphlpapi.h is planned but not yet ported
// from eMuleAI's UtpSocket.cpp. Callers must handle the false return
// by falling back to a conservative MTU (1280 / 576 / 1400 depending
// on context).

namespace NetworkInfo {

bool BestInterfaceFor(const struct sockaddr& /*remote*/, socklen_t /*remote_len*/,
                      uint16_t& out_mtu, uint32_t& out_ifindex)
{
	out_mtu = 0;
	out_ifindex = 0;
	return false;
}

uint16_t PathMtu(uint32_t /*ifindex*/)
{
	return 0;
}

} // namespace NetworkInfo

#endif // POSIX
