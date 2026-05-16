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

#ifndef NETWORKINFO_H
#define NETWORKINFO_H

#include <cstdint>

// Forward-declare instead of #include <sys/socket.h> (POSIX-only) so
// this header stays mingw-buildable. Callers that pass actual sockaddr
// objects already include the right system header (sys/socket.h on
// POSIX, winsock2.h on Windows). The socklen_t typedef matches the
// platform's expected signedness so a TU that also includes ws2tcpip.h
// (mingw) doesn't conflict on its `typedef int socklen_t`.
struct sockaddr;
#if defined(_WIN32) || defined(__WINDOWS__)
typedef int          socklen_t;
#else
typedef unsigned int socklen_t;
#endif

// Phase A2 of the NAT-T port (see .archive/eMuleAI-nat-t-implementation-plan.md
// cluster 2). Cross-platform shim providing the network-introspection
// primitives libutp's PMTU adaptation and the NAT-T coordinator need —
// best outgoing interface for a remote, MTU of an interface, etc.
//
// Replaces eMuleAI's Windows-only iphlpapi.h calls (GetIpInterfaceEntry,
// GetBestRoute2) with portable alternatives.

namespace NetworkInfo {

// Find the OS-preferred outgoing interface for a given remote address,
// and return that interface's MTU and ifindex.
//
//   remote, remote_len: the address libutp wants to send to.
//   out_mtu, out_ifindex: output parameters, filled on success.
//
// Returns:
//   true  → out_mtu and out_ifindex are filled with valid values.
//           Typical out_mtu values: 1500 (Ethernet), 1492 (PPPoE),
//           65535 (Linux loopback), 16384 (macOS loopback). Always > 0.
//   false → no route, no matching interface, unsupported address
//           family, or the OS APIs are unavailable on this platform.
//           Output parameters are set to 0.
//
// POSIX implementation: opens a UDP socket, calls connect() against the
// remote (this is a kernel-only operation for UDP — no packet is sent),
// reads back the locally-bound IP via getsockname(), then matches that
// IP against the interface list from getifaddrs() to find the
// originating interface. SIOCGIFMTU ioctl reads the MTU.
//
// Windows implementation: TODO (stub returns false). The plan calls for
// GetBestRoute2 + GetIpInterfaceEntry to mirror the eMuleAI approach.
// Callers must handle the false return — typically by falling back to
// a conservative MTU (1280 for IPv6, 576 for IPv4, or 1400 if the
// caller knows it's behind a reasonable NAT).
bool BestInterfaceFor(const struct sockaddr& remote, socklen_t remote_len,
                      uint16_t& out_mtu, uint32_t& out_ifindex);

// MTU of the interface identified by ifindex. Returns 0 if the
// interface is unknown or the MTU can't be read.
//
// Use BestInterfaceFor() to obtain a valid ifindex for a given remote;
// PathMtu() exists as a separate primitive so libutp's per-context MTU
// re-query (every few seconds for path-MTU-discovery adaptation) can
// avoid the full route lookup each time.
uint16_t PathMtu(uint32_t ifindex);

} // namespace NetworkInfo

#endif // NETWORKINFO_H
