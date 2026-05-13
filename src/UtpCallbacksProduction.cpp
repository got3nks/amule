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

#include "UtpCallbacks.h"

#ifdef ENABLE_NAT_T

// Production sendto thunk for UtpCallbacks. Lives in a separate TU
// from UtpCallbacks.cpp for the same reason UtpEncryptionProduction.cpp
// is split out: this thunk calls into CClientUDPSocket::SendTo, which
// pulls in theApp / theStats / bandwidth throttler — symbols the
// unit-test target deliberately omits. Framework + tests link only
// UtpCallbacks.cpp + their own no-op sendto delegate; this TU only
// builds in CORE_SOURCES with ENABLE_NAT_T + full daemon.

#include "ClientUDPSocket.h"

#include <arpa/inet.h>     // ntohs, ntohl
#include <netinet/in.h>    // sockaddr_in
#include <sys/socket.h>    // sockaddr, socklen_t

namespace {

// libutp's on_sendto and CUtpLayer::Connect both arrive here with the
// final wire bytes already assembled: WrapKeyFrame /
// UtpEncryption::WrapUtpFrame produced the [0xB2, sub-byte, ciphertext]
// envelope. We hand that to CMuleUDPSocket::SendTo unchanged — the
// per-peer EncryptSendClient pass that the regular SendPacket queue
// applies is exactly what WrapKeyFrame / WrapUtpFrame already did, so
// double-encrypting here would corrupt the frame.
void production_sendto(void* userdata,
                       const std::uint8_t* buf,
                       std::size_t len,
                       const struct sockaddr* addr,
                       socklen_t addr_len)
{
	if (userdata == nullptr || buf == nullptr || len == 0 ||
	    addr == nullptr || addr_len < static_cast<socklen_t>(sizeof(struct sockaddr_in)) ||
	    addr->sa_family != AF_INET) {
		return;
	}
	CClientUDPSocket* sock = static_cast<CClientUDPSocket*>(userdata);
	const struct sockaddr_in* sin = reinterpret_cast<const struct sockaddr_in*>(addr);
	const uint32_t ip   = ntohl(sin->sin_addr.s_addr);
	const uint16_t port = ntohs(sin->sin_port);
	sock->SendNatTraversalRaw(buf, static_cast<uint32_t>(len), ip, port);
}

} // anonymous namespace

namespace UtpCallbacks {

void InstallProductionSendtoDelegate(CClientUDPSocket* sock)
{
	SetSendtoDelegate(&production_sendto, sock);
}

} // namespace UtpCallbacks

#endif // ENABLE_NAT_T
