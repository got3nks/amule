//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2011 aMule Team ( admin@amule.org / http://www.amule.org )
// Copyright (c) 2002-2011 Merkur ( devs@emule-project.net / http://www.emule-project.net )
//
// Any parts of this program derived from the xMule, lMule or eMule project,
// or contributed by third-party developers are copyrighted by their
// respective authors.
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

#ifndef CLIENTUDPSOCKET_H
#define CLIENTUDPSOCKET_H

#include "config.h"		// ENABLE_NAT_T (B7.6: needed for SendNatTraversalRaw decl)

#include "MuleUDPSocket.h"

class CClientUDPSocket : public CMuleUDPSocket
{
public:
	CClientUDPSocket(const amuleIPV4Address &address, const CProxyData *ProxyData = NULL);
	~CClientUDPSocket() override;

#ifdef ENABLE_NAT_T
	/**
	 * Send an already-wrapped NAT-T / uTP envelope ([0xB2, sub-byte,
	 * ciphertext] from UtpEncryption::WrapKeyFrame or WrapUtpFrame) as
	 * a single raw UDP datagram. Used by UtpCallbacks's production
	 * sendto delegate (UtpCallbacksProduction.cpp) so libutp's
	 * on_sendto and CUtpLayer::Connect's Key Frame send can put bytes
	 * on the wire without going through SendPacket's per-peer
	 * encryption queue (which would double-encrypt the already-wrapped
	 * envelope). Equivalent to eMuleAI's
	 * CClientUDPSocket::SendUtpPacket (srchybrid/ClientUDPSocket.cpp).
	 */
	void	SendNatTraversalRaw(const uint8_t* buf, uint32_t length, uint32_t ip, uint16_t port);
#endif

#ifdef ENABLE_NAT_T
	/**
	 * Worker-thread synchronous hook. Consumes uTP / NAT-T packets
	 * (protocol byte == OP_UDPRESERVEDPROT2) before they ever reach the
	 * main thread, so libutp's LEDBAT delay sample reflects only the
	 * kernel→user-space jitter on the dedicated UDP recv path rather
	 * than main-thread scheduling delay. Returns false (and lets the
	 * packet flow through the regular OnReceive path) for everything
	 * else — Kad, eD2k UDP control packets, etc.
	 */
	bool	TryProcessUtpPacketSync(uint32 ip, uint16 port,
	                                 uint8_t* buffer, size_t length) override;
#endif

protected:
	void	OnReceive(int errorCode) override;

private:
	void	OnPacketReceived(uint32 ip, uint16 port, uint8_t* buffer, size_t length) override;
	void	ProcessPacket(uint8_t* packet, int16 size, int8 opcode, uint32 host, uint16 port);
};

#endif // CLIENTUDPSOCKET_H
// File_checked_for_headers
