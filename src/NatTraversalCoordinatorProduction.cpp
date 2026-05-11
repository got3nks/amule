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

#include "NatTraversalCoordinator.h"

#ifdef ENABLE_NAT_T

// Production thunks for CNatTraversalCoordinator's five delegates.
// Lives in a separate TU from NatTraversalCoordinator.cpp because
// the thunks pull in theApp / CClientList / CDownloadQueue /
// CUploadQueue / CUpDownClient / CClientUDPSocket — globals the
// unit-test target deliberately doesn't link against. Same split
// pattern as src/UtpEncryptionProduction.cpp from Phase B5.
//
// Production code calls InstallProductionDelegates() once at
// startup (from CClientUDPSocket's ctor, alongside
// UtpEncryption::InstallProductionDelegates from B6 and
// UtpTimer::Start from B7). After that, all five coordinator
// delegates are live and route through theApp.

#include "amule.h"               // theApp
#include "ClientList.h"          // GetBuddy, GetClientsByHash
#include "ClientUDPSocket.h"     // CClientUDPSocket (complete type for theApp->clientudp)
#include "DownloadQueue.h"       // GetDownloadClientByIP_UDP
#include "UploadQueue.h"         // GetWaitingClientByIP_UDP
#include "updownclient.h"        // CUpDownClient
#include "MuleUDPSocket.h"       // ::SendPacket
#include "Packet.h"              // CPacket
#include "Preferences.h"         // thePrefs::GetUserHash
#include "MD4Hash.h"             // CMD4Hash
#include "NatTraversal.h"        // OP_RENDEZVOUS_OPCODE, OP_HOLEPUNCH_OPCODE
#include "UtpEnvironment.h"      // GetContext
#include "UtpLayer.h"            // CUtpLayer
#include "UtpLayerRegistry.h"    // Register (so on_accept finds the layer)

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

#include <protocol/Protocols.h>            // OP_EMULEPROT

namespace {

// --- LookupClientByHash ----------------------------------------------
//
// Used by D2 (HighID buddy role) to find where to forward an
// inbound OP_RENDEZVOUS. CClientList::GetClientsByHash returns a
// list of all CUpDownClients we have any record of with the given
// user hash; for our purposes any one with a known UDP endpoint is
// good enough — the buddy needs to be able to send the forwarded
// RENDEZVOUS via UDP to the target.
bool production_lookup_client_by_hash(
	const std::uint8_t user_hash[NatTraversal::kUserHashSize],
	std::uint32_t& out_ip_host,
	std::uint16_t& out_udp_port)
{
	if (user_hash == nullptr || theApp == nullptr ||
	    theApp->clientlist == nullptr) {
		return false;
	}
	CMD4Hash hash(user_hash);
	CClientList::SourceList sources = theApp->clientlist->GetClientsByHash(hash);
	for (auto& ref : sources) {
		CUpDownClient* client = ref.GetClient();
		if (client == nullptr) continue;
		// We need a usable UDP endpoint to forward to. UDP port and
		// IP must both be set for the forward to land.
		const std::uint16_t udp_port = client->GetUDPPort();
		const std::uint32_t ip       = client->GetIP();    // already host order
		if (udp_port == 0 || ip == 0) continue;
		out_ip_host   = ip;
		out_udp_port  = udp_port;
		return true;
	}
	return false;
}


// --- LookupClientByEndpoint ------------------------------------------
//
// Used by D4 (LowID endpoint role) to identify the requester whose
// external UDP endpoint the buddy filled into the forwarded
// OP_RENDEZVOUS body. Try the download-queue first (more likely to
// hit for a typical NAT-T flow where the requester is downloading
// from us), then the upload-queue.
bool production_lookup_client_by_endpoint(
	std::uint32_t ip_host,
	std::uint16_t udp_port,
	std::uint8_t out_user_hash[NatTraversal::kUserHashSize])
{
	if (theApp == nullptr || out_user_hash == nullptr) {
		return false;
	}

	CUpDownClient* client = nullptr;

	if (theApp->downloadqueue != nullptr) {
		client = theApp->downloadqueue->GetDownloadClientByIP_UDP(
			ip_host, udp_port);
	}
	if (client == nullptr && theApp->uploadqueue != nullptr) {
		client = theApp->uploadqueue->GetWaitingClientByIP_UDP(
			ip_host, udp_port, /*bIgnorePortOnUniqueIP=*/true);
	}
	if (client == nullptr) {
		return false;
	}

	const CMD4Hash& userHash = client->GetUserHash();
	if (userHash.IsEmpty()) {
		return false;
	}
	std::memcpy(out_user_hash, userHash.GetHash(),
	            NatTraversal::kUserHashSize);
	return true;
}


// --- SendEmuleProt ---------------------------------------------------
//
// Used by D2 + D3 to emit OP_EMULEPROT-wrapped UDP packets carrying
// OP_RENDEZVOUS (0xA0) or OP_HOLEPUNCH (0xA1) inner opcodes. Wraps
// `body` into a CPacket constructed with OP_EMULEPROT envelope +
// the specified opcode, then sends via the client UDP socket. We
// don't encrypt-to-peer at this layer because OP_EMULEPROT through
// CClientUDPSocket's SendPacket already handles encryption when the
// peer supports it.
bool production_send_emule_prot(
	std::uint8_t opcode,
	const std::uint8_t* body, std::size_t body_len,
	std::uint32_t dest_ip_host,
	std::uint16_t dest_udp_port)
{
	if (theApp == nullptr || theApp->clientudp == nullptr) {
		return false;
	}

	// CPacket's body-bearing constructor takes (data, length, protocol,
	// opcode). For zero-body packets, the body-less constructor takes
	// just opcode + protocol (no length).
	CPacket* packet = nullptr;
	if (body != nullptr && body_len > 0) {
		packet = new CPacket(
			const_cast<std::uint8_t*>(body),
			static_cast<std::uint32_t>(body_len),
			OP_EMULEPROT,
			opcode);
	} else {
		packet = new CPacket(opcode, 0, OP_EMULEPROT);
	}

	// Send through CClientUDPSocket. The Hash-or-KadID and verify-key
	// args are zeroed — these are for the per-peer encrypted UDP
	// path; OP_RENDEZVOUS / OP_HOLEPUNCH are sent in the clear at
	// the eD2k UDP layer (the inner NAT-T encryption is applied
	// to uTP frames only, by UtpEncryption — sub-byte 0x00). The
	// buddy / endpoint paths reach plain UDP listeners.
	theApp->clientudp->SendPacket(
		packet,
		dest_ip_host,
		dest_udp_port,
		/*bEncrypt=*/false,
		/*pachTargetClientHashORKadID=*/nullptr,
		/*bKad=*/false,
		/*nReceiverVerifyKey=*/0);
	return true;
}


// --- FindBuddy -------------------------------------------------------
//
// Used by D3 (LowID requester role) to locate a HighID NAT-T-capable
// peer to relay OP_RENDEZVOUS through. D5a's single-buddy mode:
// query CClientList::GetBuddy() and return its UDP endpoint if the
// buddy advertised SupportsNatTraversal (the NAT-T bit on the
// connectOptions byte propagated through ClientList::RequestBuddy in
// D5a's one-line edit). D5b will replace this with the multi-served-
// buddy iterator.
bool production_find_buddy(std::uint32_t& out_buddy_ip_host,
                           std::uint16_t& out_buddy_udp_port)
{
	if (theApp == nullptr || theApp->clientlist == nullptr) {
		return false;
	}
	CUpDownClient* buddy = theApp->clientlist->GetBuddy();
	if (buddy == nullptr) {
		return false;
	}
	if (!buddy->SupportsNatTraversal()) {
		// Buddy exists but doesn't speak NAT-T. Can't use them as
		// rendezvous relay; the rendezvous would just go nowhere.
		return false;
	}
	const std::uint16_t udp_port = buddy->GetUDPPort();
	const std::uint32_t ip       = buddy->GetIP();
	if (udp_port == 0 || ip == 0) {
		return false;
	}
	out_buddy_ip_host   = ip;
	out_buddy_udp_port  = udp_port;
	return true;
}


// --- CreateUtpLayer --------------------------------------------------
//
// Used by D3 (requester) and D4 (endpoint) to construct CUtpLayers
// for the actual uTP traffic. Production wires the layer to the
// process-wide utp_context from UtpEnvironment and registers it in
// UtpLayerRegistry so the inbound dispatch / on_accept paths can
// find it. The caller takes ownership of the returned pointer.
CUtpLayer* production_create_utp_layer(
	const std::uint8_t our_hash[NatTraversal::kUserHashSize],
	const std::uint8_t peer_hash[NatTraversal::kUserHashSize],
	const struct sockaddr* peer_addr,
	socklen_t addr_len,
	bool initiator)
{
	utp_context* ctx = UtpEnvironment::GetContext();
	if (ctx == nullptr || our_hash == nullptr || peer_hash == nullptr ||
	    peer_addr == nullptr || addr_len == 0) {
		return nullptr;
	}

	CUtpLayer* layer = new CUtpLayer(ctx);
	if (!layer->Connect(our_hash, peer_hash, peer_addr, addr_len, initiator)) {
		delete layer;
		return nullptr;
	}
	// CUtpLayer::Connect internally registers the layer in
	// UtpLayerRegistry under both peer_hash and peer_addr keys
	// (B7.5 wiring) — no extra Register call needed here.
	return layer;
}

} // anonymous namespace


namespace NatTraversal {

// Installs the production thunks on the singleton coordinator and
// publishes the process-level user hash from thePrefs. Called once
// at daemon start from CClientUDPSocket's ctor.
void InstallNatTraversalCoordinatorProductionDelegates()
{
	auto& coord = CNatTraversalCoordinator::Instance();

	// Process-level user hash. thePrefs::GetUserHash() returns the
	// stable CMD4Hash that identifies this client across sessions.
	const CMD4Hash& userHash = thePrefs::GetUserHash();
	if (!userHash.IsEmpty()) {
		coord.SetOurUserHash(userHash.GetHash());
	}

	coord.SetLookupClientByHashDelegate(&production_lookup_client_by_hash);
	coord.SetLookupClientByEndpointDelegate(&production_lookup_client_by_endpoint);
	coord.SetSendEmuleProtDelegate(&production_send_emule_prot);
	coord.SetFindBuddyDelegate(&production_find_buddy);
	coord.SetCreateUtpLayerDelegate(&production_create_utp_layer);
}

} // namespace NatTraversal

#endif // ENABLE_NAT_T
