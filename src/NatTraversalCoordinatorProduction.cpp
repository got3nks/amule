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
#include "ClientTCPSocket.h"     // CClientTCPSocket (responder handoff)
#include "ClientUDPSocket.h"     // CClientUDPSocket (complete type for theApp->clientudp)
#include "DownloadQueue.h"       // GetDownloadClientByIP_UDP
#include "GuiEvents.h"           // CoreNotify_LibSocketReceive (responder handoff)
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

	// Phase E3 responder-side handoff: the initiator's success
	// path in BaseClient.cpp::OnNatTraversalComplete creates a fresh
	// CClientTCPSocket, AttachUtpLayers(layer), installs a data-available
	// callback, then fires ConnectionEstablished() to send OP_HELLO.
	// The endpoint side is purely reactive — it must NOT call
	// ConnectionEstablished — but it still needs the CClientTCPSocket
	// + AttachUtpLayer wiring so that when the initiator's HELLO arrives
	// over uTP, libutp's on_read → CUtpLayer::OnRead → the data-available
	// callback wakes CClientTCPSocket::OnReceive → ProcessPacket. Without
	// this, accepted SYN data lands in CUtpLayer::m_readBuf and never
	// surfaces; the eD2k packet parser is never invoked on the responder.
	//
	// eMuleAI does the equivalent in CClientUDPSocket.cpp:1262-1314
	// inside OP_RENDEZVOUS handling: it creates target->socket =
	// new CClientReqSocket(target), calls InitUtpSupport() to insert
	// CUtpSocket into the CAsyncSocketEx layer chain, and sets
	// SetUtpLocalInitiator(false). When the SYN arrives, on_accept
	// adopts the libutp socket onto the existing wrapper and the
	// rest of the eD2k flow runs unchanged.
	if (!initiator && theApp != nullptr && theApp->clientlist != nullptr) {
		CMD4Hash peer_user_hash(peer_hash);
		CClientList::SourceList sources =
			theApp->clientlist->GetClientsByHash(peer_user_hash);
		CUpDownClient* peer = nullptr;
		for (auto& ref : sources) {
			CUpDownClient* candidate = ref.GetClient();
			if (candidate != nullptr) {
				peer = candidate;
				break;
			}
		}
		// Cold-start placeholder (eMuleAI parity, ClientUDPSocket.cpp:1085-1119):
		// if the responder has zero prior knowledge of the requester
		// (cold-start NAT-T — neither side ever exchanged Hello,
		// source-exchange, or callback), create a placeholder CUpDownClient
		// from the rendezvous payload (the buddy has already authenticated
		// the hash by accepting us as a served-buddy and forwarding the
		// rendezvous TCP packet). Without this, the responder lookup fails and
		// the responder-side eD2k path is never wired — the inbound
		// uTP data sits in CUtpLayer's read buffer with no consumer.
		if (peer == nullptr &&
		    peer_addr->sa_family == AF_INET &&
		    addr_len >= static_cast<socklen_t>(sizeof(struct sockaddr_in))) {
			const struct sockaddr_in* sin =
				reinterpret_cast<const struct sockaddr_in*>(peer_addr);
			const uint32_t ip_host  = ntohl(sin->sin_addr.s_addr);
			const uint16_t kad_port = ntohs(sin->sin_port);
			// CUpDownClient ctor with ed2kID=false treats in_userid as
			// the raw IP in network byte order; pass it pre-swapped so
			// the ctor's swap-back puts m_nConnectIP in host order.
			peer = new CUpDownClient(
				/*in_port=*/0,                  // TCP port unknown; HELLO will fill it
				/*in_userid=*/htonl(ip_host),   // ctor swaps this back internally
				/*in_serverip=*/0,
				/*in_serverport=*/0,
				/*in_reqfile=*/nullptr,
				/*ed2kID=*/false,
				/*checkfriend=*/true);
			peer->SetIP(ip_host);
			peer->SetKadPort(kad_port);
			peer->SetUserHash(peer_user_hash);
			// Cold-start bypasses ProcessHelloTypePacket so credits
			// stays null; SendBlockData → AddUploaded would crash on the
			// first OP_SENDINGPART. Explicit lookup mirrors eMuleAI's
			// ClientList.cpp:2054 pattern for client paths that skip Hello.
			peer->InitCreditsAfterHandshake();
			peer->SetSourceFrom(SF_KADEMLIA);
			theApp->clientlist->AddClient(peer);
		}
		if (peer != nullptr) {
			// Drop any stale socket on the peer before slotting the
			// new one. Mirrors BaseClient.cpp:1640-1645 logic.
			if (peer->GetSocket() != nullptr) {
				peer->GetSocket()->Safe_Delete();
				peer->SetSocket(nullptr);
			}
			// CClientTCPSocket's ctor calls SetClient → m_client->SetSocket(this),
			// so the new socket is automatically slotted into peer->m_socket.
			CClientTCPSocket* socket = new CClientTCPSocket(
				peer, thePrefs::GetProxyData());
			socket->AttachUtpLayer(layer);
			layer->SetDataAvailableCallback([socket]() {
				CoreNotify_LibSocketReceive(socket, 0);
			});
			// Encryption: same logic as initiator. The peer's hash is
			// known by definition (we matched on it above).
			if (peer->SupportsCryptLayer()
			    && thePrefs::IsClientCryptLayerSupported()
			    && (peer->RequestsCryptLayer()
			        || thePrefs::IsClientCryptLayerRequested())) {
				socket->SetConnectionEncryption(true,
					peer->GetUserHash().GetHash(), false);
			} else {
				socket->SetConnectionEncryption(false, nullptr, false);
			}
			// Deliberately NOT calling ConnectionEstablished — the
			// responder waits for the initiator's HELLO over uTP and
			// then dispatches it through the normal eD2k packet path
			// (ClientTCPSocket::ProcessPacket OP_HELLO branch, which
			// runs ProcessHelloPacket / SendHelloAnswer / etc).
		}
	}

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
