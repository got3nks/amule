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

// Phase D6 of the NAT-T port — 3-node integration test for the
// rendezvous state machine.
//
// We stand up three independent CNatTraversalCoordinator instances
// in-process (one per simulated peer: requester, buddy, endpoint)
// and connect them via a thread-local "current node" + synchronous
// in-process router. The router intercepts each coordinator's
// outbound SendEmuleProt and re-injects the packet on the
// destination node's matching inbound handler (OnInboundRendezvous
// or OnInboundHolePunch), with src_ip/src_port set from the
// sender's "external" address. This mirrors the wire-level dispatch
// that CClientUDPSocket performs in production (Phase C1).
//
// CreateUtpLayer is stubbed to a recording factory that returns
// sentinel pointers — D6's job is rendezvous correctness across
// nodes; the actual uTP handshake is already verified end-to-end
// by B8's loopback integration test.
//
// Scope:
//   1. ThreeNodeRendezvousCompletesEndToEnd — plan-spec headline:
//      full happy path requester → buddy → endpoint → HOLEPUNCH →
//      requester callback fires with success.
//   2. BuddyForwardsExtEndpointToEndpoint — verifies the buddy
//      fills in req.requester_ext_endpoint when forwarding (the
//      load-bearing wire-format invariant from D2).
//   3. MultipleRendezvousThroughSameBuddy — two concurrent
//      requesters share the same buddy and reach two distinct
//      endpoints; the buddy's per-target lookup must not cross
//      streams.
//   4. BuddyWithoutEndpointKnowledgeDropsRendezvous — buddy doesn't
//      know the target; no forward, no HOLEPUNCH; requester's
//      pending entry stays live and eventually times out (drive
//      CheckTimeouts to confirm).
//   5. EndpointDropsUnknownRequester — endpoint can't identify the
//      requester via the ext_endpoint lookup; endpoint's factory
//      is NOT called. The requester still completes via the
//      HOLEPUNCH path (the buddy emitted HOLEPUNCH before the
//      forward outcome was known on the endpoint side, matching
//      production behavior).

#include <muleunit/test.h>
#include "NatTraversalCoordinator.h"

#ifdef ENABLE_NAT_T

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <utility>
#include <vector>

using namespace muleunit;

// Forward-decl of CUtpLayer in the global namespace — the coordinator's
// factory delegate signature uses ::CUtpLayer*; if we forward-decl
// inside the anonymous namespace below, it creates a different
// (anonymous)::CUtpLayer that won't match the delegate's signature.
class CUtpLayer;

DECLARE(NatTraversalIntegration)
END_DECLARE;


namespace {

using HashArray = std::array<std::uint8_t, NatTraversal::kUserHashSize>;

// One simulated peer: its external UDP endpoint, identity hash,
// and its own coordinator. The buddy + endpoint also carry small
// "known clients" tables that back their lookup delegates.
struct Node {
	HashArray   user_hash{};
	sockaddr_in addr{};          // host-byte-order fields stored in network order, as usual

	// LookupClientByHash table — used by buddy to find LowID
	// endpoints. Keyed on user hash.
	std::map<HashArray, sockaddr_in> known_by_hash;

	// LookupClientByEndpoint table — used by endpoint to identify
	// inbound requesters. Keyed on (ip,port) host-byte-order.
	std::map<std::uint64_t, HashArray> known_by_endpoint;

	NatTraversal::CNatTraversalCoordinator coord;
};

// Encode (ip_host, port) as a single uint64 for the endpoint
// lookup table key.
std::uint64_t pack_endpoint(std::uint32_t ip, std::uint16_t port) {
	return (static_cast<std::uint64_t>(ip) << 16) | port;
}

// Factory-call recorder. Each CreateUtpLayer invocation gets
// appended here so tests can verify which side opened which
// direction (initiator true = D3 requester, false = D4 endpoint).
struct FactoryCall {
	bool        initiator;
	HashArray   our_hash;
	HashArray   peer_hash;
	std::uint32_t peer_ip_host;
	std::uint16_t peer_port;
};
std::vector<FactoryCall> g_factory_calls;

// Globals that the C-style function pointers route through.
// Single-threaded test, no locking needed.
Node*               g_current_node = nullptr;  // sender's identity for outbound SendEmuleProt
std::vector<Node*>  g_all_nodes;

// RAII helper: sets g_current_node on construction, restores on
// destruction. Use around every entry into a coordinator method
// from outside the router (e.g. RequestRendezvous, CheckTimeouts).
struct ScopedCurrentNode {
	Node* prev;
	explicit ScopedCurrentNode(Node* n) : prev(g_current_node) {
		g_current_node = n;
	}
	~ScopedCurrentNode() { g_current_node = prev; }
};

Node* find_node_by_addr(std::uint32_t ip_host, std::uint16_t port) {
	for (Node* n : g_all_nodes) {
		if (ntohl(n->addr.sin_addr.s_addr) == ip_host &&
		    ntohs(n->addr.sin_port) == port) {
			return n;
		}
	}
	return nullptr;
}

// === Delegate implementations =====================================

// LookupClientByHash: consults the current node's known_by_hash.
bool router_lookup_by_hash(const std::uint8_t user_hash[NatTraversal::kUserHashSize],
                          std::uint32_t& out_ip_host, std::uint16_t& out_udp_port) {
	if (g_current_node == nullptr) return false;
	HashArray key;
	std::memcpy(key.data(), user_hash, NatTraversal::kUserHashSize);
	auto it = g_current_node->known_by_hash.find(key);
	if (it == g_current_node->known_by_hash.end()) return false;
	out_ip_host  = ntohl(it->second.sin_addr.s_addr);
	out_udp_port = ntohs(it->second.sin_port);
	return true;
}

// LookupClientByEndpoint: consults the current node's
// known_by_endpoint table.
bool router_lookup_by_endpoint(std::uint32_t ip_host, std::uint16_t udp_port,
                               std::uint8_t out_user_hash[NatTraversal::kUserHashSize]) {
	if (g_current_node == nullptr) return false;
	auto it = g_current_node->known_by_endpoint.find(pack_endpoint(ip_host, udp_port));
	if (it == g_current_node->known_by_endpoint.end()) return false;
	std::memcpy(out_user_hash, it->second.data(), NatTraversal::kUserHashSize);
	return true;
}

// Forward decl so SendEmuleProt can call into it.
void deliver_packet(Node* sender, Node* dest, std::uint8_t opcode,
                    const std::uint8_t* body, std::size_t body_len);

// SendEmuleProt: looks up the destination node by address and
// re-injects the packet on its inbound dispatch.
bool router_send_emule_prot(std::uint8_t opcode,
                            const std::uint8_t* body, std::size_t body_len,
                            std::uint32_t dest_ip_host,
                            std::uint16_t dest_udp_port) {
	Node* sender = g_current_node;
	Node* dest   = find_node_by_addr(dest_ip_host, dest_udp_port);
	if (sender == nullptr || dest == nullptr) return false;
	deliver_packet(sender, dest, opcode, body, body_len);
	return true;
}

// FindBuddy: each requester node stores a single "my buddy"
// address that this delegate returns. Held in a parallel global
// keyed on the calling node — set by tests via set_buddy_for.
std::map<Node*, sockaddr_in> g_buddy_for;

bool router_find_buddy(std::uint32_t& out_ip, std::uint16_t& out_port) {
	if (g_current_node == nullptr) return false;
	auto it = g_buddy_for.find(g_current_node);
	if (it == g_buddy_for.end()) return false;
	out_ip   = ntohl(it->second.sin_addr.s_addr);
	out_port = ntohs(it->second.sin_port);
	return true;
}

void set_buddy_for(Node* requester, const sockaddr_in& buddy) {
	g_buddy_for[requester] = buddy;
}

// CreateUtpLayer: recording-only stub. Returns a non-null sentinel
// pointer derived from the call sequence number, so each call's
// return value is uniquely identifiable in the on_complete callback.
// CUtpLayer is forward-declared at file scope above (must be the
// ::CUtpLayer the coordinator delegate refers to, not an
// anonymous-namespace shadow).
::CUtpLayer* router_create_utp_layer(
		const std::uint8_t our_hash[NatTraversal::kUserHashSize],
		const std::uint8_t peer_hash[NatTraversal::kUserHashSize],
		const struct sockaddr* peer_addr,
		socklen_t /*addr_len*/,
		bool initiator) {
	FactoryCall call;
	call.initiator = initiator;
	std::memcpy(call.our_hash.data(),  our_hash,  NatTraversal::kUserHashSize);
	std::memcpy(call.peer_hash.data(), peer_hash, NatTraversal::kUserHashSize);
	const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(peer_addr);
	call.peer_ip_host = ntohl(sin->sin_addr.s_addr);
	call.peer_port    = ntohs(sin->sin_port);
	g_factory_calls.push_back(call);
	// Sentinel: index-derived so the test can distinguish them.
	return reinterpret_cast<::CUtpLayer*>(static_cast<std::uintptr_t>(0x1000 + g_factory_calls.size()));
}

// Synchronous packet delivery into dest's coordinator. Swaps the
// thread-local current_node so any nested SendEmuleProt issued
// from dest's handler routes from dest as the source.
void deliver_packet(Node* sender, Node* dest, std::uint8_t opcode,
                    const std::uint8_t* body, std::size_t body_len) {
	const std::uint32_t src_ip   = ntohl(sender->addr.sin_addr.s_addr);
	const std::uint16_t src_port = ntohs(sender->addr.sin_port);

	ScopedCurrentNode guard(dest);

	if (opcode == NatTraversal::OP_RENDEZVOUS_OPCODE) {
		NatTraversal::RendezvousRequest req;
		if (NatTraversal::DecodeRendezvous(body, body_len, req)) {
			dest->coord.OnInboundRendezvous(req, src_ip, src_port);
		}
	} else if (opcode == NatTraversal::OP_HOLEPUNCH_OPCODE) {
		dest->coord.OnInboundHolePunch(src_ip, src_port);
	}
	// Other opcodes ignored.
}

// === Node setup ====================================================

sockaddr_in make_addr(std::uint32_t ip_host, std::uint16_t port) {
	sockaddr_in s;
	std::memset(&s, 0, sizeof(s));
	s.sin_family      = AF_INET;
	s.sin_port        = htons(port);
	s.sin_addr.s_addr = htonl(ip_host);
	return s;
}

void wire_node(Node* n, const HashArray& user_hash, std::uint32_t ip_host, std::uint16_t port) {
	n->user_hash = user_hash;
	n->addr      = make_addr(ip_host, port);
	n->coord.SetOurUserHash(user_hash.data());
	n->coord.SetLookupClientByHashDelegate(&router_lookup_by_hash);
	n->coord.SetLookupClientByEndpointDelegate(&router_lookup_by_endpoint);
	n->coord.SetSendEmuleProtDelegate(&router_send_emule_prot);
	n->coord.SetFindBuddyDelegate(&router_find_buddy);
	n->coord.SetCreateUtpLayerDelegate(&router_create_utp_layer);
}

HashArray fill_hash(std::uint8_t base) {
	HashArray h;
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		h[i] = static_cast<std::uint8_t>(base + i);
	}
	return h;
}

// Clean global state between cases.
void reset_globals() {
	g_factory_calls.clear();
	g_current_node = nullptr;
	g_all_nodes.clear();
	g_buddy_for.clear();
}

} // anonymous namespace


// === Tests =========================================================

// Plan-spec headline. Three nodes, full happy path:
//   requester (LowID) → buddy (HighID) → endpoint (LowID)
//   buddy forwards OP_RENDEZVOUS to endpoint AND sends OP_HOLEPUNCH back
//   endpoint creates passive uTP layer (initiator=false)
//   requester receives HOLEPUNCH, creates active uTP layer (initiator=true)
//   requester's on_complete fires with ok=true, layer=non-null.
TEST(NatTraversalIntegration, ThreeNodeRendezvousCompletesEndToEnd)
{
	reset_globals();

	auto requester_hash = fill_hash(0x10);
	auto buddy_hash     = fill_hash(0x20);
	auto endpoint_hash  = fill_hash(0x30);

	auto requester = std::unique_ptr<Node>(new Node());
	auto buddy     = std::unique_ptr<Node>(new Node());
	auto endpoint  = std::unique_ptr<Node>(new Node());

	wire_node(requester.get(), requester_hash, 0x0A000001u, 4662);  // 10.0.0.1
	wire_node(buddy.get(),     buddy_hash,     0x0A000002u, 4662);  // 10.0.0.2
	wire_node(endpoint.get(),  endpoint_hash,  0x0A000003u, 4662);  // 10.0.0.3

	g_all_nodes = {requester.get(), buddy.get(), endpoint.get()};

	// Buddy knows the endpoint (Kad publish / prior source-exchange).
	buddy->known_by_hash[endpoint_hash] = endpoint->addr;
	// Endpoint knows the requester via ext_endpoint (simulated prior
	// source-exchange — production: typically a Kad publish record).
	endpoint->known_by_endpoint[pack_endpoint(0x0A000001u, 4662)] = requester_hash;

	// Requester is configured to ask THIS buddy.
	set_buddy_for(requester.get(), buddy->addr);

	// Drive the rendezvous.
	std::atomic<int>     completed_count(0);
	std::atomic<bool>    success(false);
	std::atomic<void*>   received_layer(nullptr);
	{
		ScopedCurrentNode guard(requester.get());
		requester->coord.RequestRendezvous(
			endpoint_hash.data(),
			reinterpret_cast<sockaddr*>(&endpoint->addr),
			sizeof(endpoint->addr),
			[&](bool ok, ::CUtpLayer* layer) {
				completed_count.fetch_add(1);
				success.store(ok);
				received_layer.store(reinterpret_cast<void*>(layer));
			});
	}

	// Synchronous router => completion already fired before
	// RequestRendezvous returned (buddy forwarded RENDEZVOUS, sent
	// HOLEPUNCH; the synchronous HOLEPUNCH delivery into requester
	// fired OnInboundHolePunch which created the active layer +
	// fired the on_complete callback).
	ASSERT_EQUALS(1, completed_count.load());
	ASSERT_TRUE(success.load());
	ASSERT_TRUE(received_layer.load() != nullptr);

	// Two factory calls: endpoint's passive, then requester's active
	// (order: buddy first synchronously forwarded RENDEZVOUS to
	// endpoint, which created the passive layer; then buddy emitted
	// HOLEPUNCH back to requester, which created the active layer).
	ASSERT_EQUALS((std::size_t)2, g_factory_calls.size());
	ASSERT_FALSE(g_factory_calls[0].initiator);  // endpoint creates passive (D4)
	ASSERT_TRUE(g_factory_calls[1].initiator);   // requester creates active (D3)

	// Endpoint's factory call carries the requester's address as
	// peer_addr (the address libutp's on_accept will match against).
	ASSERT_EQUALS((std::uint32_t)0x0A000001u, g_factory_calls[0].peer_ip_host);
	ASSERT_EQUALS((std::uint16_t)4662, g_factory_calls[0].peer_port);
	// Requester's factory call carries the endpoint's address.
	ASSERT_EQUALS((std::uint32_t)0x0A000003u, g_factory_calls[1].peer_ip_host);
	ASSERT_EQUALS((std::uint16_t)4662, g_factory_calls[1].peer_port);
}

// Verify the buddy fills in req.requester_ext_endpoint when
// forwarding RENDEZVOUS to the endpoint. This is the wire-format
// invariant that lets the endpoint identify the requester's NAT
// address — without it, the endpoint can't know which inbound uTP
// SYN to expect / accept.
TEST(NatTraversalIntegration, BuddyForwardsExtEndpointToEndpoint)
{
	reset_globals();

	auto requester_hash = fill_hash(0x40);
	auto buddy_hash     = fill_hash(0x50);
	auto endpoint_hash  = fill_hash(0x60);

	auto requester = std::unique_ptr<Node>(new Node());
	auto buddy     = std::unique_ptr<Node>(new Node());
	auto endpoint  = std::unique_ptr<Node>(new Node());

	wire_node(requester.get(), requester_hash, 0x0B000001u, 5566);
	wire_node(buddy.get(),     buddy_hash,     0x0B000002u, 5566);
	wire_node(endpoint.get(),  endpoint_hash,  0x0B000003u, 5566);

	g_all_nodes = {requester.get(), buddy.get(), endpoint.get()};

	buddy->known_by_hash[endpoint_hash] = endpoint->addr;
	endpoint->known_by_endpoint[pack_endpoint(0x0B000001u, 5566)] = requester_hash;

	set_buddy_for(requester.get(), buddy->addr);

	{
		ScopedCurrentNode guard(requester.get());
		requester->coord.RequestRendezvous(
			endpoint_hash.data(),
			reinterpret_cast<sockaddr*>(&endpoint->addr),
			sizeof(endpoint->addr),
			[&](bool /*ok*/, ::CUtpLayer* /*layer*/) {});
	}

	// Endpoint's factory call's peer_addr == requester's external
	// address — this proves the buddy filled in the ext_endpoint
	// correctly when forwarding (without that fill-in, the
	// endpoint's CreateUtpLayer would either not fire at all or
	// fire with the buddy's address by mistake).
	ASSERT_EQUALS((std::size_t)2, g_factory_calls.size());
	ASSERT_FALSE(g_factory_calls[0].initiator);
	ASSERT_EQUALS((std::uint32_t)0x0B000001u, g_factory_calls[0].peer_ip_host);
	ASSERT_EQUALS((std::uint16_t)5566, g_factory_calls[0].peer_port);
}

// Two concurrent requesters sharing one buddy reach two distinct
// endpoints. The buddy's per-target lookup must route each
// rendezvous to the right endpoint without crossing streams.
TEST(NatTraversalIntegration, MultipleRendezvousThroughSameBuddy)
{
	reset_globals();

	auto r1_hash       = fill_hash(0x01);
	auto r2_hash       = fill_hash(0x02);
	auto buddy_hash    = fill_hash(0x70);
	auto endpoint1_hash = fill_hash(0x71);
	auto endpoint2_hash = fill_hash(0x72);

	auto r1   = std::unique_ptr<Node>(new Node());
	auto r2   = std::unique_ptr<Node>(new Node());
	auto buddy = std::unique_ptr<Node>(new Node());
	auto e1   = std::unique_ptr<Node>(new Node());
	auto e2   = std::unique_ptr<Node>(new Node());

	wire_node(r1.get(),   r1_hash,       0x0C000001u, 4662);
	wire_node(r2.get(),   r2_hash,       0x0C000002u, 4662);
	wire_node(buddy.get(), buddy_hash,   0x0C000099u, 4662);
	wire_node(e1.get(),   endpoint1_hash, 0x0C00000Au, 4662);
	wire_node(e2.get(),   endpoint2_hash, 0x0C00000Bu, 4662);

	g_all_nodes = {r1.get(), r2.get(), buddy.get(), e1.get(), e2.get()};

	buddy->known_by_hash[endpoint1_hash] = e1->addr;
	buddy->known_by_hash[endpoint2_hash] = e2->addr;
	e1->known_by_endpoint[pack_endpoint(0x0C000001u, 4662)] = r1_hash;
	e2->known_by_endpoint[pack_endpoint(0x0C000002u, 4662)] = r2_hash;

	set_buddy_for(r1.get(), buddy->addr);
	set_buddy_for(r2.get(), buddy->addr);

	std::atomic<int> completed(0);
	{
		ScopedCurrentNode guard(r1.get());
		r1->coord.RequestRendezvous(
			endpoint1_hash.data(),
			reinterpret_cast<sockaddr*>(&e1->addr), sizeof(e1->addr),
			[&](bool ok, ::CUtpLayer*) { if (ok) completed.fetch_add(1); });
	}
	{
		ScopedCurrentNode guard(r2.get());
		r2->coord.RequestRendezvous(
			endpoint2_hash.data(),
			reinterpret_cast<sockaddr*>(&e2->addr), sizeof(e2->addr),
			[&](bool ok, ::CUtpLayer*) { if (ok) completed.fetch_add(1); });
	}

	ASSERT_EQUALS(2, completed.load());

	// Four factory calls: two passive (one per endpoint), two active
	// (one per requester). Order: rendezvous 1 fully drives (passive
	// then active), then rendezvous 2 fully drives. So [0]=e1 passive,
	// [1]=r1 active, [2]=e2 passive, [3]=r2 active.
	ASSERT_EQUALS((std::size_t)4, g_factory_calls.size());
	ASSERT_FALSE(g_factory_calls[0].initiator);
	ASSERT_TRUE(g_factory_calls[1].initiator);
	ASSERT_FALSE(g_factory_calls[2].initiator);
	ASSERT_TRUE(g_factory_calls[3].initiator);

	// Cross-stream isolation: e1's passive layer points at r1 (not r2),
	// and e2's points at r2 (not r1).
	ASSERT_EQUALS((std::uint32_t)0x0C000001u, g_factory_calls[0].peer_ip_host);  // e1 ← r1
	ASSERT_EQUALS((std::uint32_t)0x0C000002u, g_factory_calls[2].peer_ip_host);  // e2 ← r2
}

// Buddy doesn't know the endpoint. No forward, no HOLEPUNCH. The
// requester's pending entry stays live; eventually CheckTimeouts
// fires the failure callback.
TEST(NatTraversalIntegration, BuddyWithoutEndpointKnowledgeTimesOut)
{
	reset_globals();

	auto requester_hash = fill_hash(0x80);
	auto buddy_hash     = fill_hash(0x81);
	auto endpoint_hash  = fill_hash(0x82);

	auto requester = std::unique_ptr<Node>(new Node());
	auto buddy     = std::unique_ptr<Node>(new Node());
	auto endpoint  = std::unique_ptr<Node>(new Node());

	wire_node(requester.get(), requester_hash, 0x0D000001u, 4662);
	wire_node(buddy.get(),     buddy_hash,     0x0D000002u, 4662);
	wire_node(endpoint.get(),  endpoint_hash,  0x0D000003u, 4662);

	g_all_nodes = {requester.get(), buddy.get(), endpoint.get()};

	// NOTE: buddy->known_by_hash is empty — buddy doesn't know endpoint.

	set_buddy_for(requester.get(), buddy->addr);

	std::atomic<int>  completed_count(0);
	std::atomic<bool> success(true);  // sentinel so we can prove failure
	{
		ScopedCurrentNode guard(requester.get());
		requester->coord.RequestRendezvous(
			endpoint_hash.data(),
			reinterpret_cast<sockaddr*>(&endpoint->addr),
			sizeof(endpoint->addr),
			[&](bool ok, ::CUtpLayer*) {
				completed_count.fetch_add(1);
				success.store(ok);
			});
	}

	// Buddy drops silently; no HOLEPUNCH; callback hasn't fired yet.
	ASSERT_EQUALS(0, completed_count.load());
	ASSERT_EQUALS((std::size_t)1, requester->coord.PendingCount());
	ASSERT_EQUALS((std::size_t)0, g_factory_calls.size());

	// First CheckTimeouts call seeds the deadline (deadline_ms == 0
	// path); doesn't expire anything. Second call after the timeout
	// window fires the failure callback.
	requester->coord.CheckTimeouts(0);
	ASSERT_EQUALS(0, completed_count.load());

	requester->coord.CheckTimeouts(
		NatTraversal::CNatTraversalCoordinator::kRendezvousTimeoutMs);
	ASSERT_EQUALS(1, completed_count.load());
	ASSERT_FALSE(success.load());
	ASSERT_EQUALS((std::size_t)0, requester->coord.PendingCount());
}

// Endpoint can't identify the requester via the ext_endpoint
// lookup (no prior source-exchange / Kad publish): endpoint's
// CreateUtpLayer is NOT invoked. The buddy already emitted
// HOLEPUNCH to the requester before the forward outcome was known
// on the endpoint side, so the requester DOES complete its
// rendezvous and creates its own active layer — but the endpoint
// won't be ready for the SYN, so libutp's on_accept rejects.
// (This is the documented graceful-degradation behavior from D4.)
TEST(NatTraversalIntegration, EndpointDropsUnknownRequester)
{
	reset_globals();

	auto requester_hash = fill_hash(0x90);
	auto buddy_hash     = fill_hash(0x91);
	auto endpoint_hash  = fill_hash(0x92);

	auto requester = std::unique_ptr<Node>(new Node());
	auto buddy     = std::unique_ptr<Node>(new Node());
	auto endpoint  = std::unique_ptr<Node>(new Node());

	wire_node(requester.get(), requester_hash, 0x0E000001u, 4662);
	wire_node(buddy.get(),     buddy_hash,     0x0E000002u, 4662);
	wire_node(endpoint.get(),  endpoint_hash,  0x0E000003u, 4662);

	g_all_nodes = {requester.get(), buddy.get(), endpoint.get()};

	buddy->known_by_hash[endpoint_hash] = endpoint->addr;
	// NOTE: endpoint->known_by_endpoint is empty — endpoint doesn't
	// recognise the requester.

	set_buddy_for(requester.get(), buddy->addr);

	std::atomic<int>     completed_count(0);
	std::atomic<bool>    success(false);
	std::atomic<void*>   received_layer(nullptr);
	{
		ScopedCurrentNode guard(requester.get());
		requester->coord.RequestRendezvous(
			endpoint_hash.data(),
			reinterpret_cast<sockaddr*>(&endpoint->addr),
			sizeof(endpoint->addr),
			[&](bool ok, ::CUtpLayer* layer) {
				completed_count.fetch_add(1);
				success.store(ok);
				received_layer.store(reinterpret_cast<void*>(layer));
			});
	}

	// Requester gets HOLEPUNCH from buddy and completes with success.
	ASSERT_EQUALS(1, completed_count.load());
	ASSERT_TRUE(success.load());
	ASSERT_TRUE(received_layer.load() != nullptr);

	// But only ONE factory call — the requester's active layer.
	// Endpoint's passive-layer factory was NOT invoked because the
	// endpoint's lookup-by-endpoint delegate returned false.
	ASSERT_EQUALS((std::size_t)1, g_factory_calls.size());
	ASSERT_TRUE(g_factory_calls[0].initiator);
	ASSERT_EQUALS((std::uint32_t)0x0E000003u, g_factory_calls[0].peer_ip_host);
}

#else // ENABLE_NAT_T

// ENABLE_NAT_T=OFF: nothing to test. Register a single tautological
// case so the cmake-registered ctest target has something to run.
using namespace muleunit;
DECLARE(NatTraversalIntegration)
END_DECLARE;

TEST(NatTraversalIntegration, FeatureDisabled)
{
	ASSERT_TRUE(true);
}

#endif // ENABLE_NAT_T
