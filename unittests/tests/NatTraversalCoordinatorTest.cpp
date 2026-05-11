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

// Tests for Phase D1 of the NAT-T port — CNatTraversalCoordinator
// skeleton + pending-rendezvous table + timeout management. The
// role-specific behavior (D2 buddy, D3 requester, D4 endpoint) is
// added in later sub-commits and gets its own tests there.
//
// D1 verifies just the bookkeeping: pending-table insert / replace /
// expire, callbacks fire on cancellation + timeout, NULL-arg guards.

#include <muleunit/test.h>
#include "NatTraversalCoordinator.h"

#ifdef ENABLE_NAT_T

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cstring>
#include <map>
#include <netinet/in.h>
#include <sys/socket.h>
#include <utility>
#include <vector>

using namespace muleunit;
using NatTraversal::CNatTraversalCoordinator;

DECLARE(NatTraversalCoordinator)
END_DECLARE;


namespace {

// File-scope mock for FindBuddyFn: a fixed (ip, port) the tests
// can override. install_d1_baseline / install_d3_baseline below
// pre-populate this so RequestRendezvous always finds a buddy.
std::uint32_t g_mock_buddy_ip   = 0;
std::uint16_t g_mock_buddy_port = 0;
bool          g_mock_buddy_available = false;

bool mock_find_buddy(std::uint32_t& out_ip, std::uint16_t& out_port)
{
	if (!g_mock_buddy_available) return false;
	out_ip = g_mock_buddy_ip;
	out_port = g_mock_buddy_port;
	return true;
}

// File-scope no-op SendEmuleProt for D1 tests that don't care about
// outbound packets. D2/D3 tests install their own capture-recording
// version.
bool noop_send_emule_prot(std::uint8_t /*opcode*/,
                          const std::uint8_t* /*body*/, std::size_t /*body_len*/,
                          std::uint32_t /*dest_ip*/,
                          std::uint16_t /*dest_port*/)
{
	return true;
}

sockaddr_in MakeAddr(std::uint32_t ip, std::uint16_t port)
{
	sockaddr_in s;
	std::memset(&s, 0, sizeof(s));
	s.sin_family = AF_INET;
	s.sin_port = htons(port);
	s.sin_addr.s_addr = htonl(ip);
	return s;
}

void fill_hash(std::uint8_t hash[NatTraversal::kUserHashSize], std::uint8_t base)
{
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		hash[i] = static_cast<std::uint8_t>(base + i);
	}
}

// Install the minimum set of delegates needed for D3
// RequestRendezvous to succeed (our_hash + find_buddy +
// send_emule_prot). Used by D1 tests that just want the
// pending-entry bookkeeping path to work without testing the D3
// state machine itself.
void install_d1_baseline()
{
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.ClearPendingForTesting();

	std::uint8_t our_hash[NatTraversal::kUserHashSize];
	fill_hash(our_hash, 0x77);
	coord.SetOurUserHash(our_hash);

	g_mock_buddy_available = true;
	g_mock_buddy_ip        = 0xDEADBEEFu;
	g_mock_buddy_port      = 4242;
	coord.SetFindBuddyDelegate(&mock_find_buddy);
	coord.SetSendEmuleProtDelegate(&noop_send_emule_prot);
}

void teardown_baseline()
{
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.SetFindBuddyDelegate(nullptr);
	coord.SetSendEmuleProtDelegate(nullptr);
	coord.SetCreateUtpLayerDelegate(nullptr);
	coord.SetLookupClientByHashDelegate(nullptr);
	coord.SetOurUserHash(nullptr);
	coord.ClearPendingForTesting();
	g_mock_buddy_available = false;
}

} // anonymous namespace


// RequestRendezvous records an entry in the pending table; the
// callback does NOT fire immediately (it fires only on success
// — D3 — or timeout).
TEST(NatTraversalCoordinator, RequestRendezvousAddsToPending)
{
	install_d1_baseline();
	auto& coord = CNatTraversalCoordinator::Instance();
	ASSERT_EQUALS((std::size_t)0, coord.PendingCount());

	std::uint8_t target_hash[NatTraversal::kUserHashSize];
	fill_hash(target_hash, 0xA0);
	sockaddr_in target_addr = MakeAddr(0x01020304u, 4662);

	std::atomic<int> callback_fires(0);
	coord.RequestRendezvous(target_hash,
	                        reinterpret_cast<sockaddr*>(&target_addr),
	                        sizeof(target_addr),
	                        [&](bool /*ok*/, CUtpLayer* /*layer*/) {
		callback_fires.fetch_add(1);
	});

	ASSERT_EQUALS((std::size_t)1, coord.PendingCount());
	// Callback must NOT have fired yet — request is pending.
	ASSERT_EQUALS(0, callback_fires.load());

	teardown_baseline();
}


// A second RequestRendezvous for the same target cancels the
// previous one — the previous callback fires with (false, nullptr).
TEST(NatTraversalCoordinator, SecondRequestCancelsPreviousCallback)
{
	install_d1_baseline();
	auto& coord = CNatTraversalCoordinator::Instance();

	std::uint8_t target_hash[NatTraversal::kUserHashSize];
	fill_hash(target_hash, 0xA0);
	sockaddr_in target_addr = MakeAddr(0x01020304u, 4662);

	std::atomic<int> first_fires(0);
	std::atomic<bool> first_ok(true);
	coord.RequestRendezvous(target_hash,
	                        reinterpret_cast<sockaddr*>(&target_addr),
	                        sizeof(target_addr),
	                        [&](bool ok, CUtpLayer* /*layer*/) {
		first_fires.fetch_add(1);
		first_ok.store(ok);
	});

	std::atomic<int> second_fires(0);
	coord.RequestRendezvous(target_hash,
	                        reinterpret_cast<sockaddr*>(&target_addr),
	                        sizeof(target_addr),
	                        [&](bool /*ok*/, CUtpLayer* /*layer*/) {
		second_fires.fetch_add(1);
	});

	// First was cancelled — callback fired with failure.
	ASSERT_EQUALS(1, first_fires.load());
	ASSERT_FALSE(first_ok.load());
	// Second is the new pending entry; its callback has NOT fired.
	ASSERT_EQUALS(0, second_fires.load());
	ASSERT_EQUALS((std::size_t)1, coord.PendingCount());

	coord.ClearPendingForTesting();
}


// CheckTimeouts: a pending entry expires after kRendezvousTimeoutMs
// and the callback fires with (false, nullptr).
TEST(NatTraversalCoordinator, PendingEntryTimesOutAfterDeadline)
{
	install_d1_baseline();
	auto& coord = CNatTraversalCoordinator::Instance();

	std::uint8_t target_hash[NatTraversal::kUserHashSize];
	fill_hash(target_hash, 0xA0);
	sockaddr_in target_addr = MakeAddr(0x01020304u, 4662);

	std::atomic<int> fires(0);
	std::atomic<bool> ok(true);
	std::atomic<bool> got_null_layer(false);
	coord.RequestRendezvous(target_hash,
	                        reinterpret_cast<sockaddr*>(&target_addr),
	                        sizeof(target_addr),
	                        [&](bool ok_arg, CUtpLayer* layer) {
		fires.fetch_add(1);
		ok.store(ok_arg);
		got_null_layer.store(layer == nullptr);
	});

	// First tick at t=0: deadline gets initialised to
	// 0 + kRendezvousTimeoutMs. Entry is NOT expired.
	std::size_t expired = coord.CheckTimeouts(0);
	ASSERT_EQUALS((std::size_t)0, expired);
	ASSERT_EQUALS((std::size_t)1, coord.PendingCount());
	ASSERT_EQUALS(0, fires.load());

	// Tick at t = timeout - 1: still not expired.
	expired = coord.CheckTimeouts(
		CNatTraversalCoordinator::kRendezvousTimeoutMs - 1);
	ASSERT_EQUALS((std::size_t)0, expired);
	ASSERT_EQUALS((std::size_t)1, coord.PendingCount());

	// Tick at t = deadline: entry expires, callback fires with
	// failure, table empties.
	expired = coord.CheckTimeouts(
		CNatTraversalCoordinator::kRendezvousTimeoutMs);
	ASSERT_EQUALS((std::size_t)1, expired);
	ASSERT_EQUALS((std::size_t)0, coord.PendingCount());
	ASSERT_EQUALS(1, fires.load());
	ASSERT_FALSE(ok.load());
	ASSERT_TRUE(got_null_layer.load());

	coord.ClearPendingForTesting();
}


// Multiple pending entries with staggered deadlines expire
// independently. Verifies the table iterates correctly + each
// callback fires once.
TEST(NatTraversalCoordinator, MultiplePendingExpireIndependently)
{
	install_d1_baseline();
	auto& coord = CNatTraversalCoordinator::Instance();

	std::atomic<int> fires_a(0);
	std::atomic<int> fires_b(0);
	std::atomic<int> fires_c(0);

	std::uint8_t hash_a[NatTraversal::kUserHashSize];
	std::uint8_t hash_b[NatTraversal::kUserHashSize];
	std::uint8_t hash_c[NatTraversal::kUserHashSize];
	fill_hash(hash_a, 0x10);
	fill_hash(hash_b, 0x20);
	fill_hash(hash_c, 0x30);

	sockaddr_in addr = MakeAddr(0x01020304u, 4662);

	// All three Requests at t=0 (same deadline once CheckTimeouts
	// initialises them).
	coord.RequestRendezvous(hash_a, reinterpret_cast<sockaddr*>(&addr),
	                        sizeof(addr),
	                        [&](bool, CUtpLayer*) { fires_a.fetch_add(1); });
	coord.RequestRendezvous(hash_b, reinterpret_cast<sockaddr*>(&addr),
	                        sizeof(addr),
	                        [&](bool, CUtpLayer*) { fires_b.fetch_add(1); });
	coord.RequestRendezvous(hash_c, reinterpret_cast<sockaddr*>(&addr),
	                        sizeof(addr),
	                        [&](bool, CUtpLayer*) { fires_c.fetch_add(1); });

	ASSERT_EQUALS((std::size_t)3, coord.PendingCount());

	// Initial tick sets deadlines.
	coord.CheckTimeouts(0);
	ASSERT_EQUALS((std::size_t)3, coord.PendingCount());

	// Tick past the deadline — all three expire together.
	std::size_t expired = coord.CheckTimeouts(
		CNatTraversalCoordinator::kRendezvousTimeoutMs + 1);
	ASSERT_EQUALS((std::size_t)3, expired);
	ASSERT_EQUALS((std::size_t)0, coord.PendingCount());
	ASSERT_EQUALS(1, fires_a.load());
	ASSERT_EQUALS(1, fires_b.load());
	ASSERT_EQUALS(1, fires_c.load());

	coord.ClearPendingForTesting();
}


// CheckTimeouts on an empty table is a no-op.
TEST(NatTraversalCoordinator, CheckTimeoutsOnEmptyTableIsNoop)
{
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.ClearPendingForTesting();

	ASSERT_EQUALS((std::size_t)0, coord.CheckTimeouts(0));
	ASSERT_EQUALS((std::size_t)0, coord.CheckTimeouts(1000000));
}


// === Phase D2 — buddy role tests ================================
//
// File-scope captures + mocks used by the D2 buddy-role tests. The
// LookupClientByHash delegate maps test-defined fake hashes to
// fake (ip, port) pairs; the SendEmuleProt delegate records every
// outbound packet for inspection.

namespace {

struct SentPacket {
	std::uint8_t              opcode;
	std::vector<std::uint8_t> body;
	std::uint32_t             dest_ip;
	std::uint16_t             dest_port;
};

std::vector<SentPacket> g_sent;

bool mock_send_emule_prot(std::uint8_t opcode,
                          const std::uint8_t* body, std::size_t body_len,
                          std::uint32_t dest_ip,
                          std::uint16_t dest_port)
{
	SentPacket pkt;
	pkt.opcode = opcode;
	if (body != nullptr && body_len > 0) {
		pkt.body.assign(body, body + body_len);
	}
	pkt.dest_ip = dest_ip;
	pkt.dest_port = dest_port;
	g_sent.push_back(pkt);
	return true;
}

// Mock lookup tables. `g_known_clients` maps user_hash → (ip, port).
std::map<std::array<std::uint8_t, NatTraversal::kUserHashSize>,
         std::pair<std::uint32_t, std::uint16_t>> g_known_clients;

bool mock_lookup_by_hash(const std::uint8_t user_hash[NatTraversal::kUserHashSize],
                        std::uint32_t& out_ip,
                        std::uint16_t& out_port)
{
	std::array<std::uint8_t, NatTraversal::kUserHashSize> key;
	std::memcpy(key.data(), user_hash, NatTraversal::kUserHashSize);
	auto it = g_known_clients.find(key);
	if (it == g_known_clients.end()) {
		return false;
	}
	out_ip = it->second.first;
	out_port = it->second.second;
	return true;
}

void install_d2_mocks()
{
	g_sent.clear();
	g_known_clients.clear();
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.ClearPendingForTesting();
	coord.SetLookupClientByHashDelegate(&mock_lookup_by_hash);
	coord.SetSendEmuleProtDelegate(&mock_send_emule_prot);
}

void teardown_d2_mocks()
{
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.SetLookupClientByHashDelegate(nullptr);
	coord.SetSendEmuleProtDelegate(nullptr);
	coord.ClearPendingForTesting();
	g_sent.clear();
	g_known_clients.clear();
}

} // anonymous namespace


// The headline D2 test: buddy receives OP_RENDEZVOUS from a LowID
// requester (R), the target user is one of our known clients (P),
// so we forward OP_RENDEZVOUS to P (with ext_endpoint = R's source)
// and send OP_HOLEPUNCH back to R.
TEST(NatTraversalCoordinator, BuddyForwardsRendezvousAndSendsHolePunch)
{
	install_d2_mocks();

	// Register P (the target) in the known-clients table.
	std::uint8_t hash_p[NatTraversal::kUserHashSize];
	fill_hash(hash_p, 0xB0);
	std::array<std::uint8_t, NatTraversal::kUserHashSize> key_p;
	std::memcpy(key_p.data(), hash_p, sizeof(hash_p));
	const std::uint32_t ip_p = 0xC0A80101u;   // 192.168.1.1 in host order
	const std::uint16_t port_p = 4662;
	g_known_clients[key_p] = { ip_p, port_p };

	// Build the inbound RENDEZVOUS as if it came from R directly
	// (has_ext_endpoint = false — original, not yet forwarded).
	NatTraversal::RendezvousRequest req;
	std::memcpy(req.target_user_hash, hash_p, sizeof(hash_p));
	req.connect_options    = 0x81;   // sample bits
	req.has_file_hash      = false;
	req.has_ext_endpoint   = false;

	const std::uint32_t ip_r = 0x01020304u;    // R's external IP
	const std::uint16_t port_r = 12345;

	auto& coord = CNatTraversalCoordinator::Instance();
	coord.OnInboundRendezvous(req, ip_r, port_r);

	// Two packets emitted: forward to P, hole-punch back to R.
	ASSERT_EQUALS((std::size_t)2, g_sent.size());

	// Packet 0: forwarded RENDEZVOUS to P.
	ASSERT_EQUALS((int)NatTraversal::OP_RENDEZVOUS_OPCODE, (int)g_sent[0].opcode);
	ASSERT_EQUALS((unsigned long)ip_p,   (unsigned long)g_sent[0].dest_ip);
	ASSERT_EQUALS((int)port_p,           (int)g_sent[0].dest_port);

	// Decode the forwarded body and verify ext_endpoint is R's
	// address — the whole point of the buddy role is to tell the
	// uploader where the downloader is.
	NatTraversal::RendezvousRequest decoded;
	ASSERT_TRUE(NatTraversal::DecodeRendezvous(g_sent[0].body.data(),
	                                          g_sent[0].body.size(),
	                                          decoded));
	ASSERT_TRUE(decoded.has_ext_endpoint);
	ASSERT_EQUALS((unsigned long)ip_r,   (unsigned long)decoded.requester_ext_ip);
	ASSERT_EQUALS((int)port_r,           (int)decoded.requester_ext_port);
	// target_user_hash + connect_options preserved.
	ASSERT_TRUE(std::memcmp(decoded.target_user_hash, hash_p,
	                       NatTraversal::kUserHashSize) == 0);
	ASSERT_EQUALS((int)0x81, (int)decoded.connect_options);

	// Packet 1: HOLEPUNCH back to R, empty body.
	ASSERT_EQUALS((int)NatTraversal::OP_HOLEPUNCH_OPCODE, (int)g_sent[1].opcode);
	ASSERT_EQUALS((unsigned long)ip_r,   (unsigned long)g_sent[1].dest_ip);
	ASSERT_EQUALS((int)port_r,           (int)g_sent[1].dest_port);
	ASSERT_EQUALS((std::size_t)0,        g_sent[1].body.size());

	teardown_d2_mocks();
}


// If we don't know the target, we silently drop — no packets
// emitted. Requester will retry with another buddy or time out.
TEST(NatTraversalCoordinator, BuddyDropsRendezvousForUnknownTarget)
{
	install_d2_mocks();

	std::uint8_t hash_unknown[NatTraversal::kUserHashSize];
	fill_hash(hash_unknown, 0xFF);

	NatTraversal::RendezvousRequest req;
	std::memcpy(req.target_user_hash, hash_unknown, sizeof(hash_unknown));
	req.connect_options    = 0;
	req.has_file_hash      = false;
	req.has_ext_endpoint   = false;

	auto& coord = CNatTraversalCoordinator::Instance();
	coord.OnInboundRendezvous(req, 0x01020304u, 12345);

	ASSERT_EQUALS((std::size_t)0, g_sent.size());

	teardown_d2_mocks();
}


// === Phase D3 — LowID requester role tests ======================

namespace {

// File-scope CreateUtpLayer mock + capture for D3 tests. Returns a
// non-null sentinel pointer; tests check the callback receives it
// to confirm the factory was invoked with the right args.
CUtpLayer* const kSentinelLayer = reinterpret_cast<CUtpLayer*>(0x1234);

struct CreateLayerCapture {
	int call_count = 0;
	std::vector<std::uint8_t> last_our_hash;
	std::vector<std::uint8_t> last_peer_hash;
	std::uint32_t             last_peer_ip   = 0;
	std::uint16_t             last_peer_port = 0;
	bool                      last_initiator = false;
};
CreateLayerCapture g_create_layer_capture;

CUtpLayer* mock_create_utp_layer(
	const std::uint8_t our_hash[NatTraversal::kUserHashSize],
	const std::uint8_t peer_hash[NatTraversal::kUserHashSize],
	const struct sockaddr* peer_addr,
	socklen_t /*addr_len*/,
	bool initiator)
{
	g_create_layer_capture.call_count++;
	g_create_layer_capture.last_our_hash.assign(
		our_hash, our_hash + NatTraversal::kUserHashSize);
	g_create_layer_capture.last_peer_hash.assign(
		peer_hash, peer_hash + NatTraversal::kUserHashSize);
	if (peer_addr != nullptr) {
		const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(peer_addr);
		g_create_layer_capture.last_peer_ip   = ntohl(sin->sin_addr.s_addr);
		g_create_layer_capture.last_peer_port = ntohs(sin->sin_port);
	}
	g_create_layer_capture.last_initiator = initiator;
	return kSentinelLayer;
}

void install_d3_full_mocks()
{
	// D3 needs everything D1 has plus the CreateUtpLayer factory
	// and a sendto delegate that captures into g_sent (for verifying
	// the outbound OP_RENDEZVOUS).
	install_d1_baseline();
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.SetSendEmuleProtDelegate(&mock_send_emule_prot);
	coord.SetCreateUtpLayerDelegate(&mock_create_utp_layer);
	g_sent.clear();
	g_create_layer_capture = CreateLayerCapture();
}

} // anonymous namespace


// Headline D3 test: RequestRendezvous emits OP_RENDEZVOUS to the
// configured buddy. The callback does NOT fire yet — that happens
// when OnInboundHolePunch arrives from the buddy.
TEST(NatTraversalCoordinator, RequestRendezvousEmitsOpRendezvousToBuddy)
{
	install_d3_full_mocks();

	std::uint8_t target_hash[NatTraversal::kUserHashSize];
	fill_hash(target_hash, 0xA0);
	sockaddr_in target_addr = MakeAddr(0x05060708u, 4662);

	std::atomic<int> fires(0);
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.RequestRendezvous(target_hash,
	                        reinterpret_cast<sockaddr*>(&target_addr),
	                        sizeof(target_addr),
	                        [&](bool, CUtpLayer*) { fires.fetch_add(1); });

	// One OP_RENDEZVOUS emitted to the buddy.
	ASSERT_EQUALS((std::size_t)1, g_sent.size());
	ASSERT_EQUALS((int)NatTraversal::OP_RENDEZVOUS_OPCODE,
	              (int)g_sent[0].opcode);
	ASSERT_EQUALS((unsigned long)g_mock_buddy_ip,
	              (unsigned long)g_sent[0].dest_ip);
	ASSERT_EQUALS((int)g_mock_buddy_port, (int)g_sent[0].dest_port);

	// Body decodes correctly: target_user_hash matches, no
	// ext_endpoint (the buddy adds that on forward).
	NatTraversal::RendezvousRequest decoded;
	ASSERT_TRUE(NatTraversal::DecodeRendezvous(g_sent[0].body.data(),
	                                          g_sent[0].body.size(),
	                                          decoded));
	ASSERT_TRUE(std::memcmp(decoded.target_user_hash, target_hash,
	                       NatTraversal::kUserHashSize) == 0);
	ASSERT_FALSE(decoded.has_ext_endpoint);

	// Pending entry recorded; callback NOT fired yet.
	ASSERT_EQUALS((std::size_t)1, coord.PendingCount());
	ASSERT_EQUALS(0, fires.load());

	teardown_baseline();
}


// OnInboundHolePunch with source matching a pending entry's buddy
// → factory called with the right args, callback fires with success
// + the sentinel layer pointer.
TEST(NatTraversalCoordinator, HolePunchFromMatchingBuddyCompletesRendezvous)
{
	install_d3_full_mocks();

	std::uint8_t target_hash[NatTraversal::kUserHashSize];
	fill_hash(target_hash, 0xA0);
	const std::uint32_t target_ip = 0x05060708u;
	const std::uint16_t target_port = 4662;
	sockaddr_in target_addr = MakeAddr(target_ip, target_port);

	std::atomic<int> fires(0);
	std::atomic<bool> got_ok(false);
	std::atomic<bool> got_sentinel(false);

	auto& coord = CNatTraversalCoordinator::Instance();
	coord.RequestRendezvous(target_hash,
	                        reinterpret_cast<sockaddr*>(&target_addr),
	                        sizeof(target_addr),
	                        [&](bool ok, CUtpLayer* layer) {
		fires.fetch_add(1);
		got_ok.store(ok);
		got_sentinel.store(layer == kSentinelLayer);
	});

	// Simulate HOLEPUNCH from the buddy.
	coord.OnInboundHolePunch(g_mock_buddy_ip, g_mock_buddy_port);

	ASSERT_EQUALS(1, fires.load());
	ASSERT_TRUE(got_ok.load());
	ASSERT_TRUE(got_sentinel.load());

	// Factory called with our_hash, target's peer_hash, and
	// target_addr — matches what RequestRendezvous recorded.
	ASSERT_EQUALS(1, g_create_layer_capture.call_count);
	ASSERT_EQUALS((unsigned long)target_ip,
	              (unsigned long)g_create_layer_capture.last_peer_ip);
	ASSERT_EQUALS((int)target_port,
	              (int)g_create_layer_capture.last_peer_port);
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)target_hash[i],
		              (int)g_create_layer_capture.last_peer_hash[i]);
	}

	// Pending entry consumed.
	ASSERT_EQUALS((std::size_t)0, coord.PendingCount());

	teardown_baseline();
}


// OnInboundHolePunch from a non-matching source (not any pending
// entry's buddy) is silently dropped — no factory call, no
// callback fire, pending table unchanged.
TEST(NatTraversalCoordinator, HolePunchFromUnknownSourceIsIgnored)
{
	install_d3_full_mocks();

	std::uint8_t target_hash[NatTraversal::kUserHashSize];
	fill_hash(target_hash, 0xA0);
	sockaddr_in target_addr = MakeAddr(0x05060708u, 4662);

	std::atomic<int> fires(0);
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.RequestRendezvous(target_hash,
	                        reinterpret_cast<sockaddr*>(&target_addr),
	                        sizeof(target_addr),
	                        [&](bool, CUtpLayer*) { fires.fetch_add(1); });

	ASSERT_EQUALS((std::size_t)1, coord.PendingCount());

	// HOLEPUNCH from a wrong source — ignored.
	coord.OnInboundHolePunch(0xFFFFFFFFu, 9999);

	ASSERT_EQUALS(0, fires.load());
	ASSERT_EQUALS(0, g_create_layer_capture.call_count);
	ASSERT_EQUALS((std::size_t)1, coord.PendingCount());

	teardown_baseline();
}


// RequestRendezvous fails synchronously when find_buddy reports no
// buddy available (and the pending entry is NOT created).
TEST(NatTraversalCoordinator, RequestFailsWhenNoBuddyAvailable)
{
	install_d3_full_mocks();
	// Override the baseline buddy: no buddy available.
	g_mock_buddy_available = false;

	std::uint8_t target_hash[NatTraversal::kUserHashSize];
	fill_hash(target_hash, 0xA0);
	sockaddr_in target_addr = MakeAddr(0x05060708u, 4662);

	std::atomic<int> fires(0);
	std::atomic<bool> ok(true);
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.RequestRendezvous(target_hash,
	                        reinterpret_cast<sockaddr*>(&target_addr),
	                        sizeof(target_addr),
	                        [&](bool ok_arg, CUtpLayer*) {
		fires.fetch_add(1);
		ok.store(ok_arg);
	});

	// Callback fired with failure; no pending entry; no packet.
	ASSERT_EQUALS(1, fires.load());
	ASSERT_FALSE(ok.load());
	ASSERT_EQUALS((std::size_t)0, coord.PendingCount());
	ASSERT_EQUALS((std::size_t)0, g_sent.size());

	teardown_baseline();
}


// === Phase D4 — LowID endpoint role tests =======================

namespace {

// Lookup-by-endpoint mock: (ip, port) → user_hash. install_d4_mocks
// pre-populates a single known endpoint.
std::map<std::pair<std::uint32_t, std::uint16_t>,
         std::array<std::uint8_t, NatTraversal::kUserHashSize>> g_known_endpoints;

bool mock_lookup_by_endpoint(std::uint32_t ip, std::uint16_t port,
                             std::uint8_t out_user_hash[NatTraversal::kUserHashSize])
{
	auto it = g_known_endpoints.find(std::make_pair(ip, port));
	if (it == g_known_endpoints.end()) {
		return false;
	}
	std::memcpy(out_user_hash, it->second.data(), NatTraversal::kUserHashSize);
	return true;
}

void install_d4_mocks()
{
	// D4 needs our_hash + lookup-by-endpoint + create_utp_layer.
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.ClearPendingForTesting();

	std::uint8_t our_hash[NatTraversal::kUserHashSize];
	fill_hash(our_hash, 0x77);
	coord.SetOurUserHash(our_hash);

	coord.SetLookupClientByEndpointDelegate(&mock_lookup_by_endpoint);
	coord.SetCreateUtpLayerDelegate(&mock_create_utp_layer);
	g_known_endpoints.clear();
	g_create_layer_capture = CreateLayerCapture();
}

void teardown_d4_mocks()
{
	teardown_baseline();
	g_known_endpoints.clear();
}

} // anonymous namespace


// Headline D4 test: buddy-forwarded RENDEZVOUS (has_ext_endpoint =
// true) → endpoint looks up requester by ext_endpoint, creates a
// passive CUtpLayer (initiator=false) keyed to requester's hash and
// requester's ext_endpoint.
TEST(NatTraversalCoordinator, EndpointReceivesForwardedRendezvousCreatesPassiveLayer)
{
	install_d4_mocks();

	// Register R (the requester) in the known-endpoints table.
	const std::uint32_t ip_r = 0x05060708u;
	const std::uint16_t port_r = 23456;
	std::array<std::uint8_t, NatTraversal::kUserHashSize> hash_r{};
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		hash_r[i] = static_cast<std::uint8_t>(0x44 + i);
	}
	g_known_endpoints[std::make_pair(ip_r, port_r)] = hash_r;

	// Buddy-forwarded RENDEZVOUS: target_user_hash = ours,
	// has_ext_endpoint = true, ext_endpoint = R's external address.
	std::uint8_t our_hash[NatTraversal::kUserHashSize];
	fill_hash(our_hash, 0x77);   // matches install_d4_mocks
	NatTraversal::RendezvousRequest req;
	std::memcpy(req.target_user_hash, our_hash, sizeof(our_hash));
	req.connect_options    = 0;
	req.has_file_hash      = false;
	req.has_ext_endpoint   = true;
	req.requester_ext_ip   = ip_r;
	req.requester_ext_port = port_r;

	// Source of this packet is the buddy's IP (irrelevant for the
	// endpoint path — we route by ext_endpoint, not packet source).
	const std::uint32_t buddy_ip   = 0xDEADBEEFu;
	const std::uint16_t buddy_port = 4242;

	auto& coord = CNatTraversalCoordinator::Instance();
	coord.OnInboundRendezvous(req, buddy_ip, buddy_port);

	// Layer factory called once with the right args.
	ASSERT_EQUALS(1, g_create_layer_capture.call_count);

	// our_hash matches the configured our_user_hash.
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)our_hash[i],
		              (int)g_create_layer_capture.last_our_hash[i]);
	}
	// peer_hash is R's hash (from the endpoint lookup).
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)hash_r[i],
		              (int)g_create_layer_capture.last_peer_hash[i]);
	}
	// peer_addr is R's ext_endpoint.
	ASSERT_EQUALS((unsigned long)ip_r,
	              (unsigned long)g_create_layer_capture.last_peer_ip);
	ASSERT_EQUALS((int)port_r,
	              (int)g_create_layer_capture.last_peer_port);
	// Initiator flag = false (responder).
	ASSERT_FALSE(g_create_layer_capture.last_initiator);

	teardown_d4_mocks();
}


// If the endpoint doesn't recognise the requester (no entry in the
// lookup table), the layer is NOT created — the rendezvous fails
// silently and the requester's incoming uTP will be rejected at
// libutp's on_accept stage.
TEST(NatTraversalCoordinator, EndpointDropsRendezvousFromUnknownRequester)
{
	install_d4_mocks();
	// Deliberately empty g_known_endpoints — lookup will fail.

	std::uint8_t our_hash[NatTraversal::kUserHashSize];
	fill_hash(our_hash, 0x77);
	NatTraversal::RendezvousRequest req;
	std::memcpy(req.target_user_hash, our_hash, sizeof(our_hash));
	req.connect_options    = 0;
	req.has_file_hash      = false;
	req.has_ext_endpoint   = true;
	req.requester_ext_ip   = 0xFFFFFFFFu;
	req.requester_ext_port = 9999;

	auto& coord = CNatTraversalCoordinator::Instance();
	coord.OnInboundRendezvous(req, 0xDEADBEEFu, 4242);

	ASSERT_EQUALS(0, g_create_layer_capture.call_count);

	teardown_d4_mocks();
}


// Without delegates installed, the buddy path is a safe no-op —
// matches the "production thunks installed at startup, tests don't
// crash if they skip" pattern.
TEST(NatTraversalCoordinator, BuddyDropsWithoutDelegates)
{
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.ClearPendingForTesting();
	coord.SetLookupClientByHashDelegate(nullptr);
	coord.SetSendEmuleProtDelegate(nullptr);

	g_sent.clear();

	std::uint8_t hash[NatTraversal::kUserHashSize];
	fill_hash(hash, 0xAA);

	NatTraversal::RendezvousRequest req;
	std::memcpy(req.target_user_hash, hash, sizeof(hash));
	req.connect_options    = 0;
	req.has_file_hash      = false;
	req.has_ext_endpoint   = false;

	coord.OnInboundRendezvous(req, 0x01020304u, 12345);
	ASSERT_EQUALS((std::size_t)0, g_sent.size());
}


// RequestRendezvous with NULL callback rejects silently — no crash,
// no entry added.
TEST(NatTraversalCoordinator, RequestRendezvousWithNullCallbackRejected)
{
	install_d1_baseline();
	auto& coord = CNatTraversalCoordinator::Instance();

	std::uint8_t hash[NatTraversal::kUserHashSize];
	fill_hash(hash, 0x10);
	sockaddr_in addr = MakeAddr(0x01020304u, 4662);

	// Null callback — no entry added.
	coord.RequestRendezvous(hash, reinterpret_cast<sockaddr*>(&addr),
	                        sizeof(addr),
	                        CNatTraversalCoordinator::RendezvousCompleteFn());
	ASSERT_EQUALS((std::size_t)0, coord.PendingCount());

	// Null target_user_hash — callback fires with failure if present.
	std::atomic<int> fires(0);
	coord.RequestRendezvous(nullptr, reinterpret_cast<sockaddr*>(&addr),
	                        sizeof(addr),
	                        [&](bool, CUtpLayer*) { fires.fetch_add(1); });
	ASSERT_EQUALS(1, fires.load());
	ASSERT_EQUALS((std::size_t)0, coord.PendingCount());

	// Null addr — same.
	coord.RequestRendezvous(hash, nullptr, sizeof(addr),
	                        [&](bool, CUtpLayer*) { fires.fetch_add(1); });
	ASSERT_EQUALS(2, fires.load());
	ASSERT_EQUALS((std::size_t)0, coord.PendingCount());

	coord.ClearPendingForTesting();
}

#else

using namespace muleunit;
DECLARE(NatTraversalCoordinator)
END_DECLARE;

TEST(NatTraversalCoordinator, FeatureDisabled)
{
	ASSERT_TRUE(true);
}

#endif // ENABLE_NAT_T
