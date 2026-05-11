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

} // anonymous namespace


// RequestRendezvous records an entry in the pending table; the
// callback does NOT fire immediately (it fires only on success
// — D3 — or timeout).
TEST(NatTraversalCoordinator, RequestRendezvousAddsToPending)
{
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.ClearPendingForTesting();
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

	coord.ClearPendingForTesting();
}


// A second RequestRendezvous for the same target cancels the
// previous one — the previous callback fires with (false, nullptr).
TEST(NatTraversalCoordinator, SecondRequestCancelsPreviousCallback)
{
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.ClearPendingForTesting();

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
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.ClearPendingForTesting();

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
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.ClearPendingForTesting();

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
	auto& coord = CNatTraversalCoordinator::Instance();
	coord.ClearPendingForTesting();

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
