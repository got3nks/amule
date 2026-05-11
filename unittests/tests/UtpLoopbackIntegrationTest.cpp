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

// Phase B8 of the NAT-T port — end-of-Phase-B integration test.
// Plan spec: "two CUtpLayer instances over local UDP socket pair,
// encrypted Key Frame exchange + uTP handshake + data round-trip +
// clean close."
//
// Implementation chooses an in-process router instead of real UDP
// sockets: the test installs a sendto delegate that captures
// outbound packets keyed by destination address, and a router
// function that replays each captured packet into the OTHER side's
// "ClientUDPSocket inbound dispatch" — which we replicate here to
// match the production logic in src/ClientUDPSocket.cpp's
// OP_UDPRESERVEDPROT2 case. The full sequence exercised:
//
//   1. Both sides Connect() — both send Key Frames.
//   2. Router delivers each Key Frame to the OTHER side's inbound
//      dispatch → UnwrapKeyFrame → FindByPeerHash → OnPeerKeyFrame.
//   3. Initiator's OnPeerKeyFrame fires utp_connect → libutp emits
//      SYN through on_sendto → layer wraps via OnSendto → router
//      delivers wrapped SYN to responder.
//   4. Responder's inbound dispatch UnwrapUtpFrame → utp_process_udp
//      → libutp fires UTP_ON_ACCEPT → on_accept finds the
//      responder's layer via FindByPeerAddr → layer.OnUtpAccept
//      binds the new socket.
//   5. libutp on responder emits SYN-ACK (wrapped + routed to
//      initiator).
//   6. libutp on initiator fires UTP_STATE_CONNECT → both layers
//      reach CONNECTED state.
//   7. Initiator.Send(64 KiB payload). Drained through utp_write,
//      data packets routed to responder.
//   8. Responder.Recv() drains its read buffer. Asserts bytewise
//      identity with the sent payload.
//   9. Both sides Close(). State → CLOSED.
//
// The router runs the sequence on a single thread, repeatedly
// pumping the routing queue and calling utp_check_timeouts to give
// libutp opportunities to drive its state machine.
//
// Encryption uses identity-style mocks (same as
// UtpEncryptionTest::WrapBuildsCorrectEnvelopeWithIdentity): the
// real RC4 path is verified in B5's roundtrip test and would be
// re-verified end-to-end in Phase F's real-NAT integration test.

#include <muleunit/test.h>

#include "UtpLayer.h"
#include "UtpCallbacks.h"
#include "UtpEncryption.h"
#include "UtpEnvironment.h"
#include "UtpKeyFrame.h"
#include "UtpLayerRegistry.h"

#ifdef ENABLE_NAT_T

#include <utp.h>

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <queue>
#include <sys/socket.h>
#include <thread>
#include <vector>

using namespace muleunit;

DECLARE(UtpLoopbackIntegration)
END_DECLARE;


namespace {

// Two well-known loopback ports for the two test sides.
constexpr std::uint32_t kIpA   = 0x7F000001u;  // 127.0.0.1
constexpr std::uint16_t kPortA = 4661;
constexpr std::uint32_t kIpB   = 0x7F000001u;
constexpr std::uint16_t kPortB = 4662;

sockaddr_in MakeAddr(std::uint32_t ip, std::uint16_t port)
{
	sockaddr_in s;
	std::memset(&s, 0, sizeof(s));
	s.sin_family      = AF_INET;
	s.sin_port        = htons(port);
	s.sin_addr.s_addr = htonl(ip);
	return s;
}

bool AddrEquals(const sockaddr_in& a, const sockaddr_in& b)
{
	return a.sin_family == b.sin_family &&
	       a.sin_port == b.sin_port &&
	       a.sin_addr.s_addr == b.sin_addr.s_addr;
}

// A packet captured by the sendto delegate. Stored verbatim with its
// destination address so the router can match it to a recipient.
struct CapturedPacket {
	std::vector<std::uint8_t> bytes;
	sockaddr_in               dest;
};

// File-scope router state. The sendto delegate appends to the queue;
// the test's main loop drains it by routing each packet to the side
// matching its destination address.
std::queue<CapturedPacket> g_route_queue;

// The two test sides — A initiates, B responds. The router checks
// each packet's destination against side_a.our_addr and
// side_b.our_addr to decide where to deliver.
struct TestSide {
	sockaddr_in our_addr;
};
TestSide g_side_a;
TestSide g_side_b;

// Identity encrypt/decrypt — no transformation. The envelope-and-routing
// logic is what B8 verifies; encryption is independently tested in B5.
bool identity_encrypt(const std::uint8_t* plaintext, std::size_t plaintext_len,
                      const std::uint8_t /*key*/[UtpEncryption::kUserHashSize],
                      std::vector<std::uint8_t>& out)
{
	out.assign(plaintext, plaintext + plaintext_len);
	return true;
}

bool identity_decrypt(const std::uint8_t* ciphertext, std::size_t ciphertext_len,
                      std::uint32_t /*source_ip*/,
                      std::vector<std::uint8_t>& out)
{
	out.assign(ciphertext, ciphertext + ciphertext_len);
	return true;
}

// Sendto delegate: capture every outbound packet into the route
// queue. The router drains it later.
void router_sendto(void* /*userdata*/, const std::uint8_t* buf, std::size_t len,
                   const struct sockaddr* addr, socklen_t addr_len)
{
	if (buf == NULL || addr == NULL || addr_len < sizeof(sockaddr_in)) {
		return;
	}
	CapturedPacket pkt;
	pkt.bytes.assign(buf, buf + len);
	std::memcpy(&pkt.dest, addr, sizeof(pkt.dest));
	g_route_queue.push(pkt);
}

// Simulates CClientUDPSocket::OnPacketReceived's
// OP_UDPRESERVEDPROT2 case for a single side. The caller has
// already determined which side the packet is destined for; this
// function performs the dispatch (UnwrapKeyFrame for sub-byte 0xFF,
// UnwrapUtpFrame + ProcessInboundUtpPacket for sub-byte 0x00).
void simulate_inbound_dispatch(std::uint32_t src_ip, std::uint16_t src_port,
                               const std::uint8_t* buf, std::size_t len)
{
	if (len < 2 || buf[0] != UtpKeyFrame::kOpByte) {
		return;
	}

	std::uint8_t sub = buf[1];
	if (sub == UtpKeyFrame::kSubByte) {
		std::uint8_t sender_hash[UtpKeyFrame::kUserHashSize];
		if (!UtpEncryption::UnwrapKeyFrame(buf, len, src_ip, sender_hash)) {
			return;
		}
		CUtpLayer* layer = UtpLayerRegistry::FindByPeerHash(sender_hash);
		if (layer != NULL) {
			layer->OnPeerKeyFrame(sender_hash);
		}
	} else if (sub == UtpKeyFrame::kUtpFrameSubByte) {
		std::vector<std::uint8_t> plaintext;
		if (!UtpEncryption::UnwrapUtpFrame(buf, len, src_ip, plaintext)) {
			return;
		}
		sockaddr_in src = MakeAddr(src_ip, src_port);
		UtpEnvironment::ProcessInboundUtpPacket(
			plaintext.data(), plaintext.size(),
			reinterpret_cast<sockaddr*>(&src), sizeof(src));
	}
}

// Drain one packet from the route queue, dispatch to whichever side
// owns its destination address. The src_ip/port passed to the
// inbound dispatch is whatever destination address this packet
// IS NOT — that's the sender. Returns true if a packet was drained.
bool route_one_packet()
{
	if (g_route_queue.empty()) {
		return false;
	}
	CapturedPacket pkt = g_route_queue.front();
	g_route_queue.pop();

	// Determine sender (the side whose our_addr does NOT match the
	// destination). Used as src_ip/src_port for the inbound dispatch.
	std::uint32_t src_ip = 0;
	std::uint16_t src_port = 0;
	if (AddrEquals(pkt.dest, g_side_a.our_addr)) {
		// Destined for A; sender is B.
		src_ip   = ntohl(g_side_b.our_addr.sin_addr.s_addr);
		src_port = ntohs(g_side_b.our_addr.sin_port);
	} else if (AddrEquals(pkt.dest, g_side_b.our_addr)) {
		src_ip   = ntohl(g_side_a.our_addr.sin_addr.s_addr);
		src_port = ntohs(g_side_a.our_addr.sin_port);
	} else {
		// Unknown destination — drop.
		return true;
	}

	simulate_inbound_dispatch(src_ip, src_port,
	                          pkt.bytes.data(), pkt.bytes.size());
	return true;
}

// Pump the router queue + drive libutp's timeouts until either the
// predicate returns true or `iterations` exhausts. Each iteration:
//   1. Drain all queued packets (they may produce more during
//      dispatch).
//   2. Call utp_check_timeouts to give libutp a chance to advance
//      its state machine (retransmits, SYN-ACK emission, etc).
//   3. Sleep briefly to let any pending state changes settle.
//   4. Check the predicate.
template <typename Predicate>
bool pump_until(Predicate pred, int iterations = 200)
{
	for (int i = 0; i < iterations; ++i) {
		// Drain all currently-queued packets. New packets may be
		// queued during dispatch (each side responds to inbound).
		while (route_one_packet()) {
			// keep going
		}
		// Tick libutp.
		{
			std::lock_guard<std::mutex> lock(UtpEnvironment::RuntimeLock());
			utp_context* ctx = UtpEnvironment::GetContext();
			if (ctx != NULL) {
				utp_check_timeouts(ctx);
				utp_issue_deferred_acks(ctx);
			}
		}
		// One more drain after the tick — libutp may have queued
		// retransmits or fresh outbound packets.
		while (route_one_packet()) {
			// keep going
		}
		if (pred()) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	return false;
}

void reset_global_state()
{
	while (!g_route_queue.empty()) g_route_queue.pop();
	UtpCallbacks::SetSendtoDelegate(NULL, NULL);
	UtpEncryption::SetEncryptDelegate(NULL);
	UtpEncryption::SetDecryptDelegate(NULL);
	UtpLayerRegistry::ClearForTesting();
}

void fill_hash(std::uint8_t hash[CUtpLayer::kUserHashSize], std::uint8_t base)
{
	for (std::size_t i = 0; i < CUtpLayer::kUserHashSize; ++i) {
		hash[i] = static_cast<std::uint8_t>(base + i);
	}
}

} // anonymous namespace


// Full bidirectional handshake — Key Frames + uTP SYN/SYN-ACK —
// reaches CONNECTED state on both sides. This is the integration
// gate the plan calls out, minus the data-round-trip part which is
// covered by the next test (split to make failure mode clearer).
TEST(UtpLoopbackIntegration, BidirectionalHandshakeReachesConnected)
{
	reset_global_state();
	UtpCallbacks::SetSendtoDelegate(&router_sendto, NULL);
	UtpEncryption::SetEncryptDelegate(&identity_encrypt);
	UtpEncryption::SetDecryptDelegate(&identity_decrypt);

	ASSERT_TRUE(UtpEnvironment::Init() != NULL);

	g_side_a.our_addr = MakeAddr(kIpA, kPortA);
	g_side_b.our_addr = MakeAddr(kIpB, kPortB);

	// Hashes: A and B have distinct identities. Each layer's peer
	// hash is the OTHER side's identity hash.
	std::uint8_t hash_a[CUtpLayer::kUserHashSize];
	std::uint8_t hash_b[CUtpLayer::kUserHashSize];
	fill_hash(hash_a, 0xA0);
	fill_hash(hash_b, 0xB0);

	CUtpLayer layer_a(UtpEnvironment::GetContext());
	CUtpLayer layer_b(UtpEnvironment::GetContext());

	// A initiates; B responds. Both send Key Frames immediately.
	sockaddr_in addr_b = g_side_b.our_addr;
	sockaddr_in addr_a = g_side_a.our_addr;
	ASSERT_TRUE(layer_a.Connect(hash_a, hash_b,
	                            reinterpret_cast<sockaddr*>(&addr_b),
	                            sizeof(addr_b),
	                            /*initiator=*/true));
	ASSERT_TRUE(layer_b.Connect(hash_b, hash_a,
	                            reinterpret_cast<sockaddr*>(&addr_a),
	                            sizeof(addr_a),
	                            /*initiator=*/false));

	// Pump until both sides are CONNECTED.
	bool reached = pump_until([&]() {
		return layer_a.GetState() == CUtpLayer::State::CONNECTED &&
		       layer_b.GetState() == CUtpLayer::State::CONNECTED;
	});

	ASSERT_TRUE(reached);
	ASSERT_TRUE(layer_a.IsConnected());
	ASSERT_TRUE(layer_b.IsConnected());

	// Clean teardown.
	layer_a.Close();
	layer_b.Close();
	ASSERT_TRUE(layer_a.IsClosed());
	ASSERT_TRUE(layer_b.IsClosed());

	UtpEnvironment::Shutdown();
	reset_global_state();
}


// 64 KiB payload sent A→B in chunks (the write buffer holds 16 KiB
// at a time; the test loops Send() + pump until all bytes are
// delivered, then drains B's read buffer and verifies bytewise
// identity). This is the plan-spec "data round-trip" check.
TEST(UtpLoopbackIntegration, BulkPayloadRoundTrip64KiB)
{
	reset_global_state();
	UtpCallbacks::SetSendtoDelegate(&router_sendto, NULL);
	UtpEncryption::SetEncryptDelegate(&identity_encrypt);
	UtpEncryption::SetDecryptDelegate(&identity_decrypt);

	ASSERT_TRUE(UtpEnvironment::Init() != NULL);

	g_side_a.our_addr = MakeAddr(kIpA, kPortA);
	g_side_b.our_addr = MakeAddr(kIpB, kPortB);

	std::uint8_t hash_a[CUtpLayer::kUserHashSize];
	std::uint8_t hash_b[CUtpLayer::kUserHashSize];
	fill_hash(hash_a, 0xA0);
	fill_hash(hash_b, 0xB0);

	CUtpLayer layer_a(UtpEnvironment::GetContext());
	CUtpLayer layer_b(UtpEnvironment::GetContext());

	sockaddr_in addr_b = g_side_b.our_addr;
	sockaddr_in addr_a = g_side_a.our_addr;
	ASSERT_TRUE(layer_a.Connect(hash_a, hash_b,
	                            reinterpret_cast<sockaddr*>(&addr_b),
	                            sizeof(addr_b),
	                            /*initiator=*/true));
	ASSERT_TRUE(layer_b.Connect(hash_b, hash_a,
	                            reinterpret_cast<sockaddr*>(&addr_a),
	                            sizeof(addr_a),
	                            /*initiator=*/false));

	bool connected = pump_until([&]() {
		return layer_a.GetState() == CUtpLayer::State::CONNECTED &&
		       layer_b.GetState() == CUtpLayer::State::CONNECTED;
	});
	ASSERT_TRUE(connected);

	// Synthesize a 64 KiB payload with a deterministic pattern —
	// each byte is a function of its offset, so a single mismatch
	// in the recovered stream points straight at the offset.
	const std::size_t kPayloadSize = 64 * 1024;
	std::vector<std::uint8_t> payload(kPayloadSize);
	for (std::size_t i = 0; i < kPayloadSize; ++i) {
		payload[i] = static_cast<std::uint8_t>((i * 31 + 7) & 0xFF);
	}

	// Send loop: each Send accepts up to 16 KiB (write-buffer cap).
	// Pump after each chunk so libutp drains the buffer to B.
	std::size_t sent = 0;
	while (sent < kPayloadSize) {
		std::int64_t accepted = layer_a.Send(payload.data() + sent,
		                                     kPayloadSize - sent);
		if (accepted > 0) {
			sent += static_cast<std::size_t>(accepted);
		}
		// Give libutp + the router cycles to drain the write buffer
		// and deliver to B.
		pump_until([&]() {
			return layer_a.WriteBufferSize() == 0;
		}, /*iterations=*/50);
	}
	ASSERT_EQUALS(kPayloadSize, sent);

	// Drain on the receiver side until we've collected the full
	// payload. Continue pumping in case there are in-flight packets.
	std::vector<std::uint8_t> received;
	received.reserve(kPayloadSize);
	pump_until([&]() {
		std::uint8_t buf[8192];
		std::int64_t n;
		while ((n = layer_b.Recv(buf, sizeof(buf))) > 0) {
			received.insert(received.end(), buf, buf + n);
		}
		return received.size() >= kPayloadSize;
	}, /*iterations=*/500);

	ASSERT_EQUALS(kPayloadSize, received.size());
	// Bytewise identity — the plan's hard requirement.
	bool match = (std::memcmp(payload.data(), received.data(),
	                         kPayloadSize) == 0);
	ASSERT_TRUE(match);

	layer_a.Close();
	layer_b.Close();
	UtpEnvironment::Shutdown();
	reset_global_state();
}

#else

using namespace muleunit;
DECLARE(UtpLoopbackIntegration)
END_DECLARE;

TEST(UtpLoopbackIntegration, FeatureDisabled)
{
	ASSERT_TRUE(true);
}

#endif // ENABLE_NAT_T
