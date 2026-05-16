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

// Tests for Phase B6 of the NAT-T port — the CUtpLayer connect-flow
// state machine.
//
// Plan spec: "state-machine test with mocked time + mocked send.
// Assert correct opcodes fire in correct order (Key Frame outbound
// first, then utp SYN); timeout fires if peer Key Frame never
// arrives; state transitions match spec."
//
// All four conditions covered, plus negative-path tests for missing
// delegates and hash mismatches.

#include <muleunit/test.h>

#include "UtpLayer.h"
#include "UtpCallbacks.h"
#include "UtpEncryption.h"
#include "UtpLayerRegistry.h"

#ifdef ENABLE_NAT_T

#include <utp.h>

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <vector>

using namespace muleunit;

DECLARE(UtpConnectFlow)
END_DECLARE;


namespace {

// Captured outbound UDP packets — the sendto delegate appends one
// CapturedPacket per call; tests inspect the vector to assert that
// the Key Frame went out first, the uTP SYN second, etc.
struct CapturedPacket {
	std::vector<std::uint8_t> payload;
	struct sockaddr_in        to;
};

struct SendCapture {
	std::vector<CapturedPacket> packets;
};

SendCapture g_capture;

void capture_sendto(void* userdata,
                    const std::uint8_t* buf, std::size_t len,
                    const struct sockaddr* addr, socklen_t addr_len)
{
	SendCapture* cap = static_cast<SendCapture*>(userdata);
	if (cap == NULL || buf == NULL || addr == NULL ||
	    addr_len < sizeof(struct sockaddr_in)) {
		return;
	}
	CapturedPacket pkt;
	pkt.payload.assign(buf, buf + len);
	std::memcpy(&pkt.to, addr, sizeof(pkt.to));
	cap->packets.push_back(pkt);
}

// Identity encrypt/decrypt mocks — preserve the plaintext so we can
// observe the wire bytes directly. Same approach as UtpEncryptionTest.
bool identity_encrypt(const std::uint8_t* plaintext, std::size_t plaintext_len,
                      const std::uint8_t /*key*/[UtpEncryption::kUserHashSize],
                      std::vector<std::uint8_t>& out)
{
	out.assign(plaintext, plaintext + plaintext_len);
	return true;
}

bool identity_decrypt(const std::uint8_t* ciphertext, std::size_t ciphertext_len,
                      std::uint32_t /*ip*/,
                      std::vector<std::uint8_t>& out)
{
	out.assign(ciphertext, ciphertext + ciphertext_len);
	return true;
}

void reset_global_state()
{
	g_capture.packets.clear();
	UtpCallbacks::SetSendtoDelegate(NULL, NULL);
	UtpEncryption::SetEncryptDelegate(NULL);
	UtpEncryption::SetDecryptDelegate(NULL);
	UtpLayerRegistry::ClearForTesting();
}

void install_test_delegates()
{
	UtpCallbacks::SetSendtoDelegate(&capture_sendto, &g_capture);
	UtpEncryption::SetEncryptDelegate(&identity_encrypt);
	UtpEncryption::SetDecryptDelegate(&identity_decrypt);
}

sockaddr_in make_peer_addr()
{
	sockaddr_in s;
	std::memset(&s, 0, sizeof(s));
	s.sin_family = AF_INET;
	s.sin_port = htons(4662);
	s.sin_addr.s_addr = htonl(0x7F000001u);
	return s;
}

void fill_hash(std::uint8_t hash[CUtpLayer::kUserHashSize], std::uint8_t base)
{
	for (std::size_t i = 0; i < CUtpLayer::kUserHashSize; ++i) {
		hash[i] = static_cast<std::uint8_t>(base + i);
	}
}

} // anonymous namespace


// The headline test: an initiator-side Connect must (a) emit a Key
// Frame envelope (0xB2, 0xFF, then the 16-byte identity-encrypt of
// sender_hash) as the first outbound packet, then (b) immediately
// fire utp_connect, which causes libutp to push a wrapped SYN out
// through on_sendto. Final state is UTP_CONNECTING.
//
// Initiator path is "Key Frame + SYN in one step" since commit
// cbb49144f — the layer no longer waits for the peer's Key Frame
// before firing utp_connect (the eMuleAI flow: HOLEPUNCH burst is
// what unblocks the peer's NAT, not an exchange of Key Frames).
TEST(UtpConnectFlow, ConnectSendsKeyFrameAndFiresUtpConnect)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::INIT);

		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,  0x10);
		fill_hash(peer_hash, 0xA0);
		sockaddr_in peer = make_peer_addr();

		ASSERT_TRUE(layer.Connect(our_hash, peer_hash,
		                          reinterpret_cast<sockaddr*>(&peer),
		                          sizeof(peer)));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::UTP_CONNECTING);

		// At least two packets: the Key Frame (first) and the SYN
		// (second). libutp may emit additional state-driven packets
		// from utp_connect, so the assertion is `>= 2`.
		ASSERT_TRUE(g_capture.packets.size() >= 2);

		const CapturedPacket& pkt = g_capture.packets[0];
		// 18 bytes: 0xB2 + 0xFF + 16-byte payload (identity-encrypt
		// of sender_hash).
		ASSERT_EQUALS((std::size_t)18, pkt.payload.size());
		ASSERT_EQUALS((int)0xB2, (int)pkt.payload[0]);
		ASSERT_EQUALS((int)0xFF, (int)pkt.payload[1]);
		for (std::size_t i = 0; i < CUtpLayer::kUserHashSize; ++i) {
			ASSERT_EQUALS((int)our_hash[i], (int)pkt.payload[2 + i]);
		}
		// Packet aimed at peer_addr.
		ASSERT_EQUALS(htons(4662), pkt.to.sin_port);
		ASSERT_EQUALS(htonl(0x7F000001u), pkt.to.sin_addr.s_addr);
	}

	utp_destroy(ctx);
	reset_global_state();
}


// libutp's outbound SYN (fired from Connect()'s embedded utp_connect)
// must flow through CUtpLayer::OnSendto which wraps it in the
// OP_UDPRESERVEDPROT2 sub-byte-0x00 envelope. The wrapped SYN is the
// second captured packet (the first is the Key Frame).
//
// With identity_encrypt installed, the captured packet is
// [0xB2, 0x00, raw_utp_syn...]. Byte 2 is the original libutp byte 0
// — a SYN packet with version 1 = 0x41.
//
// Also: OnPeerKeyFrame on the initiator side, called after Connect()
// has already advanced past KEY_FRAME_SENT, is a no-op (returns
// false) — the SYN has already gone out. This guards against double
// firing if the peer's Key Frame arrives late.
TEST(UtpConnectFlow, ConnectFiresWrappedUtpSyn)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,  0x10);
		fill_hash(peer_hash, 0xA0);
		sockaddr_in peer = make_peer_addr();

		ASSERT_TRUE(layer.Connect(our_hash, peer_hash,
		                          reinterpret_cast<sockaddr*>(&peer),
		                          sizeof(peer)));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::UTP_CONNECTING);

		// At least two packets: Key Frame at [0], wrapped SYN at [1].
		ASSERT_TRUE(g_capture.packets.size() >= 2);
		const CapturedPacket& wrapped_syn = g_capture.packets[1];
		// Preamble: [0xB2, 0x00].
		ASSERT_TRUE(wrapped_syn.payload.size() >= 3);
		ASSERT_EQUALS((int)0xB2, (int)wrapped_syn.payload[0]);
		ASSERT_EQUALS((int)0x00, (int)wrapped_syn.payload[1]);
		// Inside the envelope (identity_encrypt is a no-op transform):
		// byte 0 of the raw uTP packet is ST_SYN | version = 0x41.
		ASSERT_EQUALS((int)0x41, (int)wrapped_syn.payload[2]);

		// OnPeerKeyFrame is a no-op now — state is not KEY_FRAME_SENT.
		ASSERT_FALSE(layer.OnPeerKeyFrame(peer_hash));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::UTP_CONNECTING);
	}

	utp_destroy(ctx);
	reset_global_state();
}


// Phase B7.5 F1+F2: Connect must register the layer in the global
// registry; the layer's destructor must unregister it. Verifies the
// registry-driven inbound dispatch path can find the layer by
// peer_hash.
TEST(UtpConnectFlow, ConnectAndDestroyMaintainRegistry)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	std::uint8_t our_hash[CUtpLayer::kUserHashSize];
	std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
	fill_hash(our_hash,  0x10);
	fill_hash(peer_hash, 0xA0);
	sockaddr_in peer = make_peer_addr();

	ASSERT_EQUALS((std::size_t)0, UtpLayerRegistry::Size());

	{
		CUtpLayer layer(ctx);
		ASSERT_TRUE(layer.Connect(our_hash, peer_hash,
		                          reinterpret_cast<sockaddr*>(&peer),
		                          sizeof(peer)));

		// Registry now contains this layer indexed by peer_hash.
		ASSERT_EQUALS((std::size_t)1, UtpLayerRegistry::Size());
		ASSERT_TRUE(UtpLayerRegistry::FindByPeerHash(peer_hash) == &layer);
	}
	// Layer destroyed — registry entry must be gone.
	ASSERT_EQUALS((std::size_t)0, UtpLayerRegistry::Size());
	ASSERT_TRUE(UtpLayerRegistry::FindByPeerHash(peer_hash) == NULL);

	utp_destroy(ctx);
	reset_global_state();
}


// OnPeerKeyFrame must reject a Key Frame whose embedded sender_hash
// doesn't match the peer_hash we recorded on Connect. No state
// transition; no utp_connect; no second packet.
//
// Exercised on the *responder* side (initiator=false), because the
// initiator advances past KEY_FRAME_SENT inside Connect() and
// OnPeerKeyFrame would short-circuit on `m_state != KEY_FRAME_SENT`
// before reaching the hash-match check. The responder is the only
// side where the hash check is actually reachable.
TEST(UtpConnectFlow, OnPeerKeyFrameWithWrongHashIgnored)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		std::uint8_t wrong_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,    0x10);
		fill_hash(peer_hash,   0xA0);
		fill_hash(wrong_hash,  0xCC);  // different
		sockaddr_in peer = make_peer_addr();

		ASSERT_TRUE(layer.Connect(our_hash, peer_hash,
		                          reinterpret_cast<sockaddr*>(&peer),
		                          sizeof(peer),
		                          /*initiator=*/false));
		// Responder doesn't emit a Key Frame from Connect().
		ASSERT_EQUALS((std::size_t)0, g_capture.packets.size());
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);

		ASSERT_FALSE(layer.OnPeerKeyFrame(wrong_hash));
		// State unchanged — still waiting for the correct Key Frame.
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);
		// Still nothing on the wire.
		ASSERT_EQUALS((std::size_t)0, g_capture.packets.size());
	}

	utp_destroy(ctx);
	reset_global_state();
}


// CheckTimeout: short elapsed times leave the layer in
// KEY_FRAME_SENT; once elapsed_ms >= kKeyFrameTimeoutMs the
// transition fires.
//
// Uses initiator=false because timeout only matters in KEY_FRAME_SENT;
// the initiator advances past that state inside Connect() and is no
// longer in scope for this timeout. The "Key Frame didn't arrive in
// time" deadline belongs to the responder side waiting on the
// initiator's Key Frame, and (post-#cbb49144f) the initiator side
// waits on libutp's own utp_connect retransmit timer once it's
// already in UTP_CONNECTING.
TEST(UtpConnectFlow, CheckTimeoutTransitionsToFailedAfterDeadline)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,  0x10);
		fill_hash(peer_hash, 0xA0);
		sockaddr_in peer = make_peer_addr();

		ASSERT_TRUE(layer.Connect(our_hash, peer_hash,
		                          reinterpret_cast<sockaddr*>(&peer),
		                          sizeof(peer),
		                          /*initiator=*/false));

		// Well under the deadline — no transition.
		ASSERT_FALSE(layer.CheckTimeout(100));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);

		ASSERT_FALSE(layer.CheckTimeout(CUtpLayer::kKeyFrameTimeoutMs - 1));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);

		// Crossing the boundary triggers the transition.
		ASSERT_TRUE(layer.CheckTimeout(CUtpLayer::kKeyFrameTimeoutMs));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::FAILED);
		ASSERT_TRUE(layer.IsClosed());

		// Idempotent: subsequent CheckTimeout calls report no new
		// transitions.
		ASSERT_FALSE(layer.CheckTimeout(CUtpLayer::kKeyFrameTimeoutMs * 2));
	}

	utp_destroy(ctx);
	reset_global_state();
}


// Connect must refuse if WrapKeyFrame can't run (no encrypt delegate
// installed). Mandatory-encryption guarantee — see the comment on
// UtpEncryption::WrapKeyFrame.
TEST(UtpConnectFlow, ConnectFailsWithoutEncryptDelegate)
{
	reset_global_state();
	UtpCallbacks::SetSendtoDelegate(&capture_sendto, &g_capture);
	// Deliberately do NOT install encrypt delegate.

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,  0x10);
		fill_hash(peer_hash, 0xA0);
		sockaddr_in peer = make_peer_addr();

		ASSERT_FALSE(layer.Connect(our_hash, peer_hash,
		                           reinterpret_cast<sockaddr*>(&peer),
		                           sizeof(peer)));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::INIT);
		ASSERT_EQUALS((std::size_t)0, g_capture.packets.size());
	}

	utp_destroy(ctx);
	reset_global_state();
}


// Connect must refuse if SendRaw can't run (no sendto delegate).
// Failure must leave the layer in INIT so the caller can retry.
TEST(UtpConnectFlow, ConnectFailsWithoutSendtoDelegate)
{
	reset_global_state();
	UtpEncryption::SetEncryptDelegate(&identity_encrypt);
	// Deliberately do NOT install sendto delegate.

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,  0x10);
		fill_hash(peer_hash, 0xA0);
		sockaddr_in peer = make_peer_addr();

		ASSERT_FALSE(layer.Connect(our_hash, peer_hash,
		                           reinterpret_cast<sockaddr*>(&peer),
		                           sizeof(peer)));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::INIT);
	}

	utp_destroy(ctx);
	reset_global_state();
}


// State-machine progression sanity check for the initiator path:
// INIT → UTP_CONNECTING (Connect fires Key Frame + utp_connect) →
// CONNECTED (libutp completes the handshake via UTP_STATE_CONNECT).
//
// KEY_FRAME_SENT is the responder-side intermediate; the initiator
// never sits in it post-#cbb49144f. The responder-side progression
// is covered by PassiveResponderStateProgression below.
TEST(UtpConnectFlow, FullStateTransitionsToConnected)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::INIT);

		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,  0x10);
		fill_hash(peer_hash, 0xA0);
		sockaddr_in peer = make_peer_addr();

		ASSERT_TRUE(layer.Connect(our_hash, peer_hash,
		                          reinterpret_cast<sockaddr*>(&peer),
		                          sizeof(peer)));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::UTP_CONNECTING);

		// Simulate libutp completing the handshake — the
		// UTP_STATE_CONNECT callback comes back through OnStateChange.
		layer.OnStateChange(UTP_STATE_CONNECT);
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::CONNECTED);
		ASSERT_TRUE(layer.IsConnected());
		ASSERT_TRUE(layer.IsWritable());
	}

	utp_destroy(ctx);
	reset_global_state();
}


// Responder-side state progression:
// INIT → KEY_FRAME_SENT (Connect with initiator=false; no Key Frame
// or SYN emitted — it's a passive registration) → UTP_CONNECTING
// (OnPeerKeyFrame with matching hash; still no socket — waits for
// libutp's UTP_ON_ACCEPT to deliver one).
TEST(UtpConnectFlow, PassiveResponderStateProgression)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::INIT);

		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,  0x10);
		fill_hash(peer_hash, 0xA0);
		sockaddr_in peer = make_peer_addr();

		ASSERT_TRUE(layer.Connect(our_hash, peer_hash,
		                          reinterpret_cast<sockaddr*>(&peer),
		                          sizeof(peer),
		                          /*initiator=*/false));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);
		// Passive side emits nothing on Connect.
		ASSERT_EQUALS((std::size_t)0, g_capture.packets.size());

		ASSERT_TRUE(layer.OnPeerKeyFrame(peer_hash));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::UTP_CONNECTING);
		// Still nothing on the wire — the responder doesn't drive the
		// uTP handshake; libutp's UTP_ON_ACCEPT delivers the socket.
		ASSERT_EQUALS((std::size_t)0, g_capture.packets.size());
	}

	utp_destroy(ctx);
	reset_global_state();
}


// Responder-side OnUtpAccept (Phase B8 / Phase E3 post-cbb49144f):
// libutp's UTP_ON_ACCEPT delivers a freshly-bound socket to the
// passive layer. The layer takes ownership, attaches itself as
// userdata, applies UTP_RCVBUF / UTP_SNDBUF, and transitions
// straight to CONNECTED — libutp's CS_SYN_RECV path doesn't fire
// UTP_STATE_CONNECT on the responder, so OnUtpAccept IS the
// "connected" signal.
TEST(UtpConnectFlow, OnUtpAcceptAdoptsSocketAndTransitionsToConnected)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,  0x10);
		fill_hash(peer_hash, 0xA0);
		sockaddr_in peer = make_peer_addr();

		ASSERT_TRUE(layer.Connect(our_hash, peer_hash,
		                          reinterpret_cast<sockaddr*>(&peer),
		                          sizeof(peer),
		                          /*initiator=*/false));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);

		// Fabricate a libutp socket the same way libutp would in its
		// on_accept dispatch — utp_create_socket on the same context.
		utp_socket* accepted = utp_create_socket(ctx);
		ASSERT_TRUE(accepted != NULL);

		layer.OnUtpAccept(accepted);
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::CONNECTED);
		ASSERT_TRUE(layer.IsConnected());
		ASSERT_TRUE(layer.IsWritable());

		// Detach the socket before scope-end. libutp's utp_close asserts
		// on CS_UNINITIALIZED, and the fabricated socket here never
		// reached CS_SYN_RECV (in production, on_accept hands a socket
		// that has already replied to a SYN). utp_destroy(ctx) below
		// reclaims any context-owned sockets.
		layer.OnStateChange(UTP_STATE_DESTROYING);
	}

	utp_destroy(ctx);
	reset_global_state();
}


// OnUtpAccept with a NULL socket is a defensive no-op — guards
// against the libutp callback running with a partially-initialised
// utp_socket pointer.
TEST(UtpConnectFlow, OnUtpAcceptNullSocketIsNoop)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,  0x10);
		fill_hash(peer_hash, 0xA0);
		sockaddr_in peer = make_peer_addr();

		ASSERT_TRUE(layer.Connect(our_hash, peer_hash,
		                          reinterpret_cast<sockaddr*>(&peer),
		                          sizeof(peer),
		                          /*initiator=*/false));

		layer.OnUtpAccept(NULL);
		// State unchanged — still KEY_FRAME_SENT, no socket adopted.
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);
	}

	utp_destroy(ctx);
	reset_global_state();
}


// CheckTimeoutNow (steady-clock variant): on a layer that's never
// had Connect() called, the steady-clock path must short-circuit
// (m_connect_started_at is the default-constructed time_point and
// the elapsed-since-epoch value would otherwise wrongly fire the
// timeout on the first tick). Production UtpTimer sweeps every
// layer in the registry; this short-circuit prevents an INIT-state
// layer from being flipped to FAILED before the app even calls
// Connect.
//
// Note: in this codebase CheckTimeoutNow short-circuits via the
// `m_state != KEY_FRAME_SENT` gate (the INIT-state layer is
// reachable via this path), so a no-Connect layer is observably
// idempotent under repeated ticks.
TEST(UtpConnectFlow, CheckTimeoutNowOnInitStateIsNoop)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::INIT);

		// Repeated ticks — layer must stay in INIT, never transition
		// to FAILED.
		ASSERT_FALSE(layer.CheckTimeoutNow());
		ASSERT_FALSE(layer.CheckTimeoutNow());
		ASSERT_FALSE(layer.CheckTimeoutNow());
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::INIT);
	}

	utp_destroy(ctx);
	reset_global_state();
}


// CheckTimeoutNow on a CONNECTED layer is also a no-op — timeouts
// only matter while waiting for the peer's Key Frame, and a
// successfully-handshaked layer should never spontaneously flip
// to FAILED.
TEST(UtpConnectFlow, CheckTimeoutNowOnConnectedIsNoop)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,  0x10);
		fill_hash(peer_hash, 0xA0);
		sockaddr_in peer = make_peer_addr();

		ASSERT_TRUE(layer.Connect(our_hash, peer_hash,
		                          reinterpret_cast<sockaddr*>(&peer),
		                          sizeof(peer)));
		// Drive to CONNECTED via the initiator state-change path.
		layer.OnStateChange(UTP_STATE_CONNECT);
		ASSERT_TRUE(layer.IsConnected());

		ASSERT_FALSE(layer.CheckTimeoutNow());
		ASSERT_TRUE(layer.IsConnected());
	}

	utp_destroy(ctx);
	reset_global_state();
}


// Calling Connect twice on the same layer is a programming error —
// must reject the second call. Uses the passive (responder) path so
// the test can assert "no extra packets sent" — the initiator path
// also rejects the second call but produces a Key Frame + SYN burst
// on the first one, which makes the post-state easier to mistake.
TEST(UtpConnectFlow, ConnectRejectsDoubleCall)
{
	reset_global_state();
	install_test_delegates();

	utp_context* ctx = utp_init(2);
	UtpCallbacks::InstallOnContext(ctx);

	{
		CUtpLayer layer(ctx);
		std::uint8_t our_hash[CUtpLayer::kUserHashSize];
		std::uint8_t peer_hash[CUtpLayer::kUserHashSize];
		fill_hash(our_hash,  0x10);
		fill_hash(peer_hash, 0xA0);
		sockaddr_in peer = make_peer_addr();

		ASSERT_TRUE(layer.Connect(our_hash, peer_hash,
		                          reinterpret_cast<sockaddr*>(&peer),
		                          sizeof(peer),
		                          /*initiator=*/false));
		ASSERT_FALSE(layer.Connect(our_hash, peer_hash,
		                           reinterpret_cast<sockaddr*>(&peer),
		                           sizeof(peer),
		                           /*initiator=*/false));
		// Single transition; nothing on the wire (passive side).
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);
		ASSERT_EQUALS((std::size_t)0, g_capture.packets.size());
	}

	utp_destroy(ctx);
	reset_global_state();
}

#else

using namespace muleunit;
DECLARE(UtpConnectFlow)
END_DECLARE;

TEST(UtpConnectFlow, FeatureDisabled)
{
	ASSERT_TRUE(true);
}

#endif // ENABLE_NAT_T
