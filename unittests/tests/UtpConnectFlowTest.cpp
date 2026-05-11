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


// The headline test: Connect must transition INIT → KEY_FRAME_SENT
// and emit exactly one outbound UDP packet — the Key Frame envelope
// (0xB2, 0xFF, then the 16-byte identity-encrypt of sender_hash).
TEST(UtpConnectFlow, ConnectSendsKeyFrameAndTransitionsState)
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
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);

		// Exactly one packet sent — the Key Frame. utp_connect has
		// NOT yet been called, so no SYN should appear yet.
		ASSERT_EQUALS((std::size_t)1, g_capture.packets.size());

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


// OnPeerKeyFrame with the matching hash must call utp_connect, which
// triggers libutp to emit a SYN through on_sendto → our capture
// delegate gets a second packet whose first-byte high-nibble is
// ST_SYN = 4. State transitions KEY_FRAME_SENT → UTP_CONNECTING.
TEST(UtpConnectFlow, OnPeerKeyFrameTriggersUtpSyn)
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
		ASSERT_EQUALS((std::size_t)1, g_capture.packets.size());

		ASSERT_TRUE(layer.OnPeerKeyFrame(peer_hash));
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::UTP_CONNECTING);

		// libutp emitted at least one packet — the SYN. The first
		// byte's high nibble is ST_SYN (4), low nibble is wire-format
		// version (1), so byte 0 == 0x41.
		ASSERT_TRUE(g_capture.packets.size() >= 2);
		const CapturedPacket& syn = g_capture.packets[1];
		ASSERT_TRUE(syn.payload.size() >= 1);
		ASSERT_EQUALS((int)0x41, (int)syn.payload[0]);
	}

	utp_destroy(ctx);
	reset_global_state();
}


// OnPeerKeyFrame must reject a Key Frame whose embedded sender_hash
// doesn't match the peer_hash we recorded on Connect. No state
// transition; no utp_connect; no second packet.
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
		                          sizeof(peer)));

		ASSERT_FALSE(layer.OnPeerKeyFrame(wrong_hash));
		// State unchanged — still waiting for the correct Key Frame.
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);
		// Capture still has only the outbound Key Frame, no SYN.
		ASSERT_EQUALS((std::size_t)1, g_capture.packets.size());
	}

	utp_destroy(ctx);
	reset_global_state();
}


// CheckTimeout: short elapsed times leave the layer in
// KEY_FRAME_SENT; once elapsed_ms >= kKeyFrameTimeoutMs the
// transition fires.
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
		                          sizeof(peer)));

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


// State-machine progression sanity check: INIT → KEY_FRAME_SENT →
// UTP_CONNECTING → CONNECTED. Each transition exercised explicitly.
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
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);

		ASSERT_TRUE(layer.OnPeerKeyFrame(peer_hash));
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


// Calling Connect twice on the same layer is a programming error —
// must reject the second call.
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
		                          sizeof(peer)));
		ASSERT_FALSE(layer.Connect(our_hash, peer_hash,
		                           reinterpret_cast<sockaddr*>(&peer),
		                           sizeof(peer)));
		// Still in KEY_FRAME_SENT — single transition, single outbound packet.
		ASSERT_TRUE(layer.GetState() == CUtpLayer::State::KEY_FRAME_SENT);
		ASSERT_EQUALS((std::size_t)1, g_capture.packets.size());
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
