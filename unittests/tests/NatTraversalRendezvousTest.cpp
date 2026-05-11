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

// Tests for Phase C2 of the NAT-T port — OP_RENDEZVOUS /
// OP_HOLEPUNCH wire-format encoders + parsers. Pure functions, no
// libutp / theApp / threading dependencies, so the test is
// straight-line byte-level verification. The wire layout must match
// eMuleAI's ClientUDPSocket.cpp:918 (RENDEZVOUS) and :1421
// (HOLEPUNCH) exactly for interop.

#include <muleunit/test.h>
#include "NatTraversal.h"

#include <cstring>
#include <vector>

using namespace muleunit;

DECLARE(NatTraversalRendezvous)
END_DECLARE;


namespace {

void fill_hash(std::uint8_t hash[NatTraversal::kUserHashSize], std::uint8_t base)
{
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		hash[i] = static_cast<std::uint8_t>(base + i);
	}
}

bool hashes_equal(const std::uint8_t a[NatTraversal::kUserHashSize],
                  const std::uint8_t b[NatTraversal::kUserHashSize])
{
	return std::memcmp(a, b, NatTraversal::kUserHashSize) == 0;
}

} // anonymous namespace


// Mandatory-only encoding: target_user_hash (16) + connect_options
// (1) = 17 bytes total. No optional blocks.
TEST(NatTraversalRendezvous, EncodeMandatoryOnly)
{
	NatTraversal::RendezvousRequest req;
	fill_hash(req.target_user_hash, 0xA0);
	req.connect_options    = 0x83;  // crypt-supported + NAT-T bit
	req.has_file_hash      = false;
	req.has_ext_endpoint   = false;

	std::vector<std::uint8_t> out;
	ASSERT_TRUE(NatTraversal::EncodeRendezvous(req, out));
	ASSERT_EQUALS(NatTraversal::kRendezvousBodyMin, out.size());

	// Byte-level check: the hash is verbatim, then the
	// connect_options byte.
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)(0xA0 + i), (int)out[i]);
	}
	ASSERT_EQUALS((int)0x83, (int)out[NatTraversal::kUserHashSize]);
}


// With file_hash but no ext_endpoint: 33 bytes. The encoder writes
// the file_hash directly after connect_options.
TEST(NatTraversalRendezvous, EncodeWithFileHash)
{
	NatTraversal::RendezvousRequest req;
	fill_hash(req.target_user_hash, 0xA0);
	fill_hash(req.target_file_hash, 0x10);
	req.connect_options    = 0x01;
	req.has_file_hash      = true;
	req.has_ext_endpoint   = false;

	std::vector<std::uint8_t> out;
	ASSERT_TRUE(NatTraversal::EncodeRendezvous(req, out));
	ASSERT_EQUALS(NatTraversal::kRendezvousBodyMid, out.size());

	// File_hash starts at byte 17.
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)(0x10 + i),
		              (int)out[NatTraversal::kRendezvousBodyMin + i]);
	}
}


// With both optional blocks: 39 bytes. Ext IP+port are little-endian
// (matches eMule's CFile::WriteUInt32 / WriteUInt16 convention).
TEST(NatTraversalRendezvous, EncodeWithFileHashAndExtEndpoint)
{
	NatTraversal::RendezvousRequest req;
	fill_hash(req.target_user_hash, 0xA0);
	fill_hash(req.target_file_hash, 0x10);
	req.connect_options    = 0x01;
	req.has_file_hash      = true;
	req.has_ext_endpoint   = true;
	req.requester_ext_ip   = 0x01020304u;  // 4.3.2.1 in dotted, but
	                                       // wire order is LE so the
	                                       // first byte is 0x04.
	req.requester_ext_port = 0xBEEFu;

	std::vector<std::uint8_t> out;
	ASSERT_TRUE(NatTraversal::EncodeRendezvous(req, out));
	ASSERT_EQUALS(NatTraversal::kRendezvousBodyFull, out.size());

	// Ext IP at offset 33, little-endian.
	ASSERT_EQUALS((int)0x04, (int)out[33]);
	ASSERT_EQUALS((int)0x03, (int)out[34]);
	ASSERT_EQUALS((int)0x02, (int)out[35]);
	ASSERT_EQUALS((int)0x01, (int)out[36]);
	// Ext port at offset 37, little-endian.
	ASSERT_EQUALS((int)0xEF, (int)out[37]);
	ASSERT_EQUALS((int)0xBE, (int)out[38]);
}


// Special case: caller wants to emit ext_endpoint without file_hash.
// The encoder must insert a 16-byte zero placeholder so the parser's
// positional decode finds the ext fields where expected.
TEST(NatTraversalRendezvous, EncodeExtEndpointWithoutFileHashInsertsZero)
{
	NatTraversal::RendezvousRequest req;
	fill_hash(req.target_user_hash, 0xA0);
	req.connect_options    = 0x01;
	req.has_file_hash      = false;
	req.has_ext_endpoint   = true;
	req.requester_ext_ip   = 0;
	req.requester_ext_port = 0;

	std::vector<std::uint8_t> out;
	ASSERT_TRUE(NatTraversal::EncodeRendezvous(req, out));
	ASSERT_EQUALS(NatTraversal::kRendezvousBodyFull, out.size());

	// Bytes 17..32 must all be zero (the placeholder).
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)0,
		              (int)out[NatTraversal::kRendezvousBodyMin + i]);
	}
}


// Decode the mandatory-only form (17 bytes). has_file_hash and
// has_ext_endpoint must both come back as false.
TEST(NatTraversalRendezvous, DecodeMandatoryOnly)
{
	std::vector<std::uint8_t> wire;
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		wire.push_back(static_cast<std::uint8_t>(0xA0 + i));
	}
	wire.push_back(0x83);

	NatTraversal::RendezvousRequest req;
	ASSERT_TRUE(NatTraversal::DecodeRendezvous(wire.data(), wire.size(), req));
	std::uint8_t expected_hash[NatTraversal::kUserHashSize];
	fill_hash(expected_hash, 0xA0);
	ASSERT_TRUE(hashes_equal(req.target_user_hash, expected_hash));
	ASSERT_EQUALS((int)0x83, (int)req.connect_options);
	ASSERT_FALSE(req.has_file_hash);
	ASSERT_FALSE(req.has_ext_endpoint);
}


// Decode + full optional blocks: verifies that has_* flags are set
// and the ext IP/port come out in the right (host) byte order.
TEST(NatTraversalRendezvous, DecodeFullOptionalBlocks)
{
	std::vector<std::uint8_t> wire;
	// user_hash
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		wire.push_back(static_cast<std::uint8_t>(0xA0 + i));
	}
	// connect_options
	wire.push_back(0x01);
	// file_hash
	for (std::size_t i = 0; i < NatTraversal::kUserHashSize; ++i) {
		wire.push_back(static_cast<std::uint8_t>(0x10 + i));
	}
	// ext_ip = 0x01020304 little-endian (= bytes 04 03 02 01)
	wire.push_back(0x04); wire.push_back(0x03);
	wire.push_back(0x02); wire.push_back(0x01);
	// ext_port = 0xBEEF little-endian (= bytes EF BE)
	wire.push_back(0xEF); wire.push_back(0xBE);

	NatTraversal::RendezvousRequest req;
	ASSERT_TRUE(NatTraversal::DecodeRendezvous(wire.data(), wire.size(), req));
	ASSERT_TRUE(req.has_file_hash);
	ASSERT_TRUE(req.has_ext_endpoint);
	std::uint8_t expected_file[NatTraversal::kUserHashSize];
	fill_hash(expected_file, 0x10);
	ASSERT_TRUE(hashes_equal(req.target_file_hash, expected_file));
	ASSERT_EQUALS((unsigned long)0x01020304ul,
	              (unsigned long)req.requester_ext_ip);
	ASSERT_EQUALS((int)0xBEEF, (int)req.requester_ext_port);
}


// Roundtrip: encode all combinations of (has_file_hash,
// has_ext_endpoint) and verify the decoded struct matches the
// original.
TEST(NatTraversalRendezvous, RoundtripAllOptionalCombinations)
{
	for (int file_present = 0; file_present <= 1; ++file_present) {
	for (int ext_present  = 0; ext_present  <= 1; ++ext_present) {
		NatTraversal::RendezvousRequest in;
		fill_hash(in.target_user_hash, 0x55);
		fill_hash(in.target_file_hash, 0x77);
		in.connect_options    = 0xC1;
		in.has_file_hash      = (file_present != 0);
		in.has_ext_endpoint   = (ext_present  != 0);
		in.requester_ext_ip   = 0xDEADBEEFu;
		in.requester_ext_port = 0xCAFEu;

		std::vector<std::uint8_t> wire;
		ASSERT_TRUE(NatTraversal::EncodeRendezvous(in, wire));

		NatTraversal::RendezvousRequest out;
		ASSERT_TRUE(NatTraversal::DecodeRendezvous(wire.data(), wire.size(), out));

		ASSERT_TRUE(hashes_equal(in.target_user_hash, out.target_user_hash));
		ASSERT_EQUALS((int)in.connect_options, (int)out.connect_options);

		if (in.has_file_hash) {
			ASSERT_TRUE(out.has_file_hash);
			ASSERT_TRUE(hashes_equal(in.target_file_hash,
			                       out.target_file_hash));
		} else if (!in.has_ext_endpoint) {
			// Pure mandatory form — decoder sees 17 bytes, no file_hash.
			ASSERT_FALSE(out.has_file_hash);
		}
		// (When !has_file_hash && has_ext_endpoint, encoder writes
		// a zero placeholder; decoder will set has_file_hash=true
		// with a zero hash. That's the documented behavior — the
		// caller asked for ext_endpoint, which forced the file_hash
		// slot. The asymmetry is fine; consumers check
		// isnulmd4(file_hash) like eMuleAI does at line 933.)

		if (in.has_ext_endpoint) {
			ASSERT_TRUE(out.has_ext_endpoint);
			ASSERT_EQUALS((unsigned long)in.requester_ext_ip,
			              (unsigned long)out.requester_ext_ip);
			ASSERT_EQUALS((int)in.requester_ext_port,
			              (int)out.requester_ext_port);
		}
	}
	}
}


// Decode rejects bodies shorter than 17 bytes (the mandatory minimum).
TEST(NatTraversalRendezvous, DecodeRejectsShortBuffer)
{
	std::uint8_t buf[NatTraversal::kRendezvousBodyMin];
	std::memset(buf, 0, sizeof(buf));
	NatTraversal::RendezvousRequest req;
	for (std::size_t len = 0; len < NatTraversal::kRendezvousBodyMin; ++len) {
		ASSERT_FALSE(NatTraversal::DecodeRendezvous(buf, len, req));
	}
	// Exactly the minimum length parses cleanly.
	ASSERT_TRUE(NatTraversal::DecodeRendezvous(buf,
	                                          NatTraversal::kRendezvousBodyMin,
	                                          req));
}


// Decode tolerates trailing bytes past the recognised blocks (UDP
// can deliver padding; future versions might add fields).
TEST(NatTraversalRendezvous, DecodeToleratesTrailingBytes)
{
	std::vector<std::uint8_t> wire;
	// Mandatory + file_hash + ext_endpoint = 39 bytes.
	for (std::size_t i = 0; i < NatTraversal::kRendezvousBodyFull; ++i) {
		wire.push_back(static_cast<std::uint8_t>(0x11));
	}
	// Append 32 bytes of trailing garbage.
	for (int i = 0; i < 32; ++i) wire.push_back(0xEE);

	NatTraversal::RendezvousRequest req;
	ASSERT_TRUE(NatTraversal::DecodeRendezvous(wire.data(), wire.size(), req));
	ASSERT_TRUE(req.has_file_hash);
	ASSERT_TRUE(req.has_ext_endpoint);
	// Trailing garbage didn't bleed into the parsed fields.
	ASSERT_EQUALS((int)0x11, (int)req.connect_options);
}


// NULL buf is rejected cleanly.
TEST(NatTraversalRendezvous, DecodeRejectsNullBuf)
{
	NatTraversal::RendezvousRequest req;
	ASSERT_FALSE(NatTraversal::DecodeRendezvous(nullptr, 100, req));
}


// HOLEPUNCH encoder produces an empty body — the opcode header is
// the signal; no payload bytes are emitted.
TEST(NatTraversalRendezvous, HolePunchEncodeEmpty)
{
	std::vector<std::uint8_t> out;
	// Pre-populate `out` so we can confirm Encode clears it.
	out.push_back(0xAA);
	ASSERT_TRUE(NatTraversal::EncodeHolePunch(out));
	ASSERT_EQUALS((std::size_t)0, out.size());
}


// HOLEPUNCH decoder accepts any body (empty or with padding).
// Today's protocol has no payload; future versions might.
TEST(NatTraversalRendezvous, HolePunchDecodeAcceptsEmpty)
{
	ASSERT_TRUE(NatTraversal::DecodeHolePunch(nullptr, 0));

	std::uint8_t trailing[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	ASSERT_TRUE(NatTraversal::DecodeHolePunch(trailing, sizeof(trailing)));
}
