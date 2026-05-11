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

// Tests for Phase B4 of the NAT-T port — the Key Frame envelope
// encoder / parser. Pure-function tests; no libutp dependency.
// Compiles regardless of ENABLE_NAT_T because the encoder/parser
// themselves are unconditionally available (they're useful for
// hex-dump diagnostics independent of the feature flag).
//
// Coverage:
//   - Golden-byte encoding (known input → known output bytes).
//   - Golden-byte parsing (known input bytes → known struct).
//   - Roundtrip across a sweep of hash values.
//   - All defined rejection paths (bad opcode, bad sub-byte, short
//     buffer, short output capacity, NULL arguments).
//   - Trailing-bytes tolerance (extra bytes after the 18-byte
//     envelope must not break parsing — UDP frames may carry
//     padding).

#include <muleunit/test.h>
#include "UtpKeyFrame.h"

#include <cstring>

using namespace muleunit;

DECLARE(UtpKeyFrame)
END_DECLARE;


// Encoding a known hash produces exactly the expected 18-byte
// sequence: 0xB2 0xFF followed by the 16 hash bytes verbatim.
TEST(UtpKeyFrame, EncodeGoldenBytes)
{
	std::uint8_t hash[UtpKeyFrame::kUserHashSize];
	for (std::size_t i = 0; i < UtpKeyFrame::kUserHashSize; ++i) {
		hash[i] = static_cast<std::uint8_t>(0x42);
	}

	std::uint8_t out[64];
	std::memset(out, 0, sizeof(out));
	std::size_t out_len = 0;

	bool ok = UtpKeyFrame::EncodePlain(hash, out, sizeof(out), &out_len);
	ASSERT_TRUE(ok);
	ASSERT_EQUALS(UtpKeyFrame::kPlainEnvelopeSize, out_len);
	ASSERT_EQUALS((int)0xB2, (int)out[0]);
	ASSERT_EQUALS((int)0xFF, (int)out[1]);
	for (std::size_t i = 0; i < UtpKeyFrame::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)0x42, (int)out[2 + i]);
	}

	// Trailing bytes in the buffer must be untouched — Encode only
	// writes the 18-byte envelope, nothing more.
	ASSERT_EQUALS((int)0, (int)out[UtpKeyFrame::kPlainEnvelopeSize]);
}


// Parsing a known 18-byte envelope produces exactly the hash that
// was encoded. Inverse of the golden-byte encode test.
TEST(UtpKeyFrame, ParseGoldenBytes)
{
	std::uint8_t wire[UtpKeyFrame::kPlainEnvelopeSize];
	wire[0] = 0xB2;
	wire[1] = 0xFF;
	for (std::size_t i = 0; i < UtpKeyFrame::kUserHashSize; ++i) {
		wire[2 + i] = static_cast<std::uint8_t>(i + 1); // 0x01..0x10
	}

	std::uint8_t parsed[UtpKeyFrame::kUserHashSize];
	std::memset(parsed, 0, sizeof(parsed));

	bool ok = UtpKeyFrame::ParsePlain(wire, sizeof(wire), parsed);
	ASSERT_TRUE(ok);
	for (std::size_t i = 0; i < UtpKeyFrame::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)(i + 1), (int)parsed[i]);
	}
}


// Encode + Parse roundtrip for every distinct fill byte (256 hashes).
// Catches any signedness / wraparound / off-by-one in the hash copy.
TEST(UtpKeyFrame, RoundtripAllByteFills)
{
	for (int fill = 0; fill < 256; ++fill) {
		std::uint8_t hash_in[UtpKeyFrame::kUserHashSize];
		for (std::size_t i = 0; i < UtpKeyFrame::kUserHashSize; ++i) {
			hash_in[i] = static_cast<std::uint8_t>(fill);
		}

		std::uint8_t wire[UtpKeyFrame::kPlainEnvelopeSize];
		std::memset(wire, 0xAA, sizeof(wire));
		std::size_t wire_len = 0;
		ASSERT_TRUE(UtpKeyFrame::EncodePlain(hash_in, wire, sizeof(wire),
		                                     &wire_len));
		ASSERT_EQUALS(UtpKeyFrame::kPlainEnvelopeSize, wire_len);

		std::uint8_t hash_out[UtpKeyFrame::kUserHashSize];
		std::memset(hash_out, 0xBB, sizeof(hash_out));
		ASSERT_TRUE(UtpKeyFrame::ParsePlain(wire, wire_len, hash_out));
		ASSERT_TRUE(std::memcmp(hash_in, hash_out,
		                       UtpKeyFrame::kUserHashSize) == 0);
	}
}


// Roundtrip across a sweep where every position has a different byte
// value. Catches any byte-order swap or buffer indexing error that
// would be invisible to all-same-byte tests.
TEST(UtpKeyFrame, RoundtripPositionalHash)
{
	std::uint8_t hash_in[UtpKeyFrame::kUserHashSize];
	for (std::size_t i = 0; i < UtpKeyFrame::kUserHashSize; ++i) {
		// Each byte is a distinct value, with bit patterns spanning
		// both halves of the 0x00..0xFF range.
		hash_in[i] = static_cast<std::uint8_t>(0x10 + i * 9);
	}

	std::uint8_t wire[UtpKeyFrame::kPlainEnvelopeSize];
	ASSERT_TRUE(UtpKeyFrame::EncodePlain(hash_in, wire, sizeof(wire), NULL));

	std::uint8_t hash_out[UtpKeyFrame::kUserHashSize];
	ASSERT_TRUE(UtpKeyFrame::ParsePlain(wire, sizeof(wire), hash_out));
	ASSERT_TRUE(std::memcmp(hash_in, hash_out,
	                       UtpKeyFrame::kUserHashSize) == 0);
}


// Parse must reject a frame whose first byte is anything other than
// OP_UDPRESERVEDPROT2. Otherwise a vanilla eD2k UDP packet that
// happens to start with [0xAB, 0xFF] could be misinterpreted as a
// Key Frame.
TEST(UtpKeyFrame, ParseRejectsWrongOpcode)
{
	std::uint8_t wire[UtpKeyFrame::kPlainEnvelopeSize];
	std::memset(wire, 0, sizeof(wire));
	wire[0] = 0xAB;  // wrong — must be 0xB2
	wire[1] = 0xFF;

	std::uint8_t parsed[UtpKeyFrame::kUserHashSize];
	ASSERT_FALSE(UtpKeyFrame::ParsePlain(wire, sizeof(wire), parsed));
}


// Parse must reject a frame whose sub-byte is anything other than
// 0xFF. This protects the Key Frame path from being entered by a
// future sub-byte (e.g. 0x00 = uTP frame, or any unassigned value).
TEST(UtpKeyFrame, ParseRejectsWrongSubByte)
{
	std::uint8_t wire[UtpKeyFrame::kPlainEnvelopeSize];
	std::memset(wire, 0, sizeof(wire));
	wire[0] = 0xB2;
	wire[1] = 0x00;  // wrong — uTP frame, not Key Frame

	std::uint8_t parsed[UtpKeyFrame::kUserHashSize];
	ASSERT_FALSE(UtpKeyFrame::ParsePlain(wire, sizeof(wire), parsed));
}


// Short buffers must be rejected. UDP can deliver a truncated frame
// to the application layer; we must not read past the end.
TEST(UtpKeyFrame, ParseRejectsShortBuffer)
{
	std::uint8_t wire[UtpKeyFrame::kPlainEnvelopeSize];
	std::memset(wire, 0, sizeof(wire));
	wire[0] = 0xB2;
	wire[1] = 0xFF;

	std::uint8_t parsed[UtpKeyFrame::kUserHashSize];
	// Try every length from 0 to kPlainEnvelopeSize-1 — all reject.
	for (std::size_t len = 0; len < UtpKeyFrame::kPlainEnvelopeSize; ++len) {
		ASSERT_FALSE(UtpKeyFrame::ParsePlain(wire, len, parsed));
	}
	// Boundary: exactly kPlainEnvelopeSize bytes accepts.
	ASSERT_TRUE(UtpKeyFrame::ParsePlain(wire, UtpKeyFrame::kPlainEnvelopeSize,
	                                    parsed));
}


// Trailing bytes past the envelope must be tolerated. A real UDP
// datagram may carry padding; we extract our 18-byte envelope from
// the head and silently ignore the rest.
TEST(UtpKeyFrame, ParseToleratesTrailingBytes)
{
	std::uint8_t wire[UtpKeyFrame::kPlainEnvelopeSize + 32];
	std::memset(wire, 0xCC, sizeof(wire));  // tail filled with garbage
	wire[0] = 0xB2;
	wire[1] = 0xFF;
	for (std::size_t i = 0; i < UtpKeyFrame::kUserHashSize; ++i) {
		wire[2 + i] = static_cast<std::uint8_t>(0x77);
	}

	std::uint8_t parsed[UtpKeyFrame::kUserHashSize];
	ASSERT_TRUE(UtpKeyFrame::ParsePlain(wire, sizeof(wire), parsed));
	for (std::size_t i = 0; i < UtpKeyFrame::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)0x77, (int)parsed[i]);
	}
}


// Encode rejects a too-small output buffer rather than overflowing.
TEST(UtpKeyFrame, EncodeRejectsSmallCapacity)
{
	std::uint8_t hash[UtpKeyFrame::kUserHashSize];
	std::memset(hash, 0x33, sizeof(hash));

	std::uint8_t out[UtpKeyFrame::kPlainEnvelopeSize];
	std::size_t out_len = 0;

	// Capacity one byte short of the envelope size — must reject.
	bool ok = UtpKeyFrame::EncodePlain(hash, out,
	                                  UtpKeyFrame::kPlainEnvelopeSize - 1,
	                                  &out_len);
	ASSERT_FALSE(ok);
	// out_len is left unset on failure — but we don't depend on its
	// value here. Documented behavior is "may be NULL if the caller
	// doesn't care", so reading it would be implementation-defined.
}


// NULL-argument guards: each pointer argument that the docs say
// "must not be NULL" must be checked, and the function must return
// false rather than crash.
TEST(UtpKeyFrame, RejectsNullArguments)
{
	std::uint8_t hash[UtpKeyFrame::kUserHashSize];
	std::memset(hash, 0, sizeof(hash));

	std::uint8_t out[UtpKeyFrame::kPlainEnvelopeSize];
	std::size_t  out_len = 0;

	// EncodePlain: NULL sender_hash, NULL out → both reject.
	ASSERT_FALSE(UtpKeyFrame::EncodePlain(NULL, out, sizeof(out), &out_len));
	ASSERT_FALSE(UtpKeyFrame::EncodePlain(hash, NULL, sizeof(out), &out_len));

	// ParsePlain: NULL buf, NULL out → both reject.
	ASSERT_FALSE(UtpKeyFrame::ParsePlain(NULL, sizeof(out), hash));
	ASSERT_FALSE(UtpKeyFrame::ParsePlain(out,  sizeof(out), NULL));
}
