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

// Phase A3 of the NAT-T port: pure-function tests for the connect-options
// byte's NAT-T capability bit. CUpDownClient itself has heavy app-state
// dependencies that are awkward to instantiate in a unit test; the
// extraction of bit-7-decode into NatTraversal::DecodeFromConnectOptions
// (and the inverse encoder) was specifically motivated by making this
// layer testable without dragging in CamuleApp / CClientList.

#include <muleunit/test.h>
#include "NatTraversal.h"

using namespace muleunit;

DECLARE(NatTraversal)
END_DECLARE;


// Sanity: the constant is at the documented position.
TEST(NatTraversal, BitPositionIsZero80)
{
	ASSERT_EQUALS(0x80, (int)NatTraversal::CONNECT_OPT_BIT_NAT_TRAVERSAL);
}


// In Hello / DirectCallbackReq context (treat_bit7_as_nat_t = true),
// bit 7 carries the NAT-T capability.
TEST(NatTraversal, DecodeNatTraversalContext_BitSet)
{
	ASSERT_TRUE(NatTraversal::DecodeFromConnectOptions(0x80, true));
	ASSERT_TRUE(NatTraversal::DecodeFromConnectOptions(0xFF, true));
	ASSERT_TRUE(NatTraversal::DecodeFromConnectOptions(0x8F, true));
}

TEST(NatTraversal, DecodeNatTraversalContext_BitClear)
{
	ASSERT_FALSE(NatTraversal::DecodeFromConnectOptions(0x00, true));
	ASSERT_FALSE(NatTraversal::DecodeFromConnectOptions(0x0F, true));
	ASSERT_FALSE(NatTraversal::DecodeFromConnectOptions(0x7F, true));
}


// In server source-exchange context (treat_bit7_as_nat_t = false),
// bit 7 is overloaded to mean "hash follows" and MUST NEVER be reported
// as NAT-T support — even if the bit is set. This is the critical
// guarantee that protects existing call sites (PartFile.cpp,
// ED2KLink.cpp, DownloadQueue.cpp) from being regressed.
TEST(NatTraversal, DecodeSourceExchangeContext_AlwaysReturnsFalse)
{
	// Every possible byte value, with treat_bit7_as_nat_t=false, must
	// produce false. Iterate all 256 to catch any future regression
	// that might leak bit-7 semantics into the source-exchange path.
	for (int b = 0; b < 256; ++b) {
		uint8_t options = static_cast<uint8_t>(b);
		ASSERT_FALSE(NatTraversal::DecodeFromConnectOptions(options, false));
	}
}


// Encoding: setting NAT-T or'sin bit 7, clearing it &'s it off, other
// bits are preserved unchanged.
TEST(NatTraversal, EncodeRoundTrip)
{
	// Bit 7 set when supports_nat=true, regardless of base bits.
	ASSERT_EQUALS((int)0x80, (int)NatTraversal::EncodeIntoConnectOptions(0x00, true));
	ASSERT_EQUALS((int)0x8F, (int)NatTraversal::EncodeIntoConnectOptions(0x0F, true));
	ASSERT_EQUALS((int)0xFF, (int)NatTraversal::EncodeIntoConnectOptions(0xFF, true));

	// Bit 7 cleared when supports_nat=false; other bits untouched.
	ASSERT_EQUALS((int)0x00, (int)NatTraversal::EncodeIntoConnectOptions(0x00, false));
	ASSERT_EQUALS((int)0x0F, (int)NatTraversal::EncodeIntoConnectOptions(0x0F, false));
	ASSERT_EQUALS((int)0x7F, (int)NatTraversal::EncodeIntoConnectOptions(0xFF, false));
}


// Full roundtrip: encode and then decode in NAT-T context returns the
// original bool. Tests that the encode and decode are inverses.
TEST(NatTraversal, EncodeDecodeRoundTrip)
{
	for (int b = 0; b < 256; ++b) {
		uint8_t base = static_cast<uint8_t>(b);
		// Strip bit 7 from base so the test is unambiguous about
		// which side is setting the bit. (If we left bit 7 in the
		// base and passed supports_nat=false, the encoder clears
		// the bit — that's covered by the EncodeRoundTrip test
		// above. Here we're testing the inverse property.)
		base &= 0x7F;

		uint8_t encoded_true  = NatTraversal::EncodeIntoConnectOptions(base, true);
		uint8_t encoded_false = NatTraversal::EncodeIntoConnectOptions(base, false);

		ASSERT_TRUE (NatTraversal::DecodeFromConnectOptions(encoded_true,  true));
		ASSERT_FALSE(NatTraversal::DecodeFromConnectOptions(encoded_false, true));
	}
}
