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

// Tests for Phase B3 of the NAT-T port — CUtpLayer's per-connection
// write buffer, read buffer, and state-tracking logic.
//
// These tests deliberately do NOT bring up a real uTP connection.
// They construct a layer attached to a fresh utp_context and exercise
// the buffer pathways via Send() / Recv() / OnRead() / OnStateChange()
// without ever calling Connect() — the wire-level handshake belongs to
// B6 (connect flow) and the end-to-end round-trip belongs to B8
// (loopback integration). What matters at this phase is that the
// buffer invariants — capacity, FIFO ordering, overflow → short-write,
// close → reject — all hold.

#include <muleunit/test.h>

#include "UtpLayer.h"

#ifdef ENABLE_NAT_T

#include <utp.h>

#include <cstring>
#include <vector>

using namespace muleunit;

DECLARE(UtpLayer)
END_DECLARE;


// Send exactly kWriteBufferCapacity bytes — all should be accepted.
// One more byte after that returns 0 (buffer full). This is the
// "short-write" semantics the plan calls out (Q5).
TEST(UtpLayer, SendAcceptsUpToCapacityThenZero)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);

		std::vector<std::uint8_t> data(CUtpLayer::kWriteBufferCapacity, 0xAB);
		std::int64_t wrote = layer.Send(data.data(), data.size());
		ASSERT_EQUALS((std::int64_t)CUtpLayer::kWriteBufferCapacity, wrote);
		ASSERT_EQUALS(CUtpLayer::kWriteBufferCapacity, layer.WriteBufferSize());

		// Buffer is now full; Send() must return 0.
		std::uint8_t one_more = 0xCD;
		ASSERT_EQUALS((std::int64_t)0, layer.Send(&one_more, 1));
		ASSERT_EQUALS(CUtpLayer::kWriteBufferCapacity, layer.WriteBufferSize());
	}

	utp_destroy(ctx);
}


// Send 20 KiB at once — only the first 16 KiB are accepted. This is
// the "short write" return value the caller uses to decide how many
// bytes need to be retried after WRITABLE fires.
TEST(UtpLayer, SendOversizedReturnsCapacity)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);

		const std::size_t big = CUtpLayer::kWriteBufferCapacity + 4096;
		std::vector<std::uint8_t> data(big, 0x55);
		std::int64_t wrote = layer.Send(data.data(), data.size());
		ASSERT_EQUALS((std::int64_t)CUtpLayer::kWriteBufferCapacity, wrote);
		ASSERT_EQUALS(CUtpLayer::kWriteBufferCapacity, layer.WriteBufferSize());
	}

	utp_destroy(ctx);
}


// Two OnRead() deliveries land in the read buffer in order; a single
// Recv() drains them as one contiguous span. This is the
// "chunked-input reassembly" test the plan calls for.
TEST(UtpLayer, OnReadReassemblesChunkedDeliveries)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);

		const std::uint8_t chunk1[] = { 'H','e','l','l','o',',',' ' };
		const std::uint8_t chunk2[] = { 'w','o','r','l','d','!' };

		layer.OnRead(chunk1, sizeof(chunk1));
		layer.OnRead(chunk2, sizeof(chunk2));
		ASSERT_EQUALS((std::size_t)(sizeof(chunk1) + sizeof(chunk2)),
		              layer.ReadBufferSize());

		std::uint8_t out[64];
		std::memset(out, 0, sizeof(out));
		std::int64_t got = layer.Recv(out, sizeof(out));
		ASSERT_EQUALS((std::int64_t)(sizeof(chunk1) + sizeof(chunk2)), got);
		ASSERT_TRUE(std::memcmp(out, "Hello, world!", 13) == 0);
		ASSERT_EQUALS((std::size_t)0, layer.ReadBufferSize());
	}

	utp_destroy(ctx);
}


// Partial Recv into a small buffer returns only what fits; leftover
// bytes stay queued for the next call. Validates FIFO ordering across
// multiple drains (not just within a single Recv).
TEST(UtpLayer, RecvDrainsFifoAcrossMultipleCalls)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);

		const std::uint8_t data[] = "abcdefghij"; // 10 bytes (excl NUL)
		layer.OnRead(data, 10);

		std::uint8_t out[4];
		std::memset(out, 0, sizeof(out));

		std::int64_t got1 = layer.Recv(out, 4);
		ASSERT_EQUALS((std::int64_t)4, got1);
		ASSERT_TRUE(std::memcmp(out, "abcd", 4) == 0);

		std::int64_t got2 = layer.Recv(out, 4);
		ASSERT_EQUALS((std::int64_t)4, got2);
		ASSERT_TRUE(std::memcmp(out, "efgh", 4) == 0);

		std::int64_t got3 = layer.Recv(out, 4);
		ASSERT_EQUALS((std::int64_t)2, got3);  // only 2 bytes left
		ASSERT_TRUE(std::memcmp(out, "ij", 2) == 0);

		// Buffer drained.
		ASSERT_EQUALS((std::int64_t)0, layer.Recv(out, 4));
	}

	utp_destroy(ctx);
}


// Close() marks the layer closed and rejects subsequent sends.
// Critical because CUpDownClient (later) will check IsClosed() as
// its "is this layer still usable" signal.
TEST(UtpLayer, CloseMarksLayerClosedAndRejectsSend)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);
		ASSERT_FALSE(layer.IsClosed());

		layer.Close();
		ASSERT_TRUE(layer.IsClosed());

		const std::uint8_t b = 0xFF;
		ASSERT_EQUALS((std::int64_t)0, layer.Send(&b, 1));
	}

	utp_destroy(ctx);
}


// OnStateChange(UTP_STATE_DESTROYING) is libutp's "I'm freeing the
// socket" signal. The layer must drop its socket pointer and mark
// itself closed so the dtor doesn't try to utp_close a freed handle.
TEST(UtpLayer, OnStateChangeDestroyingMarksClosed)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);
		layer.OnStateChange(UTP_STATE_DESTROYING);
		ASSERT_TRUE(layer.IsClosed());
		ASSERT_FALSE(layer.IsWritable());
	}

	utp_destroy(ctx);
}


// OnGetReadBufferSize reflects remaining capacity, not the constant
// total. Important because libutp's flow control reads this every
// time it considers delivering more bytes.
TEST(UtpLayer, OnGetReadBufferSizeShrinksAsBufferFills)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);
		ASSERT_EQUALS(CUtpLayer::kReadBufferCapacity,
		              layer.OnGetReadBufferSize());

		std::vector<std::uint8_t> data(1024, 0xEE);
		layer.OnRead(data.data(), data.size());
		ASSERT_EQUALS(CUtpLayer::kReadBufferCapacity - 1024,
		              layer.OnGetReadBufferSize());
	}

	utp_destroy(ctx);
}

#else

using namespace muleunit;
DECLARE(UtpLayer)
END_DECLARE;

TEST(UtpLayer, FeatureDisabled)
{
	ASSERT_TRUE(true);
}

#endif // ENABLE_NAT_T
