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
#include "UdpReceiveBufferStat.h"

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


// Phase E3: a registered data-available callback fires once per
// OnRead delivery that actually appends bytes. Zero-byte OnRead
// (NULL data or len==0) skips the callback. Multiple deliveries
// fire multiple callbacks — the receiver (production:
// CoreNotify_LibSocketReceive) is expected to coalesce or
// be idempotent.
TEST(UtpLayer, DataAvailableCallbackFiresPerOnRead)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);

		int call_count = 0;
		layer.SetDataAvailableCallback([&call_count]() {
			++call_count;
		});

		const std::uint8_t chunk1[] = { 'a','b','c' };
		const std::uint8_t chunk2[] = { 'd','e','f','g' };
		layer.OnRead(chunk1, sizeof(chunk1));
		layer.OnRead(chunk2, sizeof(chunk2));
		ASSERT_EQUALS(2, call_count);

		// Zero-byte OnRead does not fire the callback (no bytes appended).
		layer.OnRead(nullptr, 0);
		ASSERT_EQUALS(2, call_count);
		layer.OnRead(chunk1, 0);
		ASSERT_EQUALS(2, call_count);

		// Drain doesn't fire the callback either — only inbound bytes do.
		std::uint8_t out[16];
		std::int64_t got = layer.Recv(out, sizeof(out));
		ASSERT_EQUALS((std::int64_t)7, got);
		ASSERT_EQUALS(2, call_count);
	}

	utp_destroy(ctx);
}

// Bug #4 (post-D6, commit e80a46ee3): Recv() must re-fire the
// data-available callback when bytes still remain in the read buffer
// after the pop. eD2k's CEMSocket::OnReceive do-while exits after
// one complete packet (pendingHeaderSize resets to zero), so multi-
// packet uTP frames need the caller re-entered or the residual
// stays stuck until the next OnRead. Verified by observing that the
// callback fires from inside Recv when (and only when) m_readBuf is
// non-empty afterwards.
TEST(UtpLayer, RecvReFiresDataAvailableCallbackWhenBytesRemain)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);

		int call_count = 0;
		layer.SetDataAvailableCallback([&call_count]() { ++call_count; });

		// Single OnRead delivers 8 bytes — first callback fires.
		const std::uint8_t data[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
		layer.OnRead(data, sizeof(data));
		ASSERT_EQUALS(1, call_count);

		// Recv 4 of 8 bytes — readBuf still has 4 → callback re-fires.
		std::uint8_t out[8] = {0};
		std::int64_t got = layer.Recv(out, 4);
		ASSERT_EQUALS((std::int64_t)4, got);
		ASSERT_EQUALS(2, call_count);

		// Recv remaining 4 — readBuf now empty → no callback fire.
		got = layer.Recv(out, 4);
		ASSERT_EQUALS((std::int64_t)4, got);
		ASSERT_EQUALS(2, call_count);

		// Recv on an empty buffer is also a no-op for the callback.
		got = layer.Recv(out, 4);
		ASSERT_EQUALS((std::int64_t)0, got);
		ASSERT_EQUALS(2, call_count);
	}

	utp_destroy(ctx);
}


// Bug #4 corollary: when no callback is installed, the residual-bytes
// path of Recv still drains correctly — the "fire if set" branch
// must not assume the callback is present.
TEST(UtpLayer, RecvWithoutCallbackHandlesResidualGracefully)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);
		// No SetDataAvailableCallback call — m_data_available_cb is NULL.

		const std::uint8_t data[] = { 0xA, 0xB, 0xC, 0xD };
		layer.OnRead(data, sizeof(data));

		std::uint8_t out[2] = {0};
		std::int64_t got = layer.Recv(out, 2);
		ASSERT_EQUALS((std::int64_t)2, got);
		ASSERT_EQUALS((std::size_t)2, layer.ReadBufferSize());
		// No crash from a NULL callback path — buffer is still drainable.
		got = layer.Recv(out, 2);
		ASSERT_EQUALS((std::int64_t)2, got);
		ASSERT_EQUALS((std::size_t)0, layer.ReadBufferSize());
	}

	utp_destroy(ctx);
}


// Phase E3: SetDataAvailableCallback(nullptr) detaches a previously
// registered callback — useful for teardown when the owning socket
// goes away before the layer (production: detach before deleting
// the socket so the layer can outlive briefly without dangling
// references).
TEST(UtpLayer, DataAvailableCallbackCanBeDetached)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);

		int call_count = 0;
		layer.SetDataAvailableCallback([&call_count]() { ++call_count; });

		const std::uint8_t chunk[] = { 'x','y','z' };
		layer.OnRead(chunk, sizeof(chunk));
		ASSERT_EQUALS(1, call_count);

		layer.SetDataAvailableCallback(nullptr);

		layer.OnRead(chunk, sizeof(chunk));
		ASSERT_EQUALS(1, call_count);
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


// OnGetReadBufferSize reports bytes-in-buffer (NOT free space).
// libutp's UTP_GET_READ_BUFFER_SIZE contract is "bytes currently
// queued in the app's receive buffer": libutp computes its own
// advertised window as max(0, opt_rcvbuf - returned_value) at
// utp_internal.cpp:595. Returning free-space here would make libutp
// treat a 64 KiB free buffer as if 64 KiB were already queued, and
// (post-Bug #6 always-copy) returning capacity - size() could
// underflow size_t once the soft cap is exceeded, hitting libutp's
// `(int)numbuf >= 0` assertion at utp_internal.cpp:594.
TEST(UtpLayer, OnGetReadBufferSizeReportsBytesInBuffer)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);
		ASSERT_EQUALS((std::size_t)0, layer.OnGetReadBufferSize());

		std::vector<std::uint8_t> data(1024, 0xEE);
		layer.OnRead(data.data(), data.size());
		ASSERT_EQUALS((std::size_t)1024, layer.OnGetReadBufferSize());

		layer.OnRead(data.data(), data.size());
		ASSERT_EQUALS((std::size_t)2048, layer.OnGetReadBufferSize());

		// Draining the app-side buffer shrinks the reported count.
		std::vector<std::uint8_t> out(512);
		std::int64_t got = layer.Recv(out.data(), out.size());
		ASSERT_EQUALS((std::int64_t)512, got);
		ASSERT_EQUALS((std::size_t)1536, layer.OnGetReadBufferSize());
	}

	utp_destroy(ctx);
}


// Bug #8 regression: ClampAdaptiveRcvBuf must clamp the kernel-reported
// SO_RCVBUF into [kUtpRecvBufferFloor, kUtpRecvBufferCeiling]. This is
// the policy that prevents libutp from advertising a receive window the
// kernel can't back (root cause of the LEDBAT CWND collapse seen in the
// 1 GiB soak — peer over-sent, kernel silently dropped, libutp read the
// missing ACKs as queueing delay and shrank CWND to zero permanently).
TEST(UtpLayer, ClampAdaptiveRcvBufFloorWhenKernelUnpublished)
{
	// SetUdpKernelRecvBufferBytes never called → returns 0 → floor.
	ASSERT_EQUALS(CUtpLayer::kUtpRecvBufferFloor,
	              CUtpLayer::ClampAdaptiveRcvBuf(0));
}

TEST(UtpLayer, ClampAdaptiveRcvBufFloorOnTinyKernelValue)
{
	// Stock Linux net.core.rmem_default is ~208 KiB, which sits
	// above the 64 KiB floor — but a misconfigured host with a
	// tiny default would still get the floor.
	ASSERT_EQUALS(CUtpLayer::kUtpRecvBufferFloor,
	              CUtpLayer::ClampAdaptiveRcvBuf(8 * 1024));
}

TEST(UtpLayer, ClampAdaptiveRcvBufPassesThroughTypicalLinuxDefault)
{
	// 208 KiB is between floor (64 KiB) and ceiling (4 MiB) →
	// passes through unchanged.
	const std::size_t k208KiB = 208 * 1024;
	ASSERT_EQUALS(k208KiB, CUtpLayer::ClampAdaptiveRcvBuf(k208KiB));
}

TEST(UtpLayer, ClampAdaptiveRcvBufCeilingOnSysctlTunedHost)
{
	// A host with net.core.rmem_max bumped to 16 MiB still gets
	// capped at 4 MiB — beyond that, the per-connection memory
	// cost outweighs the throughput benefit on aMule's typical
	// "handful of NAT-T peers" workload.
	const std::size_t k16MiB = 16 * 1024 * 1024;
	ASSERT_EQUALS(CUtpLayer::kUtpRecvBufferCeiling,
	              CUtpLayer::ClampAdaptiveRcvBuf(k16MiB));
}

TEST(UtpLayer, ClampAdaptiveRcvBufBoundaryExact)
{
	// Exact floor and exact ceiling pass through unchanged
	// (clamp is inclusive on both ends).
	ASSERT_EQUALS(CUtpLayer::kUtpRecvBufferFloor,
	              CUtpLayer::ClampAdaptiveRcvBuf(CUtpLayer::kUtpRecvBufferFloor));
	ASSERT_EQUALS(CUtpLayer::kUtpRecvBufferCeiling,
	              CUtpLayer::ClampAdaptiveRcvBuf(CUtpLayer::kUtpRecvBufferCeiling));
}


// UdpReceiveBufferStat — the shared atomic that LibSocketAsio's
// CreateSocket publishes the kernel's actual SO_RCVBUF readback through,
// for CUtpLayer to consume in ApplySocketBuffersLocked. Verifies the
// trivial set/get round-trip and the "never set" → 0 contract.
TEST(UtpLayer, UdpReceiveBufferStatRoundTrip)
{
	const std::size_t kProbe = 1234567u;
	SetUdpKernelRecvBufferBytes(kProbe);
	ASSERT_EQUALS(kProbe, GetUdpKernelRecvBufferBytes());
	// Overwrite — last write wins.
	SetUdpKernelRecvBufferBytes(0);
	ASSERT_EQUALS((std::size_t)0, GetUdpKernelRecvBufferBytes());
}


// Bug #6 regression: OnRead must copy every byte even when the
// resulting buffer would exceed kReadBufferCapacity. libutp's
// on_read pointer is ephemeral (utp_internal.cpp:2351) — silently
// dropping bytes there causes an eD2k stream desync the OP_*
// parser observes as ERR_TOOBIG. Flow control is enforced *via*
// OnGetReadBufferSize (which causes the peer to advertise window=0),
// not via dropping at the boundary.
TEST(UtpLayer, OnReadAlwaysCopiesEvenPastSoftCap)
{
	utp_context* ctx = utp_init(2);
	ASSERT_TRUE(ctx != NULL);

	{
		CUtpLayer layer(ctx);

		// Fill the buffer right up to the soft cap.
		std::vector<std::uint8_t> at_cap(CUtpLayer::kReadBufferCapacity, 0xAA);
		layer.OnRead(at_cap.data(), at_cap.size());
		ASSERT_EQUALS(CUtpLayer::kReadBufferCapacity, layer.ReadBufferSize());

		// One more delivery past the cap — must still be copied.
		const std::size_t kOver = 16 * 1024;
		std::vector<std::uint8_t> over(kOver, 0xBB);
		layer.OnRead(over.data(), over.size());
		ASSERT_EQUALS(CUtpLayer::kReadBufferCapacity + kOver,
		              layer.ReadBufferSize());

		// And OnGetReadBufferSize must NOT underflow.
		ASSERT_EQUALS(CUtpLayer::kReadBufferCapacity + kOver,
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
