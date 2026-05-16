//
// This file is part of the aMule Project.
//
// Copyright (c) 2026 aMule Team ( admin@amule.org / http://www.amule.org )
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//

#include "UdpReceiveBufferStat.h"

#include <atomic>

namespace {
// Module-scope atomic so the producer (asio I/O thread, on socket
// (re)create) and the consumer (libutp callback / Tick thread) don't
// need to coordinate via a lock for this single-value read/write.
std::atomic<std::size_t> g_udp_kernel_rcvbuf{0};
} // namespace

void SetUdpKernelRecvBufferBytes(std::size_t bytes)
{
	g_udp_kernel_rcvbuf.store(bytes, std::memory_order_relaxed);
}

std::size_t GetUdpKernelRecvBufferBytes()
{
	return g_udp_kernel_rcvbuf.load(std::memory_order_relaxed);
}
