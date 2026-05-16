//                              -*- C++ -*-
// This file is part of the aMule Project.
//
// Copyright (c) 2026 aMule Team ( admin@amule.org / http://www.amule.org )
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//

#ifndef UDP_RECEIVE_BUFFER_STAT_H
#define UDP_RECEIVE_BUFFER_STAT_H

#include <cstddef>

// Tiny shared module that publishes the kernel-allocated SO_RCVBUF (in
// bytes) of aMule's UDP socket.
//
// Producer: CAsioUDPSocketImpl::CreateSocket calls SetUdpKernelRecvBufferBytes
// after binding + setsockopt(SO_RCVBUF) + getsockopt readback.
//
// Consumer: CUtpLayer::ApplySocketBuffersLocked reads it via
// GetUdpKernelRecvBufferBytes to size libutp's per-connection UTP_RCVBUF
// adaptively. Over-advertising a receive window the kernel can't back
// is the root cause of LEDBAT-driven CWND collapse at default Linux
// sysctl values; matching libutp's window to the actual kernel buffer
// is what libtorrent / qBittorrent do.
//
// Lives in its own translation unit (not LibSocketAsio.cpp) so the unit
// tests for CUtpLayer can link the consumer side without pulling in
// boost::asio. Returns 0 when no UDP socket has been created yet, which
// CUtpLayer interprets as "use the floor" (64 KiB).

void        SetUdpKernelRecvBufferBytes(std::size_t bytes);
std::size_t GetUdpKernelRecvBufferBytes();

#endif // UDP_RECEIVE_BUFFER_STAT_H
