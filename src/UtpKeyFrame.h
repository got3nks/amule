//								-*- C++ -*-
// This file is part of the aMule Project.
//
// Copyright (c) 2026 aMule Team ( admin@amule.org / http://www.amule.org )
//
// Any parts of this program derived from eMuleAI (originally by David
// Xanatos / NeoLoader and the eMule AI project) are licensed GPLv2+,
// compatible with aMule's own GPLv2+ terms.
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

#ifndef UTPKEYFRAME_H
#define UTPKEYFRAME_H

#include <cstddef>
#include <cstdint>

// Phase B4 of the NAT-T port (see .archive/eMuleAI-nat-t-implementation-plan.md
// cluster 6, sub-commit B4). Key Frame is the one-time-per-session
// envelope that bootstraps the per-peer encryption key for NAT-T uTP
// traffic. It's the very first packet a NAT-T initiator sends, before
// any utp_connect, and it carries the sender's user hash so the
// receiver can derive the symmetric key for the EncryptedDatagramSocket
// wrapper used by all subsequent uTP frames.
//
// Wire layout (plaintext, pre-encryption):
//
//   offset  size  field
//        0     1  OP_UDPRESERVEDPROT2 = 0xB2 (eD2k UDP reserved opcode 2)
//        1     1  sub-byte = 0xFF             (Key Frame discriminator)
//        2    16  sender's user hash          (CMD4Hash, 16 bytes)
//   -----  ----  ---------------
//   total   18 bytes
//
// In production (Phase B5+), the 16-byte hash payload is then wrapped
// by EncryptedDatagramSocket using the receiver's user hash as the
// symmetric key — that's how the bootstrap chicken-and-egg is resolved
// without a plaintext path. The Kad search results that produced the
// peer's IP/port also include the peer's user hash, so the sender
// always knows the receiver's hash before the first Key Frame goes
// out. This module covers the plaintext envelope only; encryption
// wrapping is layered on top in B5 by routing the output of EncodePlain
// through EncryptedDatagramSocket::EncryptSendClient before the UDP
// send (and inverse on the receive side, before ParsePlain).
//
// Pure functions, no allocations, no dependence on libutp.
// `op_byte_value` is the value of `protocol/Protocols.h`'s
// OP_UDPRESERVEDPROT2 constant — kept as a local literal here rather
// than including Protocols.h so the test target stays independent of
// the eD2k include tree.

namespace UtpKeyFrame {

// Wire constants. These are protocol contract — changing any of them
// breaks interop with eMuleAI.
static constexpr std::uint8_t  kOpByte             = 0xB2; // OP_UDPRESERVEDPROT2
static constexpr std::uint8_t  kSubByte            = 0xFF; // Key Frame
static constexpr std::uint8_t  kUtpFrameSubByte    = 0x00; // uTP frame envelope
static constexpr std::size_t   kUserHashSize       = 16;   // CMD4Hash bytes
static constexpr std::size_t   kPlainEnvelopeSize  = 1 + 1 + kUserHashSize; // 18

// Encode a plaintext Key Frame: writes [kOpByte, kSubByte, hash...] into
// `out`. On success returns true and *out_len is set to kPlainEnvelopeSize.
//
//   sender_hash:  the sender's 16-byte user hash to advertise. Must
//                 not be NULL.
//   out:          destination buffer. Must not be NULL.
//   out_capacity: must be >= kPlainEnvelopeSize, otherwise this is a
//                 no-op and returns false.
//   out_len:      may be NULL if the caller doesn't care; otherwise
//                 receives the number of bytes written.
//
// Returns false on a NULL argument or insufficient capacity.
bool EncodePlain(const std::uint8_t sender_hash[kUserHashSize],
                 std::uint8_t* out, std::size_t out_capacity,
                 std::size_t* out_len);

// Parse a plaintext Key Frame: validates `buf` is exactly the
// kOpByte / kSubByte / 16-byte hash shape and copies the hash out.
//
//   buf, len:           the bytes received. `len` must be >= kPlainEnvelopeSize;
//                       trailing bytes are ignored (defensive — the caller
//                       may pass a UDP datagram with extra padding).
//   sender_hash_out:    destination for the parsed hash. Must not be NULL.
//
// Returns true iff buf starts with the correct opcode + sub-byte.
// On false return, sender_hash_out is left untouched.
bool ParsePlain(const std::uint8_t* buf, std::size_t len,
                std::uint8_t sender_hash_out[kUserHashSize]);

} // namespace UtpKeyFrame

#endif // UTPKEYFRAME_H
