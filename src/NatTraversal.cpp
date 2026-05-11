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

#include "NatTraversal.h"

#include <cstring>

namespace NatTraversal {

namespace {

// Helper: append a little-endian uint32 to the output buffer. eMule
// wire format is always little-endian; matches CFile::WriteUInt32.
inline void AppendUInt32LE(std::vector<std::uint8_t>& out, std::uint32_t v)
{
	out.push_back(static_cast<std::uint8_t>( v        & 0xFF));
	out.push_back(static_cast<std::uint8_t>((v >>  8) & 0xFF));
	out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
	out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}

inline void AppendUInt16LE(std::vector<std::uint8_t>& out, std::uint16_t v)
{
	out.push_back(static_cast<std::uint8_t>( v        & 0xFF));
	out.push_back(static_cast<std::uint8_t>((v >>  8) & 0xFF));
}

inline std::uint32_t ReadUInt32LE(const std::uint8_t* p)
{
	return static_cast<std::uint32_t>(p[0])
	     | (static_cast<std::uint32_t>(p[1]) <<  8)
	     | (static_cast<std::uint32_t>(p[2]) << 16)
	     | (static_cast<std::uint32_t>(p[3]) << 24);
}

inline std::uint16_t ReadUInt16LE(const std::uint8_t* p)
{
	return static_cast<std::uint16_t>(p[0])
	     | (static_cast<std::uint16_t>(p[1]) << 8);
}

} // anonymous namespace

bool EncodeRendezvous(const RendezvousRequest& req,
                      std::vector<std::uint8_t>& out)
{
	out.clear();
	// Worst-case length is kRendezvousBodyFull (39). Pre-reserve
	// to avoid reallocation in the common case.
	out.reserve(kRendezvousBodyFull);

	// Mandatory: target_user_hash + connect_options.
	out.insert(out.end(),
	           req.target_user_hash,
	           req.target_user_hash + kUserHashSize);
	out.push_back(req.connect_options);

	// Optional: file_hash. If the caller wants to emit ext_endpoint
	// but no file_hash, we still need to write a 16-byte placeholder
	// so the parser's positional decode finds the ext fields where
	// expected — eMuleAI uses a zero CMD4Hash for this.
	const bool need_file_hash_slot = req.has_file_hash || req.has_ext_endpoint;
	if (need_file_hash_slot) {
		if (req.has_file_hash) {
			out.insert(out.end(),
			           req.target_file_hash,
			           req.target_file_hash + kUserHashSize);
		} else {
			// Zero placeholder so the parser correctly attributes
			// the next 6 bytes to ext_endpoint, not to file_hash.
			out.insert(out.end(), kUserHashSize, std::uint8_t{0});
		}
	}

	if (req.has_ext_endpoint) {
		AppendUInt32LE(out, req.requester_ext_ip);
		AppendUInt16LE(out, req.requester_ext_port);
	}

	return true;
}

bool DecodeRendezvous(const std::uint8_t* buf, std::size_t len,
                      RendezvousRequest& out)
{
	if (buf == nullptr || len < kRendezvousBodyMin) {
		return false;
	}

	// Initialise the output to a known-clean state so optional
	// fields don't return uninitialised data if the caller forgets
	// to check the has_* flags.
	std::memset(out.target_user_hash, 0, kUserHashSize);
	out.connect_options = 0;
	out.has_file_hash = false;
	std::memset(out.target_file_hash, 0, kUserHashSize);
	out.has_ext_endpoint = false;
	out.requester_ext_ip = 0;
	out.requester_ext_port = 0;

	std::size_t pos = 0;
	std::memcpy(out.target_user_hash, buf + pos, kUserHashSize);
	pos += kUserHashSize;
	out.connect_options = buf[pos];
	pos += 1;

	// Optional file_hash: 16 bytes. eMuleAI's check at
	// ClientUDPSocket.cpp:931 is "remaining >= 16 → read file hash".
	if (len - pos >= kUserHashSize) {
		out.has_file_hash = true;
		std::memcpy(out.target_file_hash, buf + pos, kUserHashSize);
		pos += kUserHashSize;
	}

	// Optional ext_endpoint: 6 bytes (4 + 2). eMuleAI's check at
	// ClientUDPSocket.cpp:952 is "remaining >= 6 → read".
	if (len - pos >= 6) {
		out.has_ext_endpoint = true;
		out.requester_ext_ip   = ReadUInt32LE(buf + pos);
		out.requester_ext_port = ReadUInt16LE(buf + pos + 4);
		pos += 6;
	}

	// Trailing bytes (UDP padding etc.) are silently ignored.
	return true;
}

bool EncodeHolePunch(std::vector<std::uint8_t>& out)
{
	out.clear();
	return true;
}

bool DecodeHolePunch(const std::uint8_t* buf, std::size_t /*len*/)
{
	// Even with no body, the buf pointer is allowed to be NULL —
	// caller may legitimately pass a (NULL, 0) pair when reporting a
	// zero-byte body. So we don't reject on NULL buf here. The only
	// failure mode for HOLEPUNCH at this layer would be a future
	// version that adds payload validation; today, everything goes.
	(void)buf;
	return true;
}

} // namespace NatTraversal
