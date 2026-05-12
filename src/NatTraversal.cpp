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

// Phase C3 stub. Phase D's rendezvous coordinator owns the actual
// Kad search and the SupportsNatTraversal filter. Leaving this empty
// for now means the coordinator (when it arrives) has a clean
// surface to fill in; today, no callers exist outside future tests.
bool FindRendezvousCandidates(const std::uint8_t* /*target_user_hash*/,
                              std::size_t /*max_candidates*/,
                              std::vector<RendezvousCandidate>& out)
{
	out.clear();
	return false;
}

// --- Phase E6 wire helpers -----------------------------------------

bool IsRequesterCallbackNullMarker(const std::uint8_t* buf_at_offset_16,
                                   std::size_t remaining_len)
{
	if (buf_at_offset_16 == nullptr || remaining_len < kUserHashSize) {
		return false;
	}
	for (std::size_t i = 0; i < kUserHashSize; ++i) {
		if (buf_at_offset_16[i] != 0) {
			return false;
		}
	}
	return true;
}

bool EncodeRequesterCallbackPayload(const RequesterCallbackPayload& payload,
                                    std::vector<std::uint8_t>& out)
{
	out.clear();
	// Worst-case length: 50 (mandatory) + 16 (file hash) + 6 (ext endpoint) = 72.
	out.reserve(72);

	// bytes 0-15: target's serving buddy KadID
	out.insert(out.end(),
	           payload.target_buddy_kadid,
	           payload.target_buddy_kadid + kUserHashSize);

	// bytes 16-31: NAT-T null marker (16 zero bytes). The presence
	// of this all-zero block is what disambiguates this payload from
	// the file-reask variant (which has a real file hash here).
	out.insert(out.end(), kUserHashSize, std::uint8_t{0});

	// byte 32: OP_RENDEZVOUS sub-marker
	out.push_back(OP_RENDEZVOUS_OPCODE);

	// bytes 33-48: requester user hash
	out.insert(out.end(),
	           payload.requester_user_hash,
	           payload.requester_user_hash + kUserHashSize);

	// byte 49: connect_options
	out.push_back(payload.connect_options);

	// Optional file hash (bytes 50-65). When neither file hash nor
	// ext endpoint is present, the payload ends at 50 bytes.
	if (payload.has_file_hash) {
		out.insert(out.end(),
		           payload.target_file_hash,
		           payload.target_file_hash + kUserHashSize);
	}

	// Optional ext endpoint (6 bytes, little-endian IP + port). If we
	// want to emit ext_endpoint but NO file_hash, we still emit
	// directly here — the decoder uses the trailing-length math to
	// distinguish "has ext only" (56 bytes) from "has file only"
	// (66 bytes) from "has both" (72 bytes).
	if (payload.has_ext_endpoint) {
		AppendUInt32LE(out, payload.requester_ext_ip);
		AppendUInt16LE(out, payload.requester_ext_port);
	}

	return true;
}

bool DecodeRequesterCallbackPayload(const std::uint8_t* buf, std::size_t len,
                                    bool is_post_forward,
                                    RequesterCallbackPayload& out)
{
	if (buf == nullptr) {
		return false;
	}

	// Default the output struct so optional fields are clean.
	std::memset(out.target_buddy_kadid, 0, kUserHashSize);
	std::memset(out.requester_user_hash, 0, kUserHashSize);
	out.connect_options = 0;
	out.has_file_hash = false;
	std::memset(out.target_file_hash, 0, kUserHashSize);
	out.has_ext_endpoint = false;
	out.requester_ext_ip = 0;
	out.requester_ext_port = 0;

	std::size_t pos = 0;

	if (!is_post_forward) {
		// Pre-forward (requester→buddy): payload starts with the
		// target's serving buddy KadID at offset 0.
		if (len < kRequesterCallbackMinSize) {
			return false;
		}
		std::memcpy(out.target_buddy_kadid, buf, kUserHashSize);
		pos = kUserHashSize;
	}
	// is_post_forward case: the buddy stripped the leading 16-byte
	// KadID + replaced the next 6 bytes with [destIP:4][destPort:2]
	// (or 22-byte v6 header). For NAT-T detection we want to look at
	// the null marker which the buddy preserves at offset 0 of the
	// post-forward payload (because the original null marker at
	// pre-forward offset 16 maps to post-forward offset 0 after the
	// buddy's 16-byte strip… wait that overlaps with the 6-byte
	// destIP/Port the buddy wrote). See E6c notes for the resolution.
	//
	// For now, the post-forward path goes through ClientTCPSocket's
	// dispatcher which calls us with `is_post_forward=true` AFTER the
	// 6-byte [destIP][destPort] prefix has been consumed by the
	// caller. So at entry, `buf` points at the null marker.

	// bytes 16-31 (pre) or 0-15 (post): null marker. If non-zero,
	// this is NOT a NAT-T payload — caller should fall through to
	// the file-reask path.
	if (len - pos < kUserHashSize) {
		return false;
	}
	if (!IsRequesterCallbackNullMarker(buf + pos, len - pos)) {
		return false;
	}
	pos += kUserHashSize;

	// 1 byte: OP_RENDEZVOUS sub-marker. Sanity check it's actually
	// 0xA0 — anything else is some other protocol we don't speak.
	if (len - pos < 1) {
		return false;
	}
	if (buf[pos] != OP_RENDEZVOUS_OPCODE) {
		return false;
	}
	pos += 1;

	// 16 bytes: requester user hash.
	if (len - pos < kUserHashSize) {
		return false;
	}
	std::memcpy(out.requester_user_hash, buf + pos, kUserHashSize);
	pos += kUserHashSize;

	// 1 byte: connect_options.
	if (len - pos < 1) {
		return false;
	}
	out.connect_options = buf[pos];
	pos += 1;

	// Trailing optional fields: file_hash (16) and ext_endpoint (6).
	// Possibilities by remaining length: 0 (mandatory only), 6 (ext
	// only — file hash slot omitted by eMuleAI when none available),
	// 16 (file only), 22 (file + ext). Match against these patterns;
	// anything else is malformed.
	const std::size_t remaining = len - pos;
	if (remaining == 0) {
		// Mandatory-only payload. Done.
	} else if (remaining == 6) {
		out.has_ext_endpoint   = true;
		out.requester_ext_ip   = ReadUInt32LE(buf + pos);
		out.requester_ext_port = ReadUInt16LE(buf + pos + 4);
	} else if (remaining == kUserHashSize) {
		out.has_file_hash = true;
		std::memcpy(out.target_file_hash, buf + pos, kUserHashSize);
	} else if (remaining == kUserHashSize + 6) {
		out.has_file_hash = true;
		std::memcpy(out.target_file_hash, buf + pos, kUserHashSize);
		pos += kUserHashSize;
		out.has_ext_endpoint   = true;
		out.requester_ext_ip   = ReadUInt32LE(buf + pos);
		out.requester_ext_port = ReadUInt16LE(buf + pos + 4);
	}
	// Trailing-bytes pattern that doesn't match any known shape is
	// silently tolerated — we keep the mandatory fields and ignore
	// the tail (UDP padding behavior consistent with DecodeRendezvous).

	return true;
}

} // namespace NatTraversal
