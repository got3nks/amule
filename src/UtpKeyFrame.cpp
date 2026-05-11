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

#include "UtpKeyFrame.h"

#include <cstring>

namespace UtpKeyFrame {

bool EncodePlain(const std::uint8_t sender_hash[kUserHashSize],
                 std::uint8_t* out, std::size_t out_capacity,
                 std::size_t* out_len)
{
	if (sender_hash == nullptr || out == nullptr ||
	    out_capacity < kPlainEnvelopeSize) {
		return false;
	}

	out[0] = kOpByte;
	out[1] = kSubByte;
	std::memcpy(out + 2, sender_hash, kUserHashSize);

	if (out_len != nullptr) {
		*out_len = kPlainEnvelopeSize;
	}
	return true;
}

bool ParsePlain(const std::uint8_t* buf, std::size_t len,
                std::uint8_t sender_hash_out[kUserHashSize])
{
	if (buf == nullptr || sender_hash_out == nullptr ||
	    len < kPlainEnvelopeSize) {
		return false;
	}
	if (buf[0] != kOpByte || buf[1] != kSubByte) {
		return false;
	}

	std::memcpy(sender_hash_out, buf + 2, kUserHashSize);
	return true;
}

} // namespace UtpKeyFrame
