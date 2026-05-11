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

#include "UtpEncryption.h"

#ifdef ENABLE_NAT_T

#include "UtpKeyFrame.h"

namespace UtpEncryption {

namespace {

// Per-process delegate slots. Set/read concurrency: both delegates
// are set once at startup, before any libutp traffic begins, and
// read from any thread that calls Wrap/Unwrap. No locking is added
// here because the only "real" set call lives in
// InstallProductionDelegates (single call, single thread); tests
// install their own delegates serially with no in-flight traffic.
EncryptFn g_encrypt_fn = NULL;
DecryptFn g_decrypt_fn = NULL;

} // anonymous namespace

void SetEncryptDelegate(EncryptFn fn)
{
	g_encrypt_fn = fn;
}

void SetDecryptDelegate(DecryptFn fn)
{
	g_decrypt_fn = fn;
}

bool WrapKeyFrame(const std::uint8_t sender_hash[kUserHashSize],
                  const std::uint8_t receiver_hash[kUserHashSize],
                  std::vector<std::uint8_t>& out)
{
	if (sender_hash == NULL || receiver_hash == NULL ||
	    g_encrypt_fn == NULL) {
		return false;
	}

	// Encrypt the 16-byte sender hash using receiver_hash as the key.
	std::vector<std::uint8_t> ciphertext;
	if (!g_encrypt_fn(sender_hash, kUserHashSize, receiver_hash, ciphertext)) {
		return false;
	}

	// Prepend the [0xB2, 0xFF] preamble. UtpKeyFrame::kOpByte and
	// kSubByte are the single source of truth for these wire constants.
	out.clear();
	out.reserve(2 + ciphertext.size());
	out.push_back(UtpKeyFrame::kOpByte);
	out.push_back(UtpKeyFrame::kSubByte);
	out.insert(out.end(), ciphertext.begin(), ciphertext.end());
	return true;
}

bool UnwrapKeyFrame(const std::uint8_t* buf, std::size_t len,
                    std::uint32_t source_ip,
                    std::uint8_t sender_hash_out[kUserHashSize])
{
	if (buf == NULL || sender_hash_out == NULL || g_decrypt_fn == NULL) {
		return false;
	}
	// Need at least the 2-byte preamble; an empty ciphertext can't
	// decrypt to a 16-byte hash, so a stricter minimum check is
	// applied after the preamble.
	if (len < 2) {
		return false;
	}
	if (buf[0] != UtpKeyFrame::kOpByte || buf[1] != UtpKeyFrame::kSubByte) {
		return false;
	}

	std::vector<std::uint8_t> plaintext;
	if (!g_decrypt_fn(buf + 2, len - 2, source_ip, plaintext)) {
		return false;
	}

	// The decrypted payload must be exactly the user hash size.
	// Anything shorter or longer is a malformed Key Frame. (A real
	// eMuleAI peer always produces exactly this layout; rejecting
	// other shapes protects against future protocol drift.)
	if (plaintext.size() != kUserHashSize) {
		return false;
	}

	for (std::size_t i = 0; i < kUserHashSize; ++i) {
		sender_hash_out[i] = plaintext[i];
	}
	return true;
}

} // namespace UtpEncryption

#endif // ENABLE_NAT_T
