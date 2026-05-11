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

// Production thunks for UtpEncryption: live in a separate TU from
// UtpEncryption.cpp because they call into
// CEncryptedDatagramSocket::EncryptSendClient /
// DecryptReceivedClient, both of which reach into theApp / thePrefs /
// theStats globals. Pulling those symbols into the unit-test link is
// inconvenient (a real CamuleApp needs DB / wx / curl etc. to be
// initialised), so the framework + tests link only UtpEncryption.cpp
// and these thunks stay in CORE_SOURCES (built only when ENABLE_NAT_T
// + a full daemon build are both on).

#include "EncryptedDatagramSocket.h"

#include <cstring>

namespace {

// Outbound: encrypt `plaintext_len` bytes using `key` (the recipient's
// user hash) via EncryptSendClient. EncryptSendClient takes ownership
// of the input buffer (does `delete[] *buf` internally — see
// EncryptedDatagramSocket.cpp:370) and returns a new heap buffer in
// *buf; the thunk copies that out into the caller's std::vector and
// frees the new buffer.
bool production_encrypt(const std::uint8_t* plaintext,
                        std::size_t plaintext_len,
                        const std::uint8_t key[UtpEncryption::kUserHashSize],
                        std::vector<std::uint8_t>& out)
{
	if (plaintext == NULL || plaintext_len == 0 || key == NULL) {
		return false;
	}

	// Make a heap-allocated input copy with the layout EncryptSendClient
	// expects (it will delete[] this pointer internally).
	std::uint8_t* input_buf = new std::uint8_t[plaintext_len];
	std::memcpy(input_buf, plaintext, plaintext_len);

	// After this call, input_buf points to a new heap-allocated
	// ciphertext buffer; the original input bytes have been deleted
	// by the function. kad=false → ed2k-style encryption keyed on
	// the recipient's user hash.
	int rc = CEncryptedDatagramSocket::EncryptSendClient(
		&input_buf,
		static_cast<int>(plaintext_len),
		key,
		false,    // kad
		0,        // receiverVerifyKey (kad-only; unused for ed2k)
		0);       // senderVerifyKey   (kad-only; unused for ed2k)

	if (rc <= 0 || input_buf == NULL) {
		delete[] input_buf;
		return false;
	}

	out.assign(input_buf, input_buf + rc);
	delete[] input_buf;
	return true;
}

// Inbound: decrypt `ciphertext_len` bytes via DecryptReceivedClient.
// DecryptReceivedClient does NOT take ownership of its input buffer;
// it sets *bufOut to a pointer inside bufIn (past the header) and
// decrypts in-place. We pass a working copy of the ciphertext so the
// in-place decryption doesn't disturb the caller's input.
bool production_decrypt(const std::uint8_t* ciphertext,
                        std::size_t ciphertext_len,
                        std::uint32_t source_ip,
                        std::vector<std::uint8_t>& out)
{
	if (ciphertext == NULL || ciphertext_len == 0) {
		return false;
	}

	std::vector<std::uint8_t> working_copy(ciphertext, ciphertext + ciphertext_len);
	std::uint8_t* buf_out_ptr = NULL;
	std::uint32_t receiver_verify_key = 0;
	std::uint32_t sender_verify_key   = 0;

	int rc = CEncryptedDatagramSocket::DecryptReceivedClient(
		working_copy.data(),
		static_cast<int>(working_copy.size()),
		&buf_out_ptr,
		source_ip,
		&receiver_verify_key,
		&sender_verify_key);

	if (rc <= 0 || buf_out_ptr == NULL) {
		return false;
	}
	// rc == ciphertext_len means the buffer was passed through
	// (DecryptReceivedClient's "not encrypted" path — happens if
	// the first byte happens to be one of the eD2k opcodes). For our
	// inner ciphertext that's a malformed-packet signal; reject.
	if (static_cast<std::size_t>(rc) == ciphertext_len) {
		return false;
	}

	out.assign(buf_out_ptr, buf_out_ptr + rc);
	return true;
}

} // anonymous namespace

namespace UtpEncryption {

void InstallProductionDelegates()
{
	SetEncryptDelegate(&production_encrypt);
	SetDecryptDelegate(&production_decrypt);
}

} // namespace UtpEncryption

#endif // ENABLE_NAT_T
