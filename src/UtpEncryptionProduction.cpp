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
#include "amule.h"

#include <cstring>

namespace {

// Outbound: opportunistic-encrypt `plaintext_len` bytes using `key`
// (the recipient's user hash) via EncryptSendClient. Mirrors
// eMuleAI's gate at ClientUDPSocket.cpp:2092 and aMule's own existing
// eD2k UDP posture at MuleUDPSocket.cpp:277: encrypt only when our
// public IP is known (kad=false ed2k-keyed obfuscation depends on
// sender's public IP in the MD5 key derivation; with publicIP==0 the
// receiver's decrypt MD5 would mismatch and reject the frame). When
// publicIP==0, fall through to plaintext — the receiver's
// DecryptReceivedClient passthroughs `0xB2`-prefixed packets, and the
// inner libutp bytes start with a uTP type/version byte that is never
// a recognized eD2k opcode, so the inner DecryptReceivedClient call
// returns rc == ciphertext_len which production_decrypt now treats as
// a valid plaintext signal.
//
// EncryptSendClient takes ownership of the input buffer (does
// `delete[] *buf` internally — see EncryptedDatagramSocket.cpp:370)
// and returns a new heap buffer in *buf; the thunk copies that out
// into the caller's std::vector and frees the new buffer.
bool production_encrypt(const std::uint8_t* plaintext,
                        std::size_t plaintext_len,
                        const std::uint8_t key[UtpEncryption::kUserHashSize],
                        std::vector<std::uint8_t>& out)
{
	if (plaintext == NULL || plaintext_len == 0 || key == NULL) {
		return false;
	}

	// ignorelocal=true: m_localip (e.g. 127.0.1.1 from /etc/hosts) is never a key the peer can reproduce.
	const uint32_t public_ip = (theApp != NULL) ? theApp->GetPublicIP(true) : 0;
	{
		static int log_count = 0;
		if (log_count < 6) {
			log_count++;
		}
	}
	if (public_ip == 0) {
		// Plaintext fallback: copy bytes verbatim. The caller's
		// envelope ([0xB2, sub-byte, ...]) is added on top of this
		// output; on receive, DecryptReceivedClient sees the outer
		// 0xB2 and passthroughs, ClientUDPSocket's OP_UDPRESERVEDPROT2
		// dispatch reads the sub-byte and calls UnwrapUtp/KeyFrame
		// with the inner bytes; production_decrypt then sees the
		// inner-DecryptReceivedClient passthrough (rc == clen) and
		// hands the plaintext up.
		out.assign(plaintext, plaintext + plaintext_len);
		return true;
	}

	// Make a heap-allocated input copy with the layout EncryptSendClient
	// expects (it will delete[] this pointer internally).
	std::uint8_t* input_buf = new std::uint8_t[plaintext_len];
	std::memcpy(input_buf, plaintext, plaintext_len);

	// After this call, input_buf points to a new heap-allocated
	// ciphertext buffer; the original input bytes have been deleted
	// by the function. kad=false → ed2k-style encryption keyed on
	// the recipient's user hash + sender's public IP.
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

// Inbound: opportunistic-decrypt `ciphertext_len` bytes via
// DecryptReceivedClient. Mirrors eMuleAI's receive-side behavior:
// accept BOTH encrypted (rc < clen, MD5/RC4 decrypt succeeded against
// our user hash + sender's IP) and plaintext (rc == clen, sender
// emitted unencrypted because its publicIP was 0 at send time).
//
// The plaintext path is safe because the caller (UnwrapUtpFrame /
// UnwrapKeyFrame) has already validated the outer [0xB2, sub-byte]
// preamble. The inner libutp bytes start with a uTP type/version byte
// (e.g. 0x41 for ST_SYN) that is never a recognized eD2k opcode, so
// DecryptReceivedClient's first-byte switch (lines 140-150) skips the
// passthrough-by-opcode shortcut and goes into the decrypt loop;
// failing to find the magic value, it returns bufLen and *bufOut =
// bufIn — exactly the bytes the sender wrote. If a peer genuinely
// encrypted with a key we don't share, the same return path yields
// RC4-garbled bytes that libutp will reject downstream, so the
// downgrade is benign (no false accept of unauthenticated traffic).
//
// DecryptReceivedClient does NOT take ownership of its input buffer;
// it sets *bufOut to a pointer inside bufIn (past the header for the
// encrypted case, equal to bufIn for the plaintext case) and decrypts
// in-place. We pass a working copy of the ciphertext so the in-place
// decryption doesn't disturb the caller's input.
bool production_decrypt(const std::uint8_t* ciphertext,
                        std::size_t ciphertext_len,
                        std::uint32_t source_ip,
                        std::vector<std::uint8_t>& out)
{
	if (ciphertext == NULL || ciphertext_len == 0) {
		return false;
	}
	{
		static int log_count = 0;
		if (log_count < 6) {
			log_count++;
			const uint32_t my_publicIP = (theApp != NULL) ? theApp->GetPublicIP() : 0;
		}
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

	{
		static int dec_log_count = 0;
		if (dec_log_count < 6) {
			dec_log_count++;
		}
	}
	if (rc <= 0 || buf_out_ptr == NULL) {
		return false;
	}

	// rc < clen → DecryptReceivedClient succeeded; *bufOut points
	// past the obfuscation header (CRYPT_HEADER_WITHOUTPADDING +
	// padding) into the decrypted payload.
	//
	// rc == clen → either (a) the sender emitted plaintext (their
	// publicIP was 0, opportunistic encryption skipped) or (b)
	// encryption was attempted but the MD5 magic value didn't match
	// (wrong key, corruption). Both yield *bufOut == working_copy
	// data unchanged. We accept either; libutp validates the inner
	// packet shape and rejects garbage in case (b).
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
