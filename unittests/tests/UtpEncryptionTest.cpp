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

// Tests for Phase B5 of the NAT-T port — the encryption wrapping for
// the OP_UDPRESERVEDPROT2 envelope.
//
// These tests deliberately do NOT exercise CEncryptedDatagramSocket's
// real RC4 path: that function reaches into theApp / thePrefs /
// theStats globals which a unit-test binary doesn't have. Instead,
// the test installs lightweight encrypt/decrypt delegate functions
// (XOR-stream and identity) that satisfy the roundtrip property,
// and verifies that:
//
//   1. WrapKeyFrame correctly prepends [0xB2, 0xFF] before the
//      ciphertext the encrypt delegate produced.
//   2. WrapKeyFrame passes the right plaintext (sender_hash) and
//      key (receiver_hash) to the encrypt delegate.
//   3. UnwrapKeyFrame correctly validates the preamble and strips it
//      before calling the decrypt delegate.
//   4. UnwrapKeyFrame returns false on every malformed-envelope path.
//   5. The full encrypt-then-decrypt roundtrip recovers the sender
//      hash byte-for-byte when the delegates are inverses of each
//      other.
//
// The end-to-end "real RC4 encryption" path is the responsibility of
// B8's loopback integration test (which can stand up a real amuled
// environment).

#include <muleunit/test.h>

#include "UtpEncryption.h"

#ifdef ENABLE_NAT_T

#include <cstring>
#include <vector>

using namespace muleunit;

DECLARE(UtpEncryption)
END_DECLARE;


namespace {

// Captured arguments from the most recent mock encrypt/decrypt call,
// so tests can assert what was passed in. Reset at the top of each
// test via mock_reset().
struct Capture {
	std::vector<std::uint8_t> encrypt_plaintext;
	std::vector<std::uint8_t> encrypt_key;
	std::vector<std::uint8_t> decrypt_ciphertext;
	std::uint32_t             decrypt_source_ip;
	int                       encrypt_calls;
	int                       decrypt_calls;
};

Capture g_cap;

// File-scope key shared between the XOR encrypt and decrypt mocks —
// stands in for "thePrefs::GetUserHash()" on the decrypt side. Test
// fixture sets this to the receiver_hash so the roundtrip works.
std::uint8_t g_test_key[UtpEncryption::kUserHashSize];

void mock_reset()
{
	g_cap.encrypt_plaintext.clear();
	g_cap.encrypt_key.clear();
	g_cap.decrypt_ciphertext.clear();
	g_cap.decrypt_source_ip = 0;
	g_cap.encrypt_calls = 0;
	g_cap.decrypt_calls = 0;
	std::memset(g_test_key, 0, sizeof(g_test_key));
	UtpEncryption::SetEncryptDelegate(NULL);
	UtpEncryption::SetDecryptDelegate(NULL);
}

// Identity encrypt: out = plaintext verbatim. Useful for golden-byte
// envelope tests where we want to inspect WrapKeyFrame's framing
// without any byte-level transformation.
bool identity_encrypt(const std::uint8_t* plaintext, std::size_t plaintext_len,
                      const std::uint8_t key[UtpEncryption::kUserHashSize],
                      std::vector<std::uint8_t>& out)
{
	g_cap.encrypt_calls++;
	g_cap.encrypt_plaintext.assign(plaintext, plaintext + plaintext_len);
	g_cap.encrypt_key.assign(key, key + UtpEncryption::kUserHashSize);
	out.assign(plaintext, plaintext + plaintext_len);
	return true;
}

bool identity_decrypt(const std::uint8_t* ciphertext, std::size_t ciphertext_len,
                      std::uint32_t source_ip,
                      std::vector<std::uint8_t>& out)
{
	g_cap.decrypt_calls++;
	g_cap.decrypt_ciphertext.assign(ciphertext, ciphertext + ciphertext_len);
	g_cap.decrypt_source_ip = source_ip;
	out.assign(ciphertext, ciphertext + ciphertext_len);
	return true;
}

// XOR-stream encrypt: out[i] = plaintext[i] ^ key[i % 16]. The
// inverse — XOR with the same key — is its own decrypt. This proves
// roundtrip with a non-trivial transform (catches errors that
// identity wouldn't, e.g. accidentally swapping the encrypt/decrypt
// argument order).
bool xor_encrypt(const std::uint8_t* plaintext, std::size_t plaintext_len,
                 const std::uint8_t key[UtpEncryption::kUserHashSize],
                 std::vector<std::uint8_t>& out)
{
	g_cap.encrypt_calls++;
	out.resize(plaintext_len);
	for (std::size_t i = 0; i < plaintext_len; ++i) {
		out[i] = plaintext[i] ^ key[i % UtpEncryption::kUserHashSize];
	}
	return true;
}

// XOR-stream decrypt: uses the global g_test_key (stand-in for
// "our own user hash") to invert. In production the corresponding
// decrypt function reads thePrefs::GetUserHash().
bool xor_decrypt(const std::uint8_t* ciphertext, std::size_t ciphertext_len,
                 std::uint32_t /*source_ip*/,
                 std::vector<std::uint8_t>& out)
{
	g_cap.decrypt_calls++;
	out.resize(ciphertext_len);
	for (std::size_t i = 0; i < ciphertext_len; ++i) {
		out[i] = ciphertext[i] ^ g_test_key[i % UtpEncryption::kUserHashSize];
	}
	return true;
}

bool always_fail_encrypt(const std::uint8_t* /*plaintext*/, std::size_t /*plaintext_len*/,
                         const std::uint8_t /*key*/[UtpEncryption::kUserHashSize],
                         std::vector<std::uint8_t>& /*out*/)
{
	g_cap.encrypt_calls++;
	return false;
}

bool always_fail_decrypt(const std::uint8_t* /*ciphertext*/, std::size_t /*ciphertext_len*/,
                         std::uint32_t /*source_ip*/,
                         std::vector<std::uint8_t>& /*out*/)
{
	g_cap.decrypt_calls++;
	return false;
}

} // anonymous namespace


// With no encrypt delegate installed, WrapKeyFrame must refuse
// rather than producing a plaintext envelope. Critical: the
// mandatory-encryption guarantee depends on this.
TEST(UtpEncryption, WrapWithoutDelegateReturnsFalse)
{
	mock_reset();

	std::uint8_t sender[UtpEncryption::kUserHashSize];
	std::uint8_t receiver[UtpEncryption::kUserHashSize];
	std::memset(sender, 0xAA, sizeof(sender));
	std::memset(receiver, 0xBB, sizeof(receiver));

	std::vector<std::uint8_t> out;
	ASSERT_FALSE(UtpEncryption::WrapKeyFrame(sender, receiver, out));
	ASSERT_TRUE(out.empty());
}


// Same guarantee on the inbound side: no decrypt delegate → reject.
TEST(UtpEncryption, UnwrapWithoutDelegateReturnsFalse)
{
	mock_reset();

	// Build a syntactically-valid envelope so the failure is
	// definitely caused by the missing delegate, not by preamble
	// rejection.
	std::vector<std::uint8_t> envelope;
	envelope.push_back(0xB2);
	envelope.push_back(0xFF);
	for (int i = 0; i < 16; ++i) envelope.push_back(static_cast<std::uint8_t>(i));

	std::uint8_t recovered[UtpEncryption::kUserHashSize];
	std::memset(recovered, 0, sizeof(recovered));
	ASSERT_FALSE(UtpEncryption::UnwrapKeyFrame(envelope.data(), envelope.size(),
	                                          0x7F000001u, recovered));
}


// With the identity encrypt installed, WrapKeyFrame must produce
// exactly [0xB2, 0xFF, sender_hash]. Verifies the envelope-framing
// logic in isolation from any transformation the encrypt step might
// apply.
TEST(UtpEncryption, WrapBuildsCorrectEnvelopeWithIdentity)
{
	mock_reset();
	UtpEncryption::SetEncryptDelegate(&identity_encrypt);

	std::uint8_t sender[UtpEncryption::kUserHashSize];
	std::uint8_t receiver[UtpEncryption::kUserHashSize];
	for (int i = 0; i < (int)UtpEncryption::kUserHashSize; ++i) {
		sender[i]   = static_cast<std::uint8_t>(0x10 + i);
		receiver[i] = static_cast<std::uint8_t>(0xC0 + i);
	}

	std::vector<std::uint8_t> out;
	ASSERT_TRUE(UtpEncryption::WrapKeyFrame(sender, receiver, out));

	// Envelope shape: preamble + 16-byte payload.
	ASSERT_EQUALS((std::size_t)18, out.size());
	ASSERT_EQUALS((int)0xB2, (int)out[0]);
	ASSERT_EQUALS((int)0xFF, (int)out[1]);
	// Identity encrypt → payload bytes are the sender hash verbatim.
	for (std::size_t i = 0; i < UtpEncryption::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)sender[i], (int)out[2 + i]);
	}

	// The encrypt delegate must have received the sender hash as
	// plaintext and the receiver hash as the key.
	ASSERT_EQUALS(1, g_cap.encrypt_calls);
	ASSERT_EQUALS((std::size_t)UtpEncryption::kUserHashSize,
	              g_cap.encrypt_plaintext.size());
	for (std::size_t i = 0; i < UtpEncryption::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)sender[i],   (int)g_cap.encrypt_plaintext[i]);
		ASSERT_EQUALS((int)receiver[i], (int)g_cap.encrypt_key[i]);
	}
}


// Full roundtrip with XOR-based mocks: encrypt with receiver's hash,
// decrypt with the same hash (set into g_test_key — stand-in for
// thePrefs::GetUserHash() on the receiver side), recovered sender
// hash must match the original byte-for-byte. This is the headline
// test the plan calls out — "encrypt outbound from A→B keyed with
// B's hash, decrypt inbound on B side using B's own hash, assert
// payload matches".
TEST(UtpEncryption, RoundtripWithXorMock)
{
	mock_reset();
	UtpEncryption::SetEncryptDelegate(&xor_encrypt);
	UtpEncryption::SetDecryptDelegate(&xor_decrypt);

	// Two distinct user hashes — sender's (A) and receiver's (B).
	std::uint8_t sender_hash[UtpEncryption::kUserHashSize];
	std::uint8_t receiver_hash[UtpEncryption::kUserHashSize];
	for (std::size_t i = 0; i < UtpEncryption::kUserHashSize; ++i) {
		sender_hash[i]   = static_cast<std::uint8_t>(0x37 + i * 5);
		receiver_hash[i] = static_cast<std::uint8_t>(0x91 + i * 3);
	}

	// On the receiver side, "thePrefs::GetUserHash()" returns
	// receiver_hash — model that by copying it into the test's
	// shared key.
	std::memcpy(g_test_key, receiver_hash, sizeof(g_test_key));

	std::vector<std::uint8_t> wire;
	ASSERT_TRUE(UtpEncryption::WrapKeyFrame(sender_hash, receiver_hash, wire));
	ASSERT_EQUALS((std::size_t)18, wire.size());

	// The 16 payload bytes are XOR(sender_hash, receiver_hash); they
	// must NOT equal the plaintext sender_hash (sanity check that
	// the mock actually transformed something).
	bool any_diff = false;
	for (std::size_t i = 0; i < UtpEncryption::kUserHashSize; ++i) {
		if (wire[2 + i] != sender_hash[i]) {
			any_diff = true;
			break;
		}
	}
	ASSERT_TRUE(any_diff);

	std::uint8_t recovered[UtpEncryption::kUserHashSize];
	std::memset(recovered, 0, sizeof(recovered));
	ASSERT_TRUE(UtpEncryption::UnwrapKeyFrame(wire.data(), wire.size(),
	                                         0x7F000001u, recovered));

	for (std::size_t i = 0; i < UtpEncryption::kUserHashSize; ++i) {
		ASSERT_EQUALS((int)sender_hash[i], (int)recovered[i]);
	}

	ASSERT_EQUALS(1, g_cap.encrypt_calls);
	ASSERT_EQUALS(1, g_cap.decrypt_calls);
}


// UnwrapKeyFrame must reject envelopes whose first byte isn't 0xB2.
TEST(UtpEncryption, UnwrapRejectsWrongOpcode)
{
	mock_reset();
	UtpEncryption::SetDecryptDelegate(&identity_decrypt);

	std::vector<std::uint8_t> envelope;
	envelope.push_back(0xAB);  // wrong
	envelope.push_back(0xFF);
	for (int i = 0; i < 16; ++i) envelope.push_back((std::uint8_t)i);

	std::uint8_t recovered[UtpEncryption::kUserHashSize];
	ASSERT_FALSE(UtpEncryption::UnwrapKeyFrame(envelope.data(), envelope.size(),
	                                          0x7F000001u, recovered));
	// The decrypt delegate must NOT have been called — preamble
	// validation happens first.
	ASSERT_EQUALS(0, g_cap.decrypt_calls);
}


// Same for the sub-byte: anything other than 0xFF (= Key Frame)
// must be rejected by UnwrapKeyFrame, since 0x00 would be the
// reserved discriminator for sub-byte-0x00 uTP frames in later
// phases — never a Key Frame.
TEST(UtpEncryption, UnwrapRejectsWrongSubByte)
{
	mock_reset();
	UtpEncryption::SetDecryptDelegate(&identity_decrypt);

	std::vector<std::uint8_t> envelope;
	envelope.push_back(0xB2);
	envelope.push_back(0x00);  // sub-byte for uTP frame, not Key Frame
	for (int i = 0; i < 16; ++i) envelope.push_back((std::uint8_t)i);

	std::uint8_t recovered[UtpEncryption::kUserHashSize];
	ASSERT_FALSE(UtpEncryption::UnwrapKeyFrame(envelope.data(), envelope.size(),
	                                          0x7F000001u, recovered));
	ASSERT_EQUALS(0, g_cap.decrypt_calls);
}


// Short buffers must be rejected before any delegate call.
TEST(UtpEncryption, UnwrapRejectsShortBuffer)
{
	mock_reset();
	UtpEncryption::SetDecryptDelegate(&identity_decrypt);

	std::uint8_t empty[1] = { 0xB2 };
	std::uint8_t recovered[UtpEncryption::kUserHashSize];
	ASSERT_FALSE(UtpEncryption::UnwrapKeyFrame(empty, 0,            0u, recovered));
	ASSERT_FALSE(UtpEncryption::UnwrapKeyFrame(empty, 1,            0u, recovered));
	ASSERT_EQUALS(0, g_cap.decrypt_calls);
}


// If the decrypt delegate returns a buffer of the wrong size,
// Unwrap must reject — a Key Frame's plaintext is exactly 16 bytes
// by protocol contract.
TEST(UtpEncryption, UnwrapRejectsNonHashSizedDecryptOutput)
{
	mock_reset();

	// Decrypt mock that returns 15 bytes — one short of the hash size.
	struct ShortDecrypt {
		static bool fn(const std::uint8_t* c, std::size_t len,
		               std::uint32_t /*ip*/,
		               std::vector<std::uint8_t>& out) {
			(void)c; (void)len;
			out.resize(15, 0x42);
			return true;
		}
	};
	UtpEncryption::SetDecryptDelegate(&ShortDecrypt::fn);

	std::vector<std::uint8_t> envelope;
	envelope.push_back(0xB2);
	envelope.push_back(0xFF);
	for (int i = 0; i < 16; ++i) envelope.push_back((std::uint8_t)i);

	std::uint8_t recovered[UtpEncryption::kUserHashSize];
	ASSERT_FALSE(UtpEncryption::UnwrapKeyFrame(envelope.data(), envelope.size(),
	                                          0x7F000001u, recovered));
}


// If the encrypt delegate fails, Wrap propagates the failure. This
// must not produce a partial envelope.
TEST(UtpEncryption, WrapPropagatesEncryptFailure)
{
	mock_reset();
	UtpEncryption::SetEncryptDelegate(&always_fail_encrypt);

	std::uint8_t sender[UtpEncryption::kUserHashSize];
	std::uint8_t receiver[UtpEncryption::kUserHashSize];
	std::memset(sender, 0xAA, sizeof(sender));
	std::memset(receiver, 0xBB, sizeof(receiver));

	std::vector<std::uint8_t> out;
	out.push_back(0xDE);  // pre-existing data; should not be touched
	ASSERT_FALSE(UtpEncryption::WrapKeyFrame(sender, receiver, out));
	// Output is left as the caller provided it (we don't guarantee
	// emptiness on failure — only that no spurious envelope was built).
	ASSERT_EQUALS(1, g_cap.encrypt_calls);
}


// Symmetric: decrypt-side failure must propagate from Unwrap.
TEST(UtpEncryption, UnwrapPropagatesDecryptFailure)
{
	mock_reset();
	UtpEncryption::SetDecryptDelegate(&always_fail_decrypt);

	std::vector<std::uint8_t> envelope;
	envelope.push_back(0xB2);
	envelope.push_back(0xFF);
	for (int i = 0; i < 16; ++i) envelope.push_back((std::uint8_t)i);

	std::uint8_t recovered[UtpEncryption::kUserHashSize];
	ASSERT_FALSE(UtpEncryption::UnwrapKeyFrame(envelope.data(), envelope.size(),
	                                          0x7F000001u, recovered));
	ASSERT_EQUALS(1, g_cap.decrypt_calls);
}


// NULL pointer arguments must be rejected cleanly.
TEST(UtpEncryption, RejectsNullArguments)
{
	mock_reset();
	UtpEncryption::SetEncryptDelegate(&identity_encrypt);
	UtpEncryption::SetDecryptDelegate(&identity_decrypt);

	std::uint8_t hash[UtpEncryption::kUserHashSize];
	std::memset(hash, 0, sizeof(hash));
	std::vector<std::uint8_t> out;
	std::vector<std::uint8_t> envelope;
	envelope.push_back(0xB2);
	envelope.push_back(0xFF);
	for (int i = 0; i < 16; ++i) envelope.push_back(0);

	ASSERT_FALSE(UtpEncryption::WrapKeyFrame(NULL, hash, out));
	ASSERT_FALSE(UtpEncryption::WrapKeyFrame(hash, NULL, out));
	ASSERT_FALSE(UtpEncryption::UnwrapKeyFrame(NULL, envelope.size(),
	                                          0u, hash));
	ASSERT_FALSE(UtpEncryption::UnwrapKeyFrame(envelope.data(), envelope.size(),
	                                          0u, NULL));
}

#else

using namespace muleunit;
DECLARE(UtpEncryption)
END_DECLARE;

TEST(UtpEncryption, FeatureDisabled)
{
	ASSERT_TRUE(true);
}

#endif // ENABLE_NAT_T
