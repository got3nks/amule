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

#ifndef UTPENCRYPTION_H
#define UTPENCRYPTION_H

#include "config.h"

#ifdef ENABLE_NAT_T

#include <cstddef>
#include <cstdint>
#include <vector>

// Phase B5 of the NAT-T port (see .archive/eMuleAI-nat-t-implementation-plan.md
// cluster 6, sub-commit B5). Provides the encryption wrapping for
// the OP_UDPRESERVEDPROT2 envelope:
//
//   - Outbound: Wrap{KeyFrame,UtpFrame}() encrypts the payload with
//     the receiver's user hash as the symmetric key, then prepends
//     [0xB2, sub-byte] to produce the on-wire bytes.
//
//   - Inbound: Unwrap{KeyFrame,UtpFrame}() validates the
//     [0xB2, sub-byte] preamble, then decrypts the trailing payload
//     using thePrefs::GetUserHash() (the receiver's own hash; same
//     value the sender used as the key).
//
// Encryption is mandatory — there is no plaintext path. The
// plaintext envelope helpers in UtpKeyFrame.{h,cpp} exist for
// diagnostics + the encrypted-payload assembly here; they are NOT
// used directly on the wire.
//
// Testability: the encrypt and decrypt operations are pluggable via
// delegate function pointers (same pattern as
// UtpCallbacks::SetSendtoDelegate). Production code installs
// thunks that call CEncryptedDatagramSocket::EncryptSendClient /
// DecryptReceivedClient — those functions reach into theApp /
// thePrefs / theStats, so unit tests substitute lightweight mock
// delegates that satisfy the roundtrip property without needing the
// full app boot. The integration with the real
// EncryptedDatagramSocket is exercised end-to-end in B8's loopback
// integration test once a full daemon environment is available.

namespace UtpEncryption {

static constexpr std::size_t kUserHashSize = 16;

// Outbound encryption delegate.
//   plaintext, plaintext_len: bytes to encrypt.
//   key:                     16-byte symmetric key (= receiver's user hash).
//   out:                     destination for ciphertext. The implementor
//                            assigns to out; it does not have to be
//                            pre-sized.
// Returns true on success.
typedef bool (*EncryptFn)(const std::uint8_t* plaintext,
                          std::size_t plaintext_len,
                          const std::uint8_t key[kUserHashSize],
                          std::vector<std::uint8_t>& out);

// Inbound decryption delegate.
//   ciphertext, ciphertext_len: bytes to decrypt (post-preamble).
//   source_ip:                  IPv4 source of the packet — passed
//                               through to the production
//                               DecryptReceivedClient call as `ip`.
//   out:                        destination for plaintext.
// Returns true on success.
typedef bool (*DecryptFn)(const std::uint8_t* ciphertext,
                          std::size_t ciphertext_len,
                          std::uint32_t source_ip,
                          std::vector<std::uint8_t>& out);

// Install the encrypt/decrypt delegates. Pass NULL to clear.
// Initial state has both delegates NULL; Wrap/Unwrap return false
// until at least the relevant direction's delegate is installed.
void SetEncryptDelegate(EncryptFn fn);
void SetDecryptDelegate(DecryptFn fn);

// Install the production thunks that call
// CEncryptedDatagramSocket::EncryptSendClient / DecryptReceivedClient.
// Called once at daemon start from CClientUDPSocket's ctor in a
// later sub-commit (B6+). Does NOT run from unit tests — those
// install their own lightweight delegates for isolation.
void InstallProductionDelegates();

// Wrap a Key Frame: produces [0xB2, 0xFF, encrypt(sender_hash, key=receiver_hash)].
// Returns false if no encrypt delegate is installed, the inputs are
// NULL, or the encrypt delegate fails.
bool WrapKeyFrame(const std::uint8_t sender_hash[kUserHashSize],
                  const std::uint8_t receiver_hash[kUserHashSize],
                  std::vector<std::uint8_t>& out);

// Unwrap a Key Frame: validates the [0xB2, 0xFF] preamble, then
// decrypts the trailing payload via the registered DecryptFn. The
// decrypted payload must be exactly kUserHashSize bytes; otherwise
// the envelope is treated as malformed (returns false).
bool UnwrapKeyFrame(const std::uint8_t* buf, std::size_t len,
                    std::uint32_t source_ip,
                    std::uint8_t sender_hash_out[kUserHashSize]);

} // namespace UtpEncryption

#endif // ENABLE_NAT_T

#endif // UTPENCRYPTION_H
