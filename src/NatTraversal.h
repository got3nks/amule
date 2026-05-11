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

#ifndef NATTRAVERSAL_H
#define NATTRAVERSAL_H

#include <cstddef>
#include <cstdint>
#include <vector>

// Capability layer for NAT Traversal (NAT-T) / uTP support.
//
// Phase A3 of the NAT-T port (see .archive/eMuleAI-nat-t-implementation-plan.md).
// This header defines the wire-protocol bit positions and pure-function
// helpers for decoding/encoding the connect-options byte's NAT-T flag.
//
// The intent of this module is to keep the bit-position contract in one
// place, so when later phases (D/E) wire NAT-T into CUpDownClient's
// connection flow they can reach for the constants here instead of
// hard-coding 0x80 in N call sites.

namespace NatTraversal {

// Bit position in the eD2k 8-bit connect-options byte ("byCryptOptions"
// in eMule / aMule source) reserved for NAT-T capability. Matches the
// eMuleAI convention so wire-protocol interop works without aMule needing
// a separate handshake tag.
//
//   bit 0 (0x01): supports crypt layer
//   bit 1 (0x02): requests crypt layer
//   bit 2 (0x04): requires crypt layer
//   bit 3 (0x08): direct UDP callback support
//   bit 4 (0x10): reserved
//   bit 5 (0x20): reserved
//   bit 6 (0x40): reserved
//   bit 7 (0x80): NAT traversal support  <-- this module
//
// Note: in *server source-exchange packets* (CClientUDPSocket parsing
// of CT_ED2K_INDIRECTSOURCE etc., and CPartFile's source-exchange-2
// handling), bit 7 of the same byte is overloaded to mean "the source's
// user hash is appended after this byte". That overlap is contextual,
// not a conflict: source-exchange callers MUST NOT treat bit 7 as NAT-T.
// Only Hello/CallbackRequest contexts may. The DecodeFromConnectOptions
// helper below takes an explicit `treat_bit7_as_nat_t` parameter to
// force the caller to be explicit about which context it's in.
static constexpr uint8_t CONNECT_OPT_BIT_NAT_TRAVERSAL = 0x80;

// Decode the NAT-T bit from a connect-options byte.
//
//   options:                 the raw 8-bit byCryptOptions byte as
//                            received over the wire
//   treat_bit7_as_nat_t:     true  → Hello / DirectCallbackReq / etc.
//                                    contexts where bit 7 means NAT-T;
//                            false → server source-exchange contexts
//                                    where bit 7 means "hash follows".
//                                    In this case we always return
//                                    false (NAT-T not advertised).
//
// Returns: whether the peer advertises NAT-T support.
inline bool DecodeFromConnectOptions(uint8_t options,
                                     bool treat_bit7_as_nat_t)
{
	if (!treat_bit7_as_nat_t) {
		return false;
	}
	return (options & CONNECT_OPT_BIT_NAT_TRAVERSAL) != 0;
}

// Encode the NAT-T bit into a base connect-options byte.
//
//   base_options: the byte built from the other bits (crypt layer
//                 support / request / require / direct UDP callback)
//   supports_nat: whether to set bit 7
//
// Returns: the combined byte ready to write to the wire.
//
// Only call this in Hello / DirectCallbackReq paths — never in server
// source-exchange paths (the receiver there will misinterpret bit 7
// as "hash follows").
inline uint8_t EncodeIntoConnectOptions(uint8_t base_options,
                                        bool supports_nat)
{
	if (supports_nat) {
		return base_options | CONNECT_OPT_BIT_NAT_TRAVERSAL;
	}
	return base_options & ~CONNECT_OPT_BIT_NAT_TRAVERSAL;
}

// --- Phase C2: OP_RENDEZVOUS / OP_HOLEPUNCH wire format -------------
//
// Two new eMule-extension opcodes (carried inside the OP_EMULEPROT
// envelope, byte 0 = 0xC5, byte 1 = opcode) that drive the rendezvous
// half of NAT traversal:
//
//   OP_RENDEZVOUS = 0xA0  initiator → buddy → uploader path; carries
//                         the target user's hash, optional file
//                         context, optional external endpoint.
//   OP_HOLEPUNCH  = 0xA1  buddy → initiator hint; carries no body,
//                         the packet's source address is the signal.
//
// The wire format for RENDEZVOUS is variable-length to match eMuleAI
// exactly so the two implementations interop. Mandatory fields are
// 17 bytes (user_hash + connect_options); optional extension blocks
// add another 16 bytes (file_hash) and another 6 bytes (ext IPv4 +
// port). All multi-byte fields are little-endian on the wire to
// match eMule's CFile / CMemFile serialization convention.

static constexpr std::uint8_t  OP_RENDEZVOUS_OPCODE = 0xA0;
static constexpr std::uint8_t  OP_HOLEPUNCH_OPCODE  = 0xA1;

// CMD4Hash size — duplicated locally so this header doesn't pull in
// CMD4Hash.h.
static constexpr std::size_t   kUserHashSize = 16;

// The mandatory-only RENDEZVOUS body is 17 bytes; with file_hash it's
// 33; with file_hash + ext endpoint it's 39.
static constexpr std::size_t   kRendezvousBodyMin  = kUserHashSize + 1;       // 17
static constexpr std::size_t   kRendezvousBodyMid  = kRendezvousBodyMin + kUserHashSize;        // 33
static constexpr std::size_t   kRendezvousBodyFull = kRendezvousBodyMid + 4 + 2;                // 39

// Parsed RENDEZVOUS body. has_file_hash / has_ext_endpoint
// distinguish the optional blocks; the corresponding data fields
// are only meaningful when the flag is true.
struct RendezvousRequest {
	std::uint8_t  target_user_hash[kUserHashSize];
	std::uint8_t  connect_options;       // eD2k byCryptOptions byte
	bool          has_file_hash;
	std::uint8_t  target_file_hash[kUserHashSize];   // valid iff has_file_hash
	bool          has_ext_endpoint;
	std::uint32_t requester_ext_ip;      // host byte order; valid iff has_ext_endpoint
	std::uint16_t requester_ext_port;    // host byte order; valid iff has_ext_endpoint
};

// Encode a RendezvousRequest into the body bytes (just the payload
// after the OP_EMULEPROT / OP_RENDEZVOUS preamble — the caller wraps
// it via the existing CPacket OP_EMULEPROT machinery on send).
//
// has_file_hash / has_ext_endpoint on the input struct determine
// which optional blocks are appended. ext_endpoint without
// file_hash is allowed by the wire format only if file_hash is
// emitted as a zero (eMuleAI's "no file" sentinel) — Encode does
// that automatically when has_ext_endpoint && !has_file_hash.
//
// Returns false on NULL out (defensive). out is cleared on entry.
bool EncodeRendezvous(const RendezvousRequest& req,
                      std::vector<std::uint8_t>& out);

// Decode RENDEZVOUS body bytes. Length must be >= kRendezvousBodyMin;
// trailing bytes past the recognised optional blocks are silently
// ignored (UDP can deliver padding). has_file_hash and
// has_ext_endpoint flags on `out` indicate which blocks were
// present. Returns false on short buffer or NULL inputs.
bool DecodeRendezvous(const std::uint8_t* buf, std::size_t len,
                      RendezvousRequest& out);

// HOLEPUNCH has no body. The pair below exists for symmetry and to
// future-proof callers — if a future protocol version adds payload
// bytes, callers can extend the helpers without touching the
// dispatch sites.
bool EncodeHolePunch(std::vector<std::uint8_t>& out);

// Decode a HOLEPUNCH body. Today this is a no-op (body must be
// empty or trailing-padding-tolerant); returns false on NULL buf.
bool DecodeHolePunch(const std::uint8_t* buf, std::size_t len);

// --- Phase C3 scaffolding: Kad rendezvous-buddy discovery ----------
//
// A NAT-T initiator needs at least one HighID peer that can act as
// a rendezvous buddy — relay the RENDEZVOUS packet to a LowID
// uploader on the initiator's behalf and follow with HOLEPUNCH back
// to the initiator. The buddy must be:
//   (a) HighID (directly reachable on UDP), and
//   (b) advertise NAT-T support (the SupportsNatTraversal bit from
//       NatTraversal::CONNECT_OPT_BIT_NAT_TRAVERSAL).
//
// Finding such a buddy is a two-step process: standard Kad search
// for peers near the target user's hash, then filter for NAT-T
// support. This API surface mirrors what the plan's cluster 7 spec
// (FindRendezvousCandidates) called for.
//
// **Phase C3 scope**: this header DECLARES the API; the
// implementation in NatTraversal.cpp is a documented stub that
// returns no candidates. The actual Kad-search wiring lands inside
// Phase D's rendezvous coordinator (cluster 8) — bundled together
// because the coordinator is the only caller and the search policy
// (timeouts, retry, candidate-cap interaction) is coordinator-
// specific. The stub exists so callers can be written against the
// final API shape today.

struct RendezvousCandidate {
	std::uint8_t  user_hash[kUserHashSize]; // candidate's user hash
	std::uint32_t ip_be;                    // network byte order
	std::uint16_t udp_port;                 // host byte order
	std::uint16_t tcp_port;                 // host byte order
};

// Synchronous, fast variant: snapshots whatever candidates are
// currently known (from existing Kad routing tables / known-client
// state, or empty if no integration has happened yet). The caller
// supplies a max cap; the implementation appends up to that many to
// `out`. Returns true if at least one candidate was found.
//
// Today's stub always returns false with `out` left empty — Phase D
// fills in the actual Kad search against
// `Kademlia::CKademlia::GetRoutingZone()` plus a SupportsNatTraversal
// filter.
bool FindRendezvousCandidates(const std::uint8_t target_user_hash[kUserHashSize],
                              std::size_t max_candidates,
                              std::vector<RendezvousCandidate>& out);

} // namespace NatTraversal

#endif // NATTRAVERSAL_H
