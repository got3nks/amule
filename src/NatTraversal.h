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

#include <cstdint>

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

} // namespace NatTraversal

#endif // NATTRAVERSAL_H
