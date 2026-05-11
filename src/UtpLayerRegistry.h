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

#ifndef UTPLAYERREGISTRY_H
#define UTPLAYERREGISTRY_H

#include "config.h"

#ifdef ENABLE_NAT_T

// Phase B7.5 of the NAT-T port (follow-ups F1 + F2 + F4 wiring). The
// process-wide index of live CUtpLayer instances, keyed on the peer's
// user hash. Solves three concrete problems carried out of B6:
//
//   F1/F2 — Inbound Key Frame routing: when a peer's Key Frame
//           arrives at CClientUDPSocket, we recover the sender's
//           16-byte user hash from UnwrapKeyFrame; the registry maps
//           that hash to the layer that's waiting for it, so the
//           inbound dispatch can call layer->OnPeerKeyFrame(...).
//
//   F4   — Periodic timeout sweep: UtpTimer's tick callback iterates
//           the registry every 50 ms and calls CheckTimeoutNow on
//           each layer, advancing layers stuck in KEY_FRAME_SENT past
//           their 12 s deadline.
//
// Lifetime contract: layers self-register from Connect() and
// self-unregister from their destructor. Both touch the registry
// under UtpEnvironment::RuntimeLock so that the timer's iteration
// (also under the runtime lock) sees a consistent snapshot. Callers
// of FindByPeerHash from outside the runtime lock — e.g.
// CClientUDPSocket's inbound dispatch — get raw pointers whose
// lifetime is bounded by the layer's owner, NOT by the registry. The
// production layer owner (CUpDownClient in Phase E) is responsible
// for coordinating destruction with any in-flight dispatch; for the
// current B7.5 scope no such race exists because layers are only
// created by tests so far.
//
// Concurrency / lock ordering:
//   - Public methods (Register, Unregister, FindByPeerHash) each
//     take the internal registry mutex. They do NOT acquire the
//     runtime lock; callers may or may not hold it. This avoids the
//     "registry lock first, then runtime lock" inversion path.
//   - ForEachLocked is the timer's entry point. It assumes the
//     runtime lock is already held by the caller and takes the
//     registry mutex briefly only to snapshot the layer pointers.
//     Callbacks execute outside the registry lock (but inside the
//     runtime lock) so they can safely call back into per-layer
//     methods that themselves work under the runtime lock.

#include <cstdint>
#include <functional>

struct sockaddr;
typedef unsigned int socklen_t;

class CUtpLayer;

namespace UtpLayerRegistry {

// Size of the user hash key. Mirrors UtpKeyFrame::kUserHashSize /
// UtpEncryption::kUserHashSize / CUtpLayer::kUserHashSize so callers
// can use sizeof(uint8_t[16]) interchangeably.
static constexpr std::size_t kUserHashSize = 16;

// Register `layer` under `peer_hash` AND `peer_addr`. The layer is
// reachable via either lookup; both keys remove together on
// Unregister(layer). A second Register call with the same peer_hash
// REPLACES the previous hash entry; same for peer_addr — both maps
// are point-overwrite, since a NAT-T peer pair only ever has one
// active layer at a time, so a re-Register usually indicates a
// leaked layer from a previous attempt.
//
// peer_addr is optional (pass NULL with addr_len = 0 to register
// only the hash key) — address-keyed lookup only matters once the
// outbound wrap path in on_sendto needs it (after Connect creates
// a utp_socket). Tests that exercise the registry's hash side in
// isolation pass NULL.
//
// Pass NULL for `layer` to leave the slot empty; this is equivalent
// to removing the entry.
void Register(const std::uint8_t peer_hash[kUserHashSize],
              CUtpLayer* layer,
              const struct sockaddr* peer_addr = nullptr,
              socklen_t addr_len = 0);

// Remove every entry pointing at `layer` (in both the hash-keyed
// and addr-keyed indices). No-op if `layer` is not registered.
void Unregister(CUtpLayer* layer);

// Look up the layer registered under `peer_hash`. Returns NULL if no
// match. The returned pointer is valid until the layer's owner
// destroys it — coordinate destruction with any callers of this
// function if they're on different threads.
CUtpLayer* FindByPeerHash(const std::uint8_t peer_hash[kUserHashSize]);

// Look up the layer registered with a peer_addr equal byte-for-byte
// to (addr, addr_len). Returns NULL if no match. Used by
// UtpCallbacks::on_sendto because libutp's send_to_addr path passes
// NULL for the per-callback socket pointer (see utp_internal.cpp:712
// — context-level sends only), forcing us to route by destination
// address instead of by utp_get_userdata.
CUtpLayer* FindByPeerAddr(const struct sockaddr* addr, socklen_t addr_len);

// Iterate all registered layers, calling `fn(layer)` for each.
// The iteration takes a snapshot of the layer pointers under the
// internal registry mutex, releases that mutex, then invokes `fn`
// on each — so `fn` can safely call other registry methods (e.g.
// Register / Unregister from a layer's state transition).
//
// The layer pointers passed to `fn` are raw; their lifetime is
// bounded by each layer's owner. If a layer can be destroyed
// concurrently with the iteration (a different thread), the owner
// must coordinate — typically by destroying layers only on the
// thread that drives ForEach (B7.5 limits this to UtpTimer).
void ForEach(std::function<void(CUtpLayer*)> fn);

// Diagnostic: number of currently-registered layers.
std::size_t Size();

// Test helper: clear all entries. Production code should never need
// this; tests use it to reset state between cases.
void ClearForTesting();

} // namespace UtpLayerRegistry

#endif // ENABLE_NAT_T

#endif // UTPLAYERREGISTRY_H
