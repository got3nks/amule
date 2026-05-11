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

#ifndef NATTRAVERSALCOORDINATOR_H
#define NATTRAVERSALCOORDINATOR_H

#include "config.h"

#ifdef ENABLE_NAT_T

// Phase D of the NAT-T port (see .archive/eMuleAI-nat-t-implementation-plan.md
// cluster 8). The CNatTraversalCoordinator orchestrates the three
// rendezvous roles a process plays simultaneously:
//
//   LowID requester (D3): I want to reach a LowID peer P. I send
//     OP_RENDEZVOUS via a HighID buddy B; B forwards to P and sends
//     me OP_HOLEPUNCH; I start a uTP connect to P's external address.
//
//   HighID buddy (D2): another LowID requester R sent me
//     OP_RENDEZVOUS naming a LowID peer P I'm connected to. I forward
//     OP_RENDEZVOUS to P (with R's external endpoint in the body) and
//     send OP_HOLEPUNCH back to R.
//
//   LowID endpoint (D4): a HighID buddy B forwarded me OP_RENDEZVOUS
//     naming the LowID requester R that's trying to reach me. I prep
//     a passive CUtpLayer so libutp accepts R's incoming SYN.
//
// Each process can be in all three roles concurrently (you might be
// downloading from one peer while uploading to another). The
// coordinator is a process-wide singleton that demuxes inbound
// OP_RENDEZVOUS / OP_HOLEPUNCH via CClientUDPSocket's dispatch in C1
// and routes to whichever role-specific handler is appropriate.
//
// **D1 scope (this sub-commit)**: skeleton + pending-rendezvous
// table + timeout management. The role-specific handlers (D2 / D3
// / D4) land in subsequent sub-commits. D1 ships the data structures
// and the dispatch surface, plus the manual-clock timeout driver.

#include "NatTraversal.h"  // RendezvousRequest, kUserHashSize

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>

struct sockaddr;
typedef unsigned int socklen_t;

class CUtpLayer;

namespace NatTraversal {

class CNatTraversalCoordinator
{
public:
	// Time the requester is allowed to spend waiting for OP_HOLEPUNCH
	// from a buddy before giving up and falling back to TCP. Matches
	// the plan's RENDEZVOUSFALLBACKDELAY (Phase E2). Driven by
	// CheckTimeouts() which the wxTimer / production tick path
	// invokes periodically.
	static constexpr std::uint64_t kRendezvousTimeoutMs = 12000;

	// Singleton accessor. Lazily constructed on first call; lives
	// for process lifetime. The coordinator owns no OS resources of
	// its own — it's purely an in-memory state machine — so there's
	// no Shutdown() needed.
	static CNatTraversalCoordinator& Instance();

	// === Delegate API (D2+) ========================================
	//
	// The coordinator needs to consult the wider aMule app for three
	// things: look up a client by user hash (buddy → endpoint
	// routing), look up a client by UDP endpoint (endpoint →
	// requester identification), and emit OP_EMULEPROT-wrapped UDP
	// packets. Production wires these to theApp->clientlist /
	// CClientUDPSocket; tests install lightweight stubs. Matches the
	// UtpEncryption Set*Delegate pattern from B5 — keeps the
	// coordinator unit-testable without pulling in theApp.

	// Look up a client's UDP endpoint by their user hash. Returns
	// true if a known client matches; out args filled with the
	// client's external (NAT-translated) IP/port in host byte order.
	using LookupClientByHashFn = bool (*)(
		const std::uint8_t user_hash[kUserHashSize],
		std::uint32_t& out_ip_host,
		std::uint16_t& out_udp_port);

	// Look up a client's user hash given their UDP endpoint.
	// Returns true if a known client matches; out_user_hash filled
	// with the 16-byte hash on success.
	using LookupClientByEndpointFn = bool (*)(
		std::uint32_t ip_host,
		std::uint16_t udp_port,
		std::uint8_t out_user_hash[kUserHashSize]);

	// Emit an OP_EMULEPROT-wrapped UDP packet to (dest_ip, dest_port).
	// `opcode` is the inner eMule-extension opcode (e.g.
	// OP_RENDEZVOUS_OPCODE). `body` may be nullptr if body_len == 0.
	// Returns true if the packet was queued for send.
	using SendEmuleProtFn = bool (*)(
		std::uint8_t opcode,
		const std::uint8_t* body, std::size_t body_len,
		std::uint32_t dest_ip_host,
		std::uint16_t dest_udp_port);

	// Find a HighID NAT-T-capable buddy to relay our OP_RENDEZVOUS
	// through. Today's D3 implementation calls this once per
	// RequestRendezvous; D5's Kad-search wiring will replace this
	// with a multi-candidate iterator. Returns true if a buddy is
	// available; out args filled with the buddy's UDP endpoint.
	using FindBuddyFn = bool (*)(std::uint32_t& out_buddy_ip_host,
	                             std::uint16_t& out_buddy_udp_port);

	// Factory for CUtpLayer instances. Production wires this to
	// `new CUtpLayer(UtpEnvironment::GetContext())` + Connect();
	// tests install a stub that returns a sentinel pointer so the
	// coordinator's bookkeeping can be exercised without standing
	// up a full utp_context + delegate environment.
	//
	// `initiator` selects the connect flow (mirrors
	// CUtpLayer::Connect's parameter): true for the D3 requester
	// path (we initiate the uTP handshake), false for the D4
	// endpoint path (we accept libutp's incoming SYN).
	//
	// Returns a pointer the callback receives via on_complete; the
	// caller takes ownership and is responsible for deleting it. A
	// NULL return indicates the factory failed (e.g.
	// `utp_create_socket` allocation failure), in which case the
	// coordinator fires on_complete(false, nullptr) on D3 and
	// silently drops on D4 (no callback to fire on the responder
	// path).
	using CreateUtpLayerFn = CUtpLayer* (*)(
		const std::uint8_t our_hash[kUserHashSize],
		const std::uint8_t peer_hash[kUserHashSize],
		const struct sockaddr* peer_addr,
		socklen_t addr_len,
		bool initiator);

	void SetLookupClientByHashDelegate(LookupClientByHashFn fn);
	void SetLookupClientByEndpointDelegate(LookupClientByEndpointFn fn);
	void SetSendEmuleProtDelegate(SendEmuleProtFn fn);
	void SetFindBuddyDelegate(FindBuddyFn fn);
	void SetCreateUtpLayerDelegate(CreateUtpLayerFn fn);

	// Set the process-level user hash. Production calls this once
	// at startup (from thePrefs::GetUserHash()); tests set per-case.
	// Used as the `our_hash` when creating outgoing CUtpLayer
	// instances on the requester side.
	void SetOurUserHash(const std::uint8_t our_hash[kUserHashSize]);

	// === LowID requester role (D3, this method is D1 stub) =========
	//
	// Called by CUpDownClient (in Phase E) when it wants to reach a
	// LowID peer via NAT-T. Records the request in the pending
	// table, eventually issues OP_RENDEZVOUS to a buddy candidate,
	// and invokes `on_complete` when either OP_HOLEPUNCH arrives
	// (success — `layer` is the connected CUtpLayer) or the timeout
	// fires (failure — `layer` is NULL).
	//
	// D1 implementation: just inserts a PendingRendezvous entry into
	// the table. No actual OP_RENDEZVOUS is emitted yet; the
	// timeout path will fire failure after kRendezvousTimeoutMs.
	// D3 wires the actual emit + buddy lookup.
	using RendezvousCompleteFn = std::function<void(bool ok, CUtpLayer* layer)>;
	void RequestRendezvous(const std::uint8_t target_user_hash[kUserHashSize],
	                       const struct sockaddr* target_addr_hint,
	                       socklen_t addr_hint_len,
	                       RendezvousCompleteFn on_complete);

	// === Inbound dispatch entry points (called from C1) ============
	//
	// CClientUDPSocket's OP_RENDEZVOUS / OP_HOLEPUNCH case-bodies
	// call these instead of just logging once D2/D3/D4 are wired.
	// D1 implements them as logging stubs.

	// Inbound OP_RENDEZVOUS. The packet source is the peer's
	// observed address (which for D2 is the requester via the buddy
	// path, and for D4 is the buddy forwarding on behalf of the
	// requester). The req.has_ext_endpoint distinguishes the cases:
	// when set, ext_endpoint is the requester's real address (we are
	// D4 — endpoint receiving forward); when unset, the source is
	// the requester directly (we are D2 — buddy receiving original).
	void OnInboundRendezvous(const RendezvousRequest& req,
	                         std::uint32_t src_ip_host,    // host byte order
	                         std::uint16_t src_port);

	// Inbound OP_HOLEPUNCH. Source is the buddy that's signalling
	// the LowID requester (us) that the rendezvous has been
	// forwarded; we should now drive the uTP connect against the
	// target_addr we already recorded in the pending entry.
	void OnInboundHolePunch(std::uint32_t src_ip_host,
	                        std::uint16_t src_port);

	// === Timeout / housekeeping ====================================

	// Called periodically (target: every ~50 ms, fold into B7's
	// UtpTimer tick). `now_ms` is std::chrono::steady_clock-derived
	// monotonic ms; the coordinator compares against each pending
	// entry's deadline. Fires `on_complete(false, nullptr)` on every
	// expired entry and removes it from the table.
	//
	// Returns the number of entries that timed out this call.
	std::size_t CheckTimeouts(std::uint64_t now_ms);

	// Test helper: number of pending entries currently in the table.
	std::size_t PendingCount() const;

	// Test helper: forcefully clear all pending entries (e.g.
	// between test cases). Production should never call this.
	void ClearPendingForTesting();

	// Construct an independent coordinator instance. Production code
	// must use Instance() — the singleton owns the process-wide
	// rendezvous state. Tests instantiate directly (e.g. D6's 3-node
	// in-process integration test stands up three coordinators, one
	// per simulated peer).
	CNatTraversalCoordinator() = default;
	~CNatTraversalCoordinator() = default;

private:
	CNatTraversalCoordinator(const CNatTraversalCoordinator&) = delete;
	CNatTraversalCoordinator& operator=(const CNatTraversalCoordinator&) = delete;

	// One outstanding rendezvous from the LowID-requester side.
	struct PendingRendezvous {
		std::uint64_t            deadline_ms;
		std::vector<std::uint8_t> target_addr;     // sockaddr_storage bytes
		socklen_t                target_addr_len;
		RendezvousCompleteFn     on_complete;
		// D3: track which buddy we sent OP_RENDEZVOUS to so we can
		// match inbound OP_HOLEPUNCH by source against the right
		// pending entry. Multiple concurrent rendezvous through
		// different buddies are routed by source IP/port match.
		std::uint32_t            buddy_ip_host;
		std::uint16_t            buddy_udp_port;
		// D3: hash key copy + our_hash captured at request time so
		// OnInboundHolePunch can construct the CUtpLayer without
		// re-deriving them.
		std::array<std::uint8_t, kUserHashSize> peer_user_hash;
		std::array<std::uint8_t, kUserHashSize> our_user_hash;
	};

	// Pending-rendezvous index keyed on target user hash. A
	// concurrent second RequestRendezvous to the same target
	// replaces the previous pending entry (cancels its callback
	// with failure). Matches the eMuleAI "one rendezvous per peer
	// at a time" convention.
	using HashKey = std::array<std::uint8_t, kUserHashSize>;
	mutable std::mutex                   m_lock;  // mutable: PendingCount() const path
	std::map<HashKey, PendingRendezvous> m_pending;

	// Delegate slots. Set once at startup (production thunks or test
	// stubs); read from any role-handler. Reading without locking is
	// safe under the "delegates set at startup, no races" contract
	// inherited from UtpEncryption's design.
	LookupClientByHashFn     m_lookup_by_hash     = nullptr;
	LookupClientByEndpointFn m_lookup_by_endpoint = nullptr;
	SendEmuleProtFn          m_send_emule_prot    = nullptr;
	FindBuddyFn              m_find_buddy         = nullptr;
	CreateUtpLayerFn         m_create_utp_layer   = nullptr;

	// Process-level user hash, set via SetOurUserHash. Zero until
	// first set — D3 RequestRendezvous fires failure if our_hash
	// hasn't been provisioned.
	std::array<std::uint8_t, kUserHashSize> m_our_user_hash{};
	bool                                    m_our_user_hash_set = false;
};

// Phase D5a: install the production thunks (defined in
// NatTraversalCoordinatorProduction.cpp) on the singleton
// coordinator. Wires LookupClientByHash → CClientList,
// LookupClientByEndpoint → CDownloadQueue / CUploadQueue,
// SendEmuleProt → CClientUDPSocket::SendPacket, FindBuddy →
// CClientList::GetBuddy (D5a single-buddy; D5b extends to
// served-buddy iterator), CreateUtpLayer → new CUtpLayer +
// Connect against UtpEnvironment's context. Also publishes the
// process-level user hash from thePrefs::GetUserHash().
//
// Called once at daemon startup from CClientUDPSocket's ctor,
// next to UtpEncryption::InstallProductionDelegates (B6) and
// UtpTimer::Start (B7). Tests deliberately do NOT call this —
// they install their own lightweight stubs via the individual
// CNatTraversalCoordinator::SetXxxDelegate methods.
void InstallNatTraversalCoordinatorProductionDelegates();

} // namespace NatTraversal

#endif // ENABLE_NAT_T

#endif // NATTRAVERSALCOORDINATOR_H
