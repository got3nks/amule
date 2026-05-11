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

#include "NatTraversalCoordinator.h"

#ifdef ENABLE_NAT_T

#include <cstring>
#include <vector>

namespace NatTraversal {

constexpr std::uint64_t CNatTraversalCoordinator::kRendezvousTimeoutMs;

CNatTraversalCoordinator& CNatTraversalCoordinator::Instance()
{
	// Meyers singleton. Construction is thread-safe in C++11+
	// (static-local initialisation under the function-local
	// init-once guard). Lives for process lifetime.
	static CNatTraversalCoordinator s_instance;
	return s_instance;
}

void CNatTraversalCoordinator::SetLookupClientByHashDelegate(LookupClientByHashFn fn)
{
	m_lookup_by_hash = fn;
}

void CNatTraversalCoordinator::SetLookupClientByEndpointDelegate(LookupClientByEndpointFn fn)
{
	m_lookup_by_endpoint = fn;
}

void CNatTraversalCoordinator::SetSendEmuleProtDelegate(SendEmuleProtFn fn)
{
	m_send_emule_prot = fn;
}

void CNatTraversalCoordinator::RequestRendezvous(
	const std::uint8_t target_user_hash[kUserHashSize],
	const struct sockaddr* target_addr_hint,
	socklen_t addr_hint_len,
	RendezvousCompleteFn on_complete)
{
	if (target_user_hash == nullptr || target_addr_hint == nullptr ||
	    addr_hint_len == 0 || !on_complete) {
		// Defensive: nothing to do if any required arg is missing.
		// Invoke the callback with failure if it's present, so the
		// caller's logic stays consistent (no abandoned coroutine
		// on the requester side).
		if (on_complete) {
			on_complete(false, nullptr);
		}
		return;
	}

	// Stage the new entry before touching the table, so the
	// "replace existing" path can hand off any cancelled callback
	// to be invoked AFTER the lock is released.
	RendezvousCompleteFn cancelled_cb;
	HashKey key;
	std::memcpy(key.data(), target_user_hash, kUserHashSize);

	PendingRendezvous pending;
	pending.deadline_ms = 0;  // set by next CheckTimeouts; placeholder
	pending.target_addr.assign(
		reinterpret_cast<const std::uint8_t*>(target_addr_hint),
		reinterpret_cast<const std::uint8_t*>(target_addr_hint) + addr_hint_len);
	pending.target_addr_len = addr_hint_len;
	pending.on_complete = std::move(on_complete);

	{
		std::lock_guard<std::mutex> lock(m_lock);
		auto existing = m_pending.find(key);
		if (existing != m_pending.end()) {
			cancelled_cb = std::move(existing->second.on_complete);
			m_pending.erase(existing);
		}
		m_pending[key] = std::move(pending);
	}

	// Fire the cancelled callback (if any) without the lock held —
	// the callback may re-enter the coordinator (e.g. to immediately
	// issue a fresh RequestRendezvous as a fallback).
	if (cancelled_cb) {
		cancelled_cb(false, nullptr);
	}
}

void CNatTraversalCoordinator::OnInboundRendezvous(
	const RendezvousRequest& req,
	std::uint32_t src_ip_host,
	std::uint16_t src_port)
{
	// Dispatch on req.has_ext_endpoint:
	//   - false → we are the BUDDY, req came directly from the LowID
	//     requester. Forward to the target LowID endpoint + emit
	//     HOLEPUNCH back to the requester.
	//   - true  → we are the ENDPOINT (D4, future); req came from a
	//     buddy forwarding the requester's RENDEZVOUS; prep a passive
	//     CUtpLayer keyed to req.requester_ext_endpoint.

	if (!req.has_ext_endpoint) {
		// === BUDDY ROLE (D2) ====================================
		//
		// Look up where the target LowID peer is. We're a HighID
		// buddy by virtue of having a UDP-reachable connection to
		// the target; if we don't know them, we silently drop —
		// the requester will retry with a different buddy
		// candidate, or eventually time out.
		if (m_lookup_by_hash == nullptr || m_send_emule_prot == nullptr) {
			// Delegates not installed (test paths or pre-startup).
			return;
		}

		std::uint32_t target_ip   = 0;
		std::uint16_t target_port = 0;
		if (!m_lookup_by_hash(req.target_user_hash, target_ip, target_port)) {
			// We don't know this target — not our problem to relay.
			return;
		}

		// Forward OP_RENDEZVOUS to the target. The body carries the
		// original target_user_hash + connect_options, plus the
		// ext_endpoint fields filled in with the requester's
		// observed external address. The target uses ext_endpoint
		// to know where to expect the incoming uTP connection from.
		RendezvousRequest forwarded;
		std::memcpy(forwarded.target_user_hash, req.target_user_hash,
		            kUserHashSize);
		forwarded.connect_options    = req.connect_options;
		forwarded.has_file_hash      = req.has_file_hash;
		if (forwarded.has_file_hash) {
			std::memcpy(forwarded.target_file_hash, req.target_file_hash,
			            kUserHashSize);
		} else {
			std::memset(forwarded.target_file_hash, 0, kUserHashSize);
		}
		forwarded.has_ext_endpoint   = true;
		forwarded.requester_ext_ip   = src_ip_host;
		forwarded.requester_ext_port = src_port;

		std::vector<std::uint8_t> body;
		if (!EncodeRendezvous(forwarded, body)) {
			return;
		}
		m_send_emule_prot(OP_RENDEZVOUS_OPCODE,
		                  body.data(), body.size(),
		                  target_ip, target_port);

		// Send HOLEPUNCH back to the requester. Empty body — the
		// HOLEPUNCH packet is itself the signal that the rendezvous
		// has been relayed and the requester should now start its
		// uTP connect against the target's already-known address.
		m_send_emule_prot(OP_HOLEPUNCH_OPCODE,
		                  nullptr, 0,
		                  src_ip_host, src_port);
		return;
	}

	// req.has_ext_endpoint == true → endpoint (D4) path. Stub for now.
}

void CNatTraversalCoordinator::OnInboundHolePunch(
	std::uint32_t /*src_ip_host*/,
	std::uint16_t /*src_port*/)
{
	// D1 stub. D3 fills this in: look up the pending entry for the
	// HolePunch's source (a buddy), drive utp_connect against the
	// recorded target_addr, hand the resulting CUtpLayer back via
	// on_complete(true, layer). For D1 the table just sits.
}

std::size_t CNatTraversalCoordinator::CheckTimeouts(std::uint64_t now_ms)
{
	// Build a list of expired entries while holding the lock, then
	// fire callbacks outside the lock (callbacks may re-enter the
	// coordinator, e.g. to issue a fresh RequestRendezvous as a
	// fallback). Same pattern UtpLayerRegistry::ForEach uses.
	std::vector<RendezvousCompleteFn> expired_callbacks;

	{
		std::lock_guard<std::mutex> lock(m_lock);
		for (auto it = m_pending.begin(); it != m_pending.end(); ) {
			if (it->second.deadline_ms == 0) {
				// First time we see this entry — set the deadline
				// relative to now. (Done lazily here rather than in
				// RequestRendezvous because Request doesn't yet know
				// the clock value.)
				it->second.deadline_ms = now_ms + kRendezvousTimeoutMs;
				++it;
				continue;
			}
			if (now_ms >= it->second.deadline_ms) {
				expired_callbacks.push_back(std::move(it->second.on_complete));
				it = m_pending.erase(it);
			} else {
				++it;
			}
		}
	}

	for (auto& cb : expired_callbacks) {
		if (cb) {
			cb(false, nullptr);
		}
	}
	return expired_callbacks.size();
}

std::size_t CNatTraversalCoordinator::PendingCount() const
{
	std::lock_guard<std::mutex> lock(m_lock);
	return m_pending.size();
}

void CNatTraversalCoordinator::ClearPendingForTesting()
{
	std::lock_guard<std::mutex> lock(m_lock);
	m_pending.clear();
}

} // namespace NatTraversal

#endif // ENABLE_NAT_T
