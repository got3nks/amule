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

#include <arpa/inet.h>     // htons / htonl
#include <cstring>
#include <netinet/in.h>    // sockaddr_in
#include <sys/socket.h>    // AF_INET, sockaddr
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

void CNatTraversalCoordinator::SetFindBuddyDelegate(FindBuddyFn fn)
{
	m_find_buddy = fn;
}

void CNatTraversalCoordinator::SetCreateUtpLayerDelegate(CreateUtpLayerFn fn)
{
	m_create_utp_layer = fn;
}

void CNatTraversalCoordinator::SetOurUserHash(const std::uint8_t our_hash[kUserHashSize])
{
	if (our_hash == nullptr) {
		m_our_user_hash_set = false;
		return;
	}
	std::memcpy(m_our_user_hash.data(), our_hash, kUserHashSize);
	m_our_user_hash_set = true;
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

	// Pre-flight checks for the D3 requester role: we need our own
	// user hash provisioned, a way to find a buddy, and a way to
	// emit the OP_RENDEZVOUS packet. If any is missing, fail fast.
	if (!m_our_user_hash_set || m_find_buddy == nullptr ||
	    m_send_emule_prot == nullptr) {
		on_complete(false, nullptr);
		return;
	}

	// Locate a buddy candidate. D3's single-shot lookup is replaced
	// by D5's Kad-search candidate iterator. For now, if there's
	// no buddy available, fail synchronously.
	std::uint32_t buddy_ip   = 0;
	std::uint16_t buddy_port = 0;
	if (!m_find_buddy(buddy_ip, buddy_port)) {
		on_complete(false, nullptr);
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
	pending.buddy_ip_host   = buddy_ip;
	pending.buddy_udp_port  = buddy_port;
	std::memcpy(pending.peer_user_hash.data(), target_user_hash, kUserHashSize);
	pending.our_user_hash = m_our_user_hash;

	{
		std::lock_guard<std::mutex> lock(m_lock);
		auto existing = m_pending.find(key);
		if (existing != m_pending.end()) {
			cancelled_cb = std::move(existing->second.on_complete);
			m_pending.erase(existing);
		}
		m_pending[key] = std::move(pending);
	}

	// Emit OP_RENDEZVOUS to the buddy. Body carries the target user
	// hash + connect_options (no ext_endpoint — that's the buddy's
	// job to fill in when forwarding to the endpoint, see D2's
	// OnInboundRendezvous).
	RendezvousRequest out_req;
	std::memcpy(out_req.target_user_hash, target_user_hash, kUserHashSize);
	out_req.connect_options    = 0;       // TODO Phase E: from CUpDownClient
	out_req.has_file_hash      = false;
	out_req.has_ext_endpoint   = false;
	std::vector<std::uint8_t> body;
	if (EncodeRendezvous(out_req, body)) {
		m_send_emule_prot(OP_RENDEZVOUS_OPCODE,
		                  body.data(), body.size(),
		                  buddy_ip, buddy_port);
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

	// === ENDPOINT ROLE (D4) =====================================
	//
	// req.has_ext_endpoint == true → a HighID buddy has forwarded
	// us a RENDEZVOUS naming a LowID requester R that wants to
	// reach us. The buddy filled req.requester_ext_endpoint with
	// R's external (NAT-translated) UDP address. Our job:
	//
	//   1. Look up R's user hash via the endpoint lookup delegate.
	//      R must already be a known client to us (typically from a
	//      prior eD2k source-exchange or Kad publish); if we don't
	//      recognise them, drop the rendezvous — the requester's
	//      uTP SYN will reach our libutp but our on_accept won't
	//      find a registered layer at FindByPeerAddr, so libutp
	//      rejects via utp_close. That's the correct fallback —
	//      the rendezvous fails cleanly.
	//
	//   2. Create a passive CUtpLayer (initiator=false) keyed to
	//      R's hash + R's external address. The factory's
	//      production thunk wires the layer into UtpLayerRegistry
	//      so libutp's on_accept finds it when R's SYN arrives.
	//
	// No callback to fire on the responder path — this is a purely
	// reactive role. The CUtpLayer's caller (typically Phase E's
	// CUpDownClient integration) is the ongoing owner.

	if (!m_our_user_hash_set || m_create_utp_layer == nullptr ||
	    m_lookup_by_endpoint == nullptr) {
		return;
	}

	std::uint8_t requester_hash[kUserHashSize];
	if (!m_lookup_by_endpoint(req.requester_ext_ip,
	                          req.requester_ext_port,
	                          requester_hash)) {
		// Unknown requester — drop.
		return;
	}

	sockaddr_in addr;
	std::memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(req.requester_ext_port);
	addr.sin_addr.s_addr = htonl(req.requester_ext_ip);

	(void)src_ip_host;
	(void)src_port;
	(void)m_create_utp_layer(
		m_our_user_hash.data(),
		requester_hash,
		reinterpret_cast<sockaddr*>(&addr),
		sizeof(addr),
		/*initiator=*/false);
	// Factory owns the layer from here. Returning NULL on factory
	// failure is acceptable — same drop behavior as an unknown
	// requester.
}

void CNatTraversalCoordinator::OnInboundHolePunch(
	std::uint32_t src_ip_host,
	std::uint16_t src_port)
{
	// D3 requester role: an OP_HOLEPUNCH from a buddy signals that
	// our prior OP_RENDEZVOUS reached the LowID endpoint and the
	// endpoint is now ready to accept our incoming uTP. Find the
	// matching pending entry (one whose buddy address == this
	// packet's source), tear it out of the table, create the
	// CUtpLayer, and fire the callback.
	//
	// Multiple pending entries can coexist (one per target).
	// Matching by buddy source lets us serve all of them with the
	// same single OP_HOLEPUNCH carrier — the buddy doesn't have to
	// disambiguate which target the HOLEPUNCH is "for" because the
	// requester's own pending table is keyed on target.

	if (m_create_utp_layer == nullptr) {
		return;
	}

	// Stage the matched entry under the lock, then create the layer
	// + fire the callback outside the lock. Releasing the lock before
	// the callback is consistent with the pattern in RequestRendezvous
	// and CheckTimeouts — the callback may re-enter the coordinator.
	PendingRendezvous matched;
	bool found = false;
	{
		std::lock_guard<std::mutex> lock(m_lock);
		for (auto it = m_pending.begin(); it != m_pending.end(); ++it) {
			if (it->second.buddy_ip_host == src_ip_host &&
			    it->second.buddy_udp_port == src_port) {
				matched = std::move(it->second);
				m_pending.erase(it);
				found = true;
				break;
			}
		}
	}

	if (!found) {
		// Unsolicited HOLEPUNCH — either a stale buddy or routing
		// confusion. Silently drop; we have no state to advance.
		return;
	}

	// Create the CUtpLayer for the requester side. peer_addr is the
	// target's external (NAT-translated) UDP endpoint, recorded at
	// RequestRendezvous time. The factory is responsible for
	// wiring Connect(initiator=true) so libutp's SYN goes out to
	// peer_addr.
	const struct sockaddr* peer = reinterpret_cast<const struct sockaddr*>(
		matched.target_addr.data());
	CUtpLayer* layer = m_create_utp_layer(
		matched.our_user_hash.data(),
		matched.peer_user_hash.data(),
		peer,
		matched.target_addr_len,
		/*initiator=*/true);

	const bool ok = (layer != nullptr);
	if (matched.on_complete) {
		matched.on_complete(ok, layer);
	}
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
