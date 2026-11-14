//								-*- C++ -*-
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
//
// Any parts of this program derived from the xMule, lMule or eMule project,
// or contributed by third-party developers are copyrighted by their
// respective authors.
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

#ifndef AMULE_PUBLISHMETRICS_H
#define AMULE_PUBLISHMETRICS_H

#include "LookupTrace.h"
#include <algorithm>
#include <set>
#include <utility>
#include <vector>

namespace Kademlia
{
// Packets of one kind queued to each destination IP in a rolling 60 s window. The receivers'
// limits in PacketTracking.cpp are leaky buckets, so this window is a close approximation.
class CPerIPRate
{
public:
	static constexpr size_t MaxSamples = 65536;
	explicit CPerIPRate(std::vector<uint64_t> thresholds)
	: m_thresholds(std::move(thresholds))
	, m_reached(m_thresholds.size())
	{
	}
	// Returns true when a logged value changed.
	bool Add(uint32_t ip, uint64_t now)
	{
		Expire(now);
		if (m_samples.size() == MaxSamples) {
			++omitted;
			return true;
		}
		m_samples.emplace_back(now, ip);
		const uint64_t count = ++m_counts[ip];
		bool changed = false;
		if (count > peak) {
			peak = count;
			changed = true;
		}
		for (size_t i = 0; i < m_thresholds.size(); ++i) {
			if (count == m_thresholds[i]) {
				changed |= m_reached[i].insert(ip).second;
			}
		}
		return changed;
	}
	void Expire(uint64_t now)
	{
		while (!m_samples.empty() && now - m_samples.front().first >= 60000) {
			auto it = m_counts.find(m_samples.front().second);
			if (--it->second == 0) {
				m_counts.erase(it);
			}
			m_samples.pop_front();
		}
	}
	// The IPs that reached each threshold since the previous call, in threshold order.
	std::vector<std::set<uint32_t>> TakeReached()
	{
		std::vector<std::set<uint32_t>> reached(m_thresholds.size());
		reached.swap(m_reached);
		return reached;
	}
	uint64_t Count(uint32_t ip) const
	{
		const auto it = m_counts.find(ip);
		return it == m_counts.end() ? 0 : it->second;
	}
	uint64_t peak = 0, omitted = 0;

private:
	std::vector<uint64_t> m_thresholds;
	std::vector<std::set<uint32_t>> m_reached;
	std::deque<std::pair<uint64_t, uint32_t>> m_samples;
	std::map<uint32_t, uint64_t> m_counts;
};

// Main-thread diagnostics, called only while the Kademlia Publish category is enabled.
class CPublishMetrics
{
public:
	static CPublishMetrics &Instance()
	{
		static CPublishMetrics metrics;
		return metrics;
	}
	void Attempt(bool started)
	{
		++attempts;
		startFailures += !started;
		++changes;
	}
	void Start()
	{
		++starts;
		++changes;
	}
	void Queued(uint32_t ip, uint64_t now)
	{
		++queued;
		++changes;
		publishRequests.Add(ip, now);
	}
	static uint64_t Acknowledged(const CLookupTrace &trace)
	{
		uint64_t count = 0;
		uint32_t previous = 0;
		bool havePrevious = false;
		for (const auto &peer : trace.Peers()) {
			if (peer.second.itemReplies && (!havePrevious || previous != peer.first.first)) {
				++count;
				previous = peer.first.first;
				havePrevious = true;
			}
		}
		return count;
	}
	void Finish(const CLookupTrace &trace, bool completed, uint64_t elapsed)
	{
		++changes;
		const auto replies = Acknowledged(trace);
		acknowledged += replies;
		if (!completed) {
			++cancelled;
			return;
		}
		++finished;
		zeroAcknowledgements += replies == 0;
		durationMs += elapsed;
		maxDurationMs = std::max(maxDurationMs, elapsed);
	}
	void LookupQueued(uint32_t ip, uint64_t now)
	{
		if (lookupRequests.Add(ip, now)) {
			++changes;
		}
	}
	bool ReportDue(uint64_t now)
	{
		lookupRequests.Expire(now);
		publishRequests.Expire(now);
		if (!reportStarted) {
			reportStarted = true;
			lastReport = now;
			return false;
		}
		if (now - lastReport < 60000) {
			return false;
		}
		lastReport = now;
		if (reportedChanges == changes) {
			return false;
		}
		reportedChanges = changes;
		reportedLookupIPs = lookupRequests.TakeReached();
		reportedPublishIPs = publishRequests.TakeReached();
		return true;
	}
	uint64_t attempts = 0, startFailures = 0, starts = 0;
	uint64_t queued = 0, acknowledged = 0, finished = 0, zeroAcknowledgements = 0, cancelled = 0;
	uint64_t durationMs = 0, maxDurationMs = 0;
	// Receivers drop a KADEMLIA2_REQ above 10 a minute and a KADEMLIA2_PUBLISH_SOURCE_REQ above 2.
	CPerIPRate lookupRequests{ { 6, 8, 11 } };
	CPerIPRate publishRequests{ { 2, 3 } };
	// Set by a due report: the IPs that reached each threshold since the previous one.
	std::vector<std::set<uint32_t>> reportedLookupIPs, reportedPublishIPs;

private:
	bool reportStarted = false;
	uint64_t lastReport = 0, changes = 0, reportedChanges = 0;
};

// Diagnostic only: whether the nodes that stored a file's source are still the ones its next
// lookup finds, which decides if a refresh could skip the lookup.
using StoreNodes = std::map<CLookupTrace::ID, CLookupTrace::Address>;

inline StoreNodes AcknowledgingNodes(const CLookupTrace &trace)
{
	StoreNodes nodes;
	for (const auto &peer : trace.Peers()) {
		if (peer.second.itemReplies) {
			nodes[peer.second.id] = peer.first;
		}
	}
	return nodes;
}

struct SStoreNodeOverlap
{
	uint32_t previous = 0;
	uint32_t queried = 0;      // The lookup asked it again.
	uint32_t replied = 0;      // It answered that request.
	uint32_t acknowledged = 0; // It stored the entry again.
	uint32_t moved = 0;        // Same Kad ID, another address.
	uint32_t replaced = 0;     // Same address, another Kad ID.
};

inline SStoreNodeOverlap CompareStoreNodes(const StoreNodes &previous, const CLookupTrace &trace)
{
	std::map<CLookupTrace::ID, std::pair<CLookupTrace::Address, const CLookupTrace::Peer *>> byID;
	for (const auto &peer : trace.Peers()) {
		byID[peer.second.id] = { peer.first, &peer.second };
	}
	SStoreNodeOverlap overlap;
	for (const auto &node : previous) {
		++overlap.previous;
		const auto found = byID.find(node.first);
		if (found == byID.end()) {
			const auto atAddress = trace.Peers().find(node.second);
			if (atAddress != trace.Peers().end() && atAddress->second.id != node.first) {
				++overlap.replaced;
			}
			continue;
		}
		const CLookupTrace::Peer &peer = *found->second.second;
		overlap.queried += peer.requests ? 1 : 0;
		overlap.replied += peer.replies ? 1 : 0;
		overlap.acknowledged += peer.itemReplies ? 1 : 0;
		overlap.moved += found->second.first != node.second ? 1 : 0;
	}
	return overlap;
}

// The nodes that acknowledged, plus spares: nodes that answered inside the store tolerance
// but were not stored on, closest first, up to `limit` nodes in all.
struct SStoreSet
{
	StoreNodes acked;
	StoreNodes spares;
};

inline SStoreSet StoreCandidates(const CLookupTrace &trace, size_t limit = 20)
{
	SStoreSet set;
	set.acked = AcknowledgingNodes(trace);
	std::vector<std::pair<CLookupTrace::ID,
		const std::pair<const CLookupTrace::Address, CLookupTrace::Peer> *>>
		others;
	for (const auto &peer : trace.Peers()) {
		// SEARCHTOLERANCE: the top 8 distance bits are zero.
		if (!peer.second.itemReplies && peer.second.replies && peer.second.distance[0] == 0) {
			others.emplace_back(peer.second.distance, &peer);
		}
	}
	std::sort(
		others.begin(), others.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
	for (const auto &other : others) {
		if (set.acked.size() + set.spares.size() >= limit) {
			break;
		}
		set.spares[other.second->second.id] = other.second->first;
	}
	return set;
}

struct SSpareOverlap
{
	uint32_t spares = 0;
	uint32_t sparesReplied = 0; // Still answers a lookup.
	uint32_t sparesAcked = 0;   // Stored it this time.
	uint32_t fresh = 0;         // Stored it this time, in neither previous set.
	uint32_t freshReferred = 0; // ...and a node of the previous sets pointed to it.
};

inline SSpareOverlap CompareSpares(const SStoreSet &previous, const CLookupTrace &trace)
{
	std::map<CLookupTrace::ID, const CLookupTrace::Peer *> byID;
	for (const auto &peer : trace.Peers()) {
		byID[peer.second.id] = &peer.second;
	}
	SSpareOverlap overlap;
	for (const auto &spare : previous.spares) {
		++overlap.spares;
		const auto found = byID.find(spare.first);
		if (found != byID.end()) {
			overlap.sparesReplied += found->second->replies ? 1 : 0;
			overlap.sparesAcked += found->second->itemReplies ? 1 : 0;
		}
	}
	const auto known = [&previous](const CLookupTrace::ID &id) {
		return previous.acked.count(id) || previous.spares.count(id);
	};
	for (const auto &peer : trace.Peers()) {
		if (!peer.second.itemReplies || known(peer.second.id)) {
			continue;
		}
		++overlap.fresh;
		for (auto it = trace.Mentions().lower_bound({ peer.first, {} });
			it != trace.Mentions().end() && it->first == peer.first;
			++it) {
			const auto source = trace.Peers().find(it->second);
			if (source != trace.Peers().end() && known(source->second.id)) {
				++overlap.freshReferred;
				break;
			}
		}
	}
	return overlap;
}

// Diagnostic only: one source-publish lookup that did not store, to compare a lookup seeded
// with the last nodes against one started from the routing table.
struct SDryLookup
{
	uint32_t requests = 0;
	uint32_t far = 0; // Nodes asked outside the store tolerance: hops lookups share.
	std::set<CLookupTrace::ID> queried, replied, stored;
	std::map<CLookupTrace::ID, CLookupTrace::ID> near; // Distance to ID, answered inside tolerance.
};

inline SDryLookup SummariseDryLookup(const CLookupTrace &trace)
{
	SDryLookup lookup;
	for (const auto &peer : trace.Peers()) {
		const CLookupTrace::Peer &row = peer.second;
		if (!row.requests) {
			continue;
		}
		lookup.requests += row.requests;
		lookup.queried.insert(row.id);
		// SEARCHTOLERANCE: the top 8 distance bits are zero.
		lookup.far += row.distance[0] != 0 ? 1 : 0;
		if (row.replies) {
			lookup.replied.insert(row.id);
			if (row.distance[0] == 0) {
				lookup.near[row.distance] = row.id;
			}
		}
		if (row.itemRequests) {
			lookup.stored.insert(row.id);
		}
	}
	return lookup;
}

struct SDryComparison
{
	uint32_t reference = 0; // Closest nodes either lookup heard from inside the tolerance.
	uint32_t seededRecall = 0;
	uint32_t fullRecall = 0;
	uint32_t common = 0; // Stored by both.
};

inline SDryComparison CompareDryLookups(const SDryLookup &seeded, const SDryLookup &full, size_t size = 10)
{
	std::map<CLookupTrace::ID, CLookupTrace::ID> near = seeded.near;
	near.insert(full.near.begin(), full.near.end());
	SDryComparison comparison;
	for (const auto &node : near) {
		if (comparison.reference == size) {
			break;
		}
		++comparison.reference;
		comparison.seededRecall += seeded.stored.count(node.second) ? 1 : 0;
		comparison.fullRecall += full.stored.count(node.second) ? 1 : 0;
	}
	for (const auto &id : seeded.stored) {
		comparison.common += full.stored.count(id) ? 1 : 0;
	}
	return comparison;
}
} // namespace Kademlia
#endif
