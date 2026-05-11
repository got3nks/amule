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

#include "UtpLayerRegistry.h"

#ifdef ENABLE_NAT_T

#include <array>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace UtpLayerRegistry {

namespace {

using HashKey = std::array<std::uint8_t, kUserHashSize>;
using AddrKey = std::string;  // raw sockaddr bytes; std::string supports binary content

// File-scope state. Single global maps (process-wide singleton
// matching UtpEnvironment's). std::map gives O(log n) for the
// small-n case we expect; n is bounded by concurrent NAT-T connects,
// typically < 50.
//
// Two parallel maps: hash-keyed for inbound Key Frame dispatch
// (F2), addr-keyed for outbound wrap in UtpCallbacks::on_sendto
// (libutp's send_to_addr passes NULL for the socket pointer — see
// utp_internal.cpp:712 — so we can't look up via utp_get_userdata).
std::mutex                       g_lock;
std::map<HashKey, CUtpLayer*>    g_byHash;
std::map<AddrKey, CUtpLayer*>    g_byAddr;

HashKey MakeHashKey(const std::uint8_t peer_hash[kUserHashSize])
{
	HashKey key;
	std::memcpy(key.data(), peer_hash, kUserHashSize);
	return key;
}

AddrKey MakeAddrKey(const struct sockaddr* addr, socklen_t addr_len)
{
	if (addr == nullptr || addr_len == 0) {
		return AddrKey();
	}
	return AddrKey(reinterpret_cast<const char*>(addr), addr_len);
}

} // anonymous namespace

void Register(const std::uint8_t peer_hash[kUserHashSize],
              CUtpLayer* layer,
              const struct sockaddr* peer_addr,
              socklen_t addr_len)
{
	if (peer_hash == NULL) {
		return;
	}
	std::lock_guard<std::mutex> lock(g_lock);
	HashKey hash_key = MakeHashKey(peer_hash);
	AddrKey addr_key = MakeAddrKey(peer_addr, addr_len);
	if (layer == NULL) {
		g_byHash.erase(hash_key);
		if (!addr_key.empty()) {
			g_byAddr.erase(addr_key);
		}
	} else {
		g_byHash[hash_key] = layer;  // replaces any prior entry
		if (!addr_key.empty()) {
			g_byAddr[addr_key] = layer;
		}
	}
}

void Unregister(CUtpLayer* layer)
{
	if (layer == NULL) {
		return;
	}
	std::lock_guard<std::mutex> lock(g_lock);
	for (auto it = g_byHash.begin(); it != g_byHash.end(); ) {
		if (it->second == layer) {
			it = g_byHash.erase(it);
		} else {
			++it;
		}
	}
	for (auto it = g_byAddr.begin(); it != g_byAddr.end(); ) {
		if (it->second == layer) {
			it = g_byAddr.erase(it);
		} else {
			++it;
		}
	}
}

CUtpLayer* FindByPeerHash(const std::uint8_t peer_hash[kUserHashSize])
{
	if (peer_hash == NULL) {
		return NULL;
	}
	std::lock_guard<std::mutex> lock(g_lock);
	HashKey key = MakeHashKey(peer_hash);
	auto it = g_byHash.find(key);
	if (it == g_byHash.end()) {
		return NULL;
	}
	return it->second;
}

CUtpLayer* FindByPeerAddr(const struct sockaddr* addr, socklen_t addr_len)
{
	if (addr == NULL || addr_len == 0) {
		return NULL;
	}
	std::lock_guard<std::mutex> lock(g_lock);
	AddrKey key = MakeAddrKey(addr, addr_len);
	auto it = g_byAddr.find(key);
	if (it == g_byAddr.end()) {
		return NULL;
	}
	return it->second;
}

void ForEach(std::function<void(CUtpLayer*)> fn)
{
	// Take the registry mutex briefly to snapshot the layer pointers,
	// then release before invoking fn — that way fn can safely call
	// back into Register/Unregister without deadlock (e.g. a layer's
	// CheckTimeoutNow path may trigger a state transition that
	// unregisters the layer). Iteration is over the hash-keyed
	// map (the primary index — every layer registers there).
	std::vector<CUtpLayer*> snapshot;
	{
		std::lock_guard<std::mutex> lock(g_lock);
		snapshot.reserve(g_byHash.size());
		for (auto& kv : g_byHash) {
			snapshot.push_back(kv.second);
		}
	}
	for (CUtpLayer* layer : snapshot) {
		fn(layer);
	}
}

std::size_t Size()
{
	std::lock_guard<std::mutex> lock(g_lock);
	return g_byHash.size();
}

void ClearForTesting()
{
	std::lock_guard<std::mutex> lock(g_lock);
	g_byHash.clear();
	g_byAddr.clear();
}

} // namespace UtpLayerRegistry

#endif // ENABLE_NAT_T
