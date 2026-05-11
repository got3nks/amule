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

// Tests for Phase B7.5 follow-up F1: UtpLayerRegistry. The registry
// is a process-wide map from peer_hash to CUtpLayer*. These tests
// drive the API directly with raw casts of arbitrary pointers as
// "stub layers" — the registry only stores opaque pointers and
// doesn't dereference them, so it doesn't need real CUtpLayer
// instances to exercise its semantics.

#include <muleunit/test.h>

#include "UtpLayerRegistry.h"

#ifdef ENABLE_NAT_T

#include <cstdint>
#include <cstring>
#include <vector>

using namespace muleunit;

DECLARE(UtpLayerRegistry)
END_DECLARE;


namespace {

// Helper: produce a peer_hash filled with a single byte value. Two
// different `fill` values produce distinct hashes — useful for
// "multiple peers" tests.
void fill_hash(std::uint8_t hash[UtpLayerRegistry::kUserHashSize],
               std::uint8_t fill)
{
	std::memset(hash, fill, UtpLayerRegistry::kUserHashSize);
}

// Stub layer pointer — the registry stores it but never dereferences.
// Casting an integer to CUtpLayer* is OK for this purpose because the
// registry treats the pointer opaquely.
CUtpLayer* stub_layer(std::uintptr_t value)
{
	return reinterpret_cast<CUtpLayer*>(value);
}

} // anonymous namespace


// Register / FindByPeerHash roundtrip.
TEST(UtpLayerRegistry, RegisterAndFindByPeerHash)
{
	UtpLayerRegistry::ClearForTesting();

	std::uint8_t hash_a[UtpLayerRegistry::kUserHashSize];
	std::uint8_t hash_b[UtpLayerRegistry::kUserHashSize];
	fill_hash(hash_a, 0xA0);
	fill_hash(hash_b, 0xB0);

	CUtpLayer* layer_a = stub_layer(0x1111);
	CUtpLayer* layer_b = stub_layer(0x2222);

	UtpLayerRegistry::Register(hash_a, layer_a);
	UtpLayerRegistry::Register(hash_b, layer_b);

	ASSERT_EQUALS((std::size_t)2, UtpLayerRegistry::Size());
	ASSERT_TRUE(UtpLayerRegistry::FindByPeerHash(hash_a) == layer_a);
	ASSERT_TRUE(UtpLayerRegistry::FindByPeerHash(hash_b) == layer_b);

	UtpLayerRegistry::ClearForTesting();
}


// FindByPeerHash returns NULL for an unregistered hash.
TEST(UtpLayerRegistry, FindMissingReturnsNull)
{
	UtpLayerRegistry::ClearForTesting();

	std::uint8_t hash_a[UtpLayerRegistry::kUserHashSize];
	std::uint8_t hash_b[UtpLayerRegistry::kUserHashSize];
	fill_hash(hash_a, 0xA0);
	fill_hash(hash_b, 0xB0);

	UtpLayerRegistry::Register(hash_a, stub_layer(0x1111));

	ASSERT_TRUE(UtpLayerRegistry::FindByPeerHash(hash_b) == NULL);

	UtpLayerRegistry::ClearForTesting();
}


// Unregister by pointer: looks up the layer in the map, removes it
// regardless of which hash it's keyed under.
TEST(UtpLayerRegistry, UnregisterByPointer)
{
	UtpLayerRegistry::ClearForTesting();

	std::uint8_t hash_a[UtpLayerRegistry::kUserHashSize];
	fill_hash(hash_a, 0xA0);

	CUtpLayer* layer_a = stub_layer(0x1111);
	UtpLayerRegistry::Register(hash_a, layer_a);
	ASSERT_EQUALS((std::size_t)1, UtpLayerRegistry::Size());

	UtpLayerRegistry::Unregister(layer_a);
	ASSERT_EQUALS((std::size_t)0, UtpLayerRegistry::Size());
	ASSERT_TRUE(UtpLayerRegistry::FindByPeerHash(hash_a) == NULL);

	UtpLayerRegistry::ClearForTesting();
}


// Unregister with a layer that was never registered is a safe no-op.
TEST(UtpLayerRegistry, UnregisterUnknownIsNoop)
{
	UtpLayerRegistry::ClearForTesting();

	UtpLayerRegistry::Unregister(stub_layer(0xDEAD));
	ASSERT_EQUALS((std::size_t)0, UtpLayerRegistry::Size());

	UtpLayerRegistry::ClearForTesting();
}


// Re-registering the same hash REPLACES the entry. This matches the
// "one active layer per peer" contract — a second Register on the
// same hash usually means a stale layer was leaked.
TEST(UtpLayerRegistry, RegisterReplacesExisting)
{
	UtpLayerRegistry::ClearForTesting();

	std::uint8_t hash[UtpLayerRegistry::kUserHashSize];
	fill_hash(hash, 0xA0);

	CUtpLayer* first  = stub_layer(0x1111);
	CUtpLayer* second = stub_layer(0x2222);

	UtpLayerRegistry::Register(hash, first);
	ASSERT_TRUE(UtpLayerRegistry::FindByPeerHash(hash) == first);

	UtpLayerRegistry::Register(hash, second);
	ASSERT_TRUE(UtpLayerRegistry::FindByPeerHash(hash) == second);
	ASSERT_EQUALS((std::size_t)1, UtpLayerRegistry::Size());

	UtpLayerRegistry::ClearForTesting();
}


// Register with NULL layer removes the entry (equivalent to
// Unregister-by-hash, which isn't exposed directly).
TEST(UtpLayerRegistry, RegisterNullClearsSlot)
{
	UtpLayerRegistry::ClearForTesting();

	std::uint8_t hash[UtpLayerRegistry::kUserHashSize];
	fill_hash(hash, 0xA0);

	UtpLayerRegistry::Register(hash, stub_layer(0x1111));
	ASSERT_EQUALS((std::size_t)1, UtpLayerRegistry::Size());

	UtpLayerRegistry::Register(hash, NULL);
	ASSERT_EQUALS((std::size_t)0, UtpLayerRegistry::Size());

	UtpLayerRegistry::ClearForTesting();
}


// ForEach iterates every registered layer. Snapshot semantics mean
// the callback can safely call back into the registry (e.g.
// Register / Unregister) without deadlock.
TEST(UtpLayerRegistry, ForEachIteratesAll)
{
	UtpLayerRegistry::ClearForTesting();

	std::uint8_t hashes[3][UtpLayerRegistry::kUserHashSize];
	CUtpLayer* layers[3] = {
		stub_layer(0x1111),
		stub_layer(0x2222),
		stub_layer(0x3333),
	};
	for (int i = 0; i < 3; ++i) {
		fill_hash(hashes[i], static_cast<std::uint8_t>(0x10 * (i + 1)));
		UtpLayerRegistry::Register(hashes[i], layers[i]);
	}

	std::vector<CUtpLayer*> seen;
	UtpLayerRegistry::ForEach([&seen](CUtpLayer* layer) {
		seen.push_back(layer);
	});
	ASSERT_EQUALS((std::size_t)3, seen.size());

	// Order is map-dependent (sorted by key bytes). All three must
	// appear; we don't assert order.
	bool found0 = false, found1 = false, found2 = false;
	for (CUtpLayer* l : seen) {
		if (l == layers[0]) found0 = true;
		if (l == layers[1]) found1 = true;
		if (l == layers[2]) found2 = true;
	}
	ASSERT_TRUE(found0);
	ASSERT_TRUE(found1);
	ASSERT_TRUE(found2);

	UtpLayerRegistry::ClearForTesting();
}


// ForEach callback can mutate the registry (Register / Unregister)
// without deadlock. The snapshot has already been taken; subsequent
// mutations don't affect this iteration's seen set.
TEST(UtpLayerRegistry, ForEachCallbackCanReenter)
{
	UtpLayerRegistry::ClearForTesting();

	std::uint8_t hash[UtpLayerRegistry::kUserHashSize];
	fill_hash(hash, 0xA0);
	CUtpLayer* layer = stub_layer(0x1111);
	UtpLayerRegistry::Register(hash, layer);

	bool callback_ran = false;
	UtpLayerRegistry::ForEach([&](CUtpLayer* /*l*/) {
		callback_ran = true;
		// Re-enter — this must not deadlock.
		UtpLayerRegistry::Unregister(layer);
	});

	ASSERT_TRUE(callback_ran);
	ASSERT_EQUALS((std::size_t)0, UtpLayerRegistry::Size());

	UtpLayerRegistry::ClearForTesting();
}


// NULL inputs to Register / FindByPeerHash are tolerated.
TEST(UtpLayerRegistry, NullInputsTolerated)
{
	UtpLayerRegistry::ClearForTesting();

	UtpLayerRegistry::Register(NULL, stub_layer(0x1111));  // no crash
	UtpLayerRegistry::Unregister(NULL);                    // no crash
	ASSERT_TRUE(UtpLayerRegistry::FindByPeerHash(NULL) == NULL);
	ASSERT_EQUALS((std::size_t)0, UtpLayerRegistry::Size());

	UtpLayerRegistry::ClearForTesting();
}

#else

using namespace muleunit;
DECLARE(UtpLayerRegistry)
END_DECLARE;

TEST(UtpLayerRegistry, FeatureDisabled)
{
	ASSERT_TRUE(true);
}

#endif // ENABLE_NAT_T
