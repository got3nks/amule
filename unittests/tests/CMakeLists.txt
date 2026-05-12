add_executable (CTagTest
	CTagTest.cpp
	${CMAKE_SOURCE_DIR}/src/SafeFile.cpp
	${CMAKE_SOURCE_DIR}/src/MemFile.cpp
	${CMAKE_SOURCE_DIR}/src/Tag.cpp
)

add_test (NAME CTagTest
	COMMAND CTagTest
)

target_include_directories (CTagTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (CTagTest
	muleunit
)

add_executable (CUInt128Test
	CUInt128Test.cpp
	${CMAKE_SOURCE_DIR}/src/kademlia/utils/UInt128.cpp
)

add_test (NAME CUInt128Test
	COMMAND CUInt128Test
)

target_include_directories (CUInt128Test
	PRIVATE ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries (CUInt128Test
	muleunit
)

add_executable (FileDataIOTest
	FileDataIOTest.cpp
	${CMAKE_SOURCE_DIR}/src/SafeFile.cpp
	${CMAKE_SOURCE_DIR}/src/CFile.cpp
	${CMAKE_SOURCE_DIR}/src/MemFile.cpp
	${CMAKE_SOURCE_DIR}/src/kademlia/utils/UInt128.cpp
	${CMAKE_SOURCE_DIR}/src/Tag.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Path.cpp
)

add_test (NAME FileDataIOTest
	COMMAND FileDataIOTest
)

target_include_directories (FileDataIOTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (FileDataIOTest
	muleunit
)

add_executable (FormatTest
	FormatTest.cpp
)

add_test (NAME FormatTest
	COMMAND FormatTest
)

target_include_directories (FormatTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries (FormatTest
	muleunit
)

add_executable (NetworkFunctionsTest
	NetworkFunctionsTest.cpp
	${CMAKE_SOURCE_DIR}/src/NetworkFunctions.cpp
	${CMAKE_SOURCE_DIR}/src/LibSocket.cpp
)

add_test (NAME NetworkFunctionsTest
	COMMAND NetworkFunctionsTest
)

target_compile_definitions (NetworkFunctionsTest
	PRIVATE "EC_REMOTE"
)

target_include_directories (NetworkFunctionsTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_include_directories (NetworkFunctionsTest
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (NetworkFunctionsTest
	${Boost_LIBRARIES}
)

target_link_libraries (NetworkFunctionsTest
	muleunit
	wxWidgets::NET
)

add_executable (PathTest
	PathTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Path.cpp
)

add_test (NAME PathTest
	COMMAND PathTest
)

target_link_libraries (PathTest
	muleunit
)

add_executable (RangeMapTest
	RangeMapTest.cpp
)

add_test (NAME RangeMapTest
	COMMAND RangeMapTest
)

target_include_directories (RangeMapTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries (RangeMapTest
	muleunit
)

add_executable (StringFunctionsTest
	StringFunctionsTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Path.cpp
)

add_test (NAME StringFunctionsTest
	COMMAND StringFunctionsTest
)

target_link_libraries (StringFunctionsTest
	muleunit
)

add_executable (TextFileTest
	TextFileTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Path.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/TextFile.cpp
)

add_test (NAME TextFileTest
	COMMAND TextFileTest
)

target_compile_definitions (TextFileTest
	PRIVATE "SRCDIR=${CMAKE_CURRENT_SOURCE_DIR}"
)

target_include_directories (TextFileTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (TextFileTest
	muleunit
)

# Phase A1 of the NAT-T port: smoke-test that the vendored libutp at utp/
# builds and links. Only compiled when ENABLE_NAT_T=YES; if NAT-T is off
# the utp target doesn't exist, so this test is omitted from the suite.
if (ENABLE_NAT_T)
	add_executable (LibUtpLinkTest
		LibUtpLinkTest.cpp
	)

	add_test (NAME LibUtpLinkTest
		COMMAND LibUtpLinkTest
	)

	target_include_directories (LibUtpLinkTest
		PRIVATE ${CMAKE_SOURCE_DIR}/src
		PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	)

	target_link_libraries (LibUtpLinkTest
		muleunit
		utp
	)
endif()

# Phase A3 of the NAT-T port: pure-function tests for the connect-options
# byte's NAT-T capability bit. Compiled unconditionally (the helpers live
# in a header-only namespace so the test doesn't depend on ENABLE_NAT_T).
add_executable (NatTraversalTest
	NatTraversalTest.cpp
)

add_test (NAME NatTraversalTest
	COMMAND NatTraversalTest
)

target_include_directories (NatTraversalTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (NatTraversalTest
	muleunit
)

# Phase A2 of the NAT-T port: cross-platform network-introspection shim
# (PMTU + best-interface discovery). Self-tests against the loopback
# interface — no internet required. Compiled unconditionally; the
# Windows stub still produces meaningful assertions for that platform.
add_executable (NetworkInfoTest
	NetworkInfoTest.cpp
	${CMAKE_SOURCE_DIR}/src/NetworkInfo.cpp
)

add_test (NAME NetworkInfoTest
	COMMAND NetworkInfoTest
)

target_include_directories (NetworkInfoTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (NetworkInfoTest
	muleunit
)

# Phase B1 of the NAT-T port: the global libutp context owner +
# runtime lock. The test pulls in UtpEnvironment.cpp directly so it
# doesn't depend on the rest of the amuled object set. When
# ENABLE_NAT_T=OFF the test still compiles (UtpEnvironment.cpp's body
# is a no-op #ifdef'd out, and the test registers a single
# always-passes case) but it skips the libutp link — so we only link
# `utp` into the test target when the feature is on.
add_executable (UtpEnvironmentTest
	UtpEnvironmentTest.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEnvironment.cpp
	${CMAKE_SOURCE_DIR}/src/UtpCallbacks.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayer.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEncryption.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayerRegistry.cpp
)

add_test (NAME UtpEnvironmentTest
	COMMAND UtpEnvironmentTest
)

target_include_directories (UtpEnvironmentTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpEnvironmentTest
	muleunit
)

if (ENABLE_NAT_T)
	target_link_libraries (UtpEnvironmentTest
		utp
	)
endif()

# Phase B2 of the NAT-T port: libutp callback implementations. The
# test creates its own utp_context (not via UtpEnvironment) so the
# install/sendto-delegate flow can be exercised in isolation without
# tearing down the singleton state across tests. When ENABLE_NAT_T=OFF
# the test compiles to a single tautological case and skips the libutp
# link, matching UtpEnvironmentTest's pattern.
add_executable (UtpCallbacksTest
	UtpCallbacksTest.cpp
	${CMAKE_SOURCE_DIR}/src/UtpCallbacks.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayer.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEnvironment.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEncryption.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayerRegistry.cpp
)

add_test (NAME UtpCallbacksTest
	COMMAND UtpCallbacksTest
)

target_include_directories (UtpCallbacksTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpCallbacksTest
	muleunit
)

if (ENABLE_NAT_T)
	target_link_libraries (UtpCallbacksTest
		utp
	)
endif()

# Phase B3 of the NAT-T port: CUtpLayer — per-connection wrapper
# around a utp_socket with its 16 KiB write buffer + 64 KiB read
# buffer. The test exercises buffer-capacity, FIFO ordering,
# short-write semantics, close behavior, and the OnXxx callback paths
# WITHOUT bringing up a real wire connection — Phase B6/B8 cover that.
# UtpLayer.cpp depends on UtpEnvironment.cpp (for RuntimeLock) and on
# UtpCallbacks.cpp (transitively through nothing at link time, but
# kept consistent for the linker's sake).
add_executable (UtpLayerTest
	UtpLayerTest.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayer.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEnvironment.cpp
	${CMAKE_SOURCE_DIR}/src/UtpCallbacks.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEncryption.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayerRegistry.cpp
)

add_test (NAME UtpLayerTest
	COMMAND UtpLayerTest
)

target_include_directories (UtpLayerTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpLayerTest
	muleunit
)

if (ENABLE_NAT_T)
	target_link_libraries (UtpLayerTest
		utp
	)
endif()

# Phase B4 of the NAT-T port: Key Frame encoder/parser. Pure-function
# byte-level tests with no libutp dependency, so the test is
# compiled unconditionally (matches the NatTraversalTest pattern from
# Phase A3).
add_executable (UtpKeyFrameTest
	UtpKeyFrameTest.cpp
	${CMAKE_SOURCE_DIR}/src/UtpKeyFrame.cpp
)

add_test (NAME UtpKeyFrameTest
	COMMAND UtpKeyFrameTest
)

target_include_directories (UtpKeyFrameTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpKeyFrameTest
	muleunit
)

# Phase B5 of the NAT-T port: encryption wrapping for the
# OP_UDPRESERVEDPROT2 envelope. The test deliberately does NOT pull
# in UtpEncryptionProduction.cpp — those thunks call into
# CEncryptedDatagramSocket which reaches into theApp / thePrefs /
# theStats. The framework half (UtpEncryption.cpp) plus mock
# encrypt/decrypt delegates installed by the test is enough to verify
# envelope framing, delegate dispatch, and the encrypt→decrypt
# roundtrip property. B8's loopback integration test exercises the
# real RC4 path end-to-end.
add_executable (UtpEncryptionTest
	UtpEncryptionTest.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEncryption.cpp
	${CMAKE_SOURCE_DIR}/src/UtpKeyFrame.cpp
)

add_test (NAME UtpEncryptionTest
	COMMAND UtpEncryptionTest
)

target_include_directories (UtpEncryptionTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpEncryptionTest
	muleunit
)

# Phase B6 of the NAT-T port: CUtpLayer state-machine connect flow.
# Pulls UtpLayer + UtpCallbacks + UtpEncryption + UtpKeyFrame +
# UtpEnvironment so the layer's Connect path can encrypt the Key
# Frame, send it via the test sendto delegate, and drive
# utp_connect — all in a single test process without touching real
# UDP. Production thunks (UtpEncryptionProduction.cpp) deliberately
# stay out of the test link.
add_executable (UtpConnectFlowTest
	UtpConnectFlowTest.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayer.cpp
	${CMAKE_SOURCE_DIR}/src/UtpCallbacks.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEnvironment.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEncryption.cpp
	${CMAKE_SOURCE_DIR}/src/UtpKeyFrame.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayerRegistry.cpp
)

add_test (NAME UtpConnectFlowTest
	COMMAND UtpConnectFlowTest
)

target_include_directories (UtpConnectFlowTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpConnectFlowTest
	muleunit
)

if (ENABLE_NAT_T)
	target_link_libraries (UtpConnectFlowTest
		utp
	)
endif()

# Phase B7 of the NAT-T port: periodic libutp tick driver. The test
# runs the worker thread without a live utp_context — the worker's
# null-context skip path is exercised, and the tick counter is the
# direct proxy for "utp_check_timeouts was called approximately N
# times". UtpTimer depends on UtpEnvironment (for RuntimeLock +
# GetContext) so both .cpps go into the test target. When
# ENABLE_NAT_T=OFF the test compiles to the FeatureDisabled
# tautology + skips the libutp link.
add_executable (UtpTimerTest
	UtpTimerTest.cpp
	${CMAKE_SOURCE_DIR}/src/UtpTimer.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEnvironment.cpp
	${CMAKE_SOURCE_DIR}/src/UtpCallbacks.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayer.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEncryption.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayerRegistry.cpp
)

add_test (NAME UtpTimerTest
	COMMAND UtpTimerTest
)

target_include_directories (UtpTimerTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpTimerTest
	muleunit
)

if (ENABLE_NAT_T)
	target_link_libraries (UtpTimerTest
		utp
	)
endif()

# Phase B7.5 of the NAT-T port: UtpLayerRegistry (follow-up F1).
# The registry stores opaque CUtpLayer* values without dereferencing
# them, so the test can pass synthetic pointers and skip the rest of
# the NAT-T link chain. Compiles unconditionally; the test body
# itself is guarded on ENABLE_NAT_T.
add_executable (UtpLayerRegistryTest
	UtpLayerRegistryTest.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayerRegistry.cpp
)

add_test (NAME UtpLayerRegistryTest
	COMMAND UtpLayerRegistryTest
)

target_include_directories (UtpLayerRegistryTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpLayerRegistryTest
	muleunit
)

# Phase B8 of the NAT-T port: end-of-phase integration test. Drives
# the full bidirectional handshake (Key Frame exchange + uTP
# SYN/SYN-ACK) and a 64 KiB data round-trip via an in-process router
# that replays sendto-delegate captures into the recipient side's
# inbound dispatch. Pulls EVERY Utp* TU into the link since the test
# exercises end-to-end behavior — initiator side, responder side,
# timer, encryption, registry, callbacks.
add_executable (UtpLoopbackIntegrationTest
	UtpLoopbackIntegrationTest.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayer.cpp
	${CMAKE_SOURCE_DIR}/src/UtpCallbacks.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEnvironment.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEncryption.cpp
	${CMAKE_SOURCE_DIR}/src/UtpKeyFrame.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayerRegistry.cpp
)

add_test (NAME UtpLoopbackIntegrationTest
	COMMAND UtpLoopbackIntegrationTest
)

target_include_directories (UtpLoopbackIntegrationTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpLoopbackIntegrationTest
	muleunit
)

if (ENABLE_NAT_T)
	target_link_libraries (UtpLoopbackIntegrationTest
		utp
	)
endif()

# Phase C2 of the NAT-T port: OP_RENDEZVOUS / OP_HOLEPUNCH wire-format
# encoders / parsers. Pure-function byte-level tests with no libutp
# dependency; compiled unconditionally (matches NatTraversalTest
# pattern from Phase A3).
add_executable (NatTraversalRendezvousTest
	NatTraversalRendezvousTest.cpp
	${CMAKE_SOURCE_DIR}/src/NatTraversal.cpp
)

add_test (NAME NatTraversalRendezvousTest
	COMMAND NatTraversalRendezvousTest
)

target_include_directories (NatTraversalRendezvousTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (NatTraversalRendezvousTest
	muleunit
)

# Phase D1 of the NAT-T port: NatTraversalCoordinator skeleton.
# The pending-rendezvous table + timeout management is testable in
# isolation; D2/D3/D4 role-specific behavior arrives in subsequent
# sub-commits with their own tests.
add_executable (NatTraversalCoordinatorTest
	NatTraversalCoordinatorTest.cpp
	${CMAKE_SOURCE_DIR}/src/NatTraversalCoordinator.cpp
	${CMAKE_SOURCE_DIR}/src/NatTraversal.cpp
)

add_test (NAME NatTraversalCoordinatorTest
	COMMAND NatTraversalCoordinatorTest
)

target_include_directories (NatTraversalCoordinatorTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (NatTraversalCoordinatorTest
	muleunit
)

# Phase D6 of the NAT-T port: 3-node integration test for the
# rendezvous state machine. Stands up three independent
# CNatTraversalCoordinator instances (requester / buddy / endpoint)
# and connects them via an in-process router, mirroring the
# wire-level dispatch that CClientUDPSocket performs in production.
# The actual uTP handshake is already covered by B8's loopback
# test; D6 verifies rendezvous correctness across nodes.
add_executable (NatTraversalIntegrationTest
	NatTraversalIntegrationTest.cpp
	${CMAKE_SOURCE_DIR}/src/NatTraversalCoordinator.cpp
	${CMAKE_SOURCE_DIR}/src/NatTraversal.cpp
)

add_test (NAME NatTraversalIntegrationTest
	COMMAND NatTraversalIntegrationTest
)

target_include_directories (NatTraversalIntegrationTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (NatTraversalIntegrationTest
	muleunit
)
