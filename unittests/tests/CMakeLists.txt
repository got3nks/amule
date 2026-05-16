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
	# LibSocket.cpp transitively #includes LibSocketAsio.cpp on
	# ENABLE_BOOST builds, which calls SetUdpKernelRecvBufferBytes.
	# Pull the publisher TU here too (mirrors src/CMakeLists.txt's
	# mulesocket library layout) — this test target builds LibSocket.cpp
	# directly rather than linking against mulesocket.
	${CMAKE_SOURCE_DIR}/src/UdpReceiveBufferStat.cpp
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

# ---------------------------------------------------------------------------
# NAT-T / uTP test suite
#
# History: each phase (A1 → D6) of the NAT-T port grew its own test
# executable. With 13 NAT-T-related tests the per-binary CMake bloat
# was substantial and the same .cpp files were getting compiled into
# many targets. Consolidated 2026-05-16 into two grouped executables
# plus the two genuinely standalone smoke tests:
#
#   LibUtpLinkTest               — libutp link sanity (trivial, kept
#                                  separate because it's the only
#                                  test that doesn't pull in the
#                                  uTP/NAT-T framework code)
#   NetworkInfoTest              — cross-platform network-introspection
#                                  shim. Self-contained; kept separate.
#   NatUtpUnitTests              — low-level building blocks of the
#                                  uTP layer: env, callbacks,
#                                  encryption, key-frame, registry,
#                                  timer, the CUtpLayer state machine.
#   NatUtpIntegrationTests       — protocol-level flows: connect-flow,
#                                  loopback round-trip, NAT-T headers,
#                                  rendezvous protocol, coordinator
#                                  state machine, 3-node integration.
#
# Each muleunit TEST() macro self-registers via static initialisation,
# so multiple test .cpp files happily coexist in one executable —
# muleunit/main.cpp's `RUN_ALL_TESTS` walks the global registry.
# ---------------------------------------------------------------------------

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


# Phase A2 of the NAT-T port: cross-platform network-introspection shim
# (PMTU + best-interface discovery). Self-tests against the loopback
# interface — no internet required. Kept standalone because it doesn't
# pull in the rest of the uTP framework.
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

# Windows: htons / htonl / inet_ntop live in ws2_32. Without this, the
# loopback test's address-construction fails to link on mingw.
if (WIN32)
	target_link_libraries (NetworkInfoTest ws2_32)
endif()


# ---------------------------------------------------------------------------
# NatUtpUnitTests — low-level building blocks of the uTP layer.
#
# Folds the per-phase unit tests (B1 UtpEnvironment, B2 UtpCallbacks,
# B3 UtpLayer, B4 UtpKeyFrame, B5 UtpEncryption, B7 UtpTimer, B7.5
# UtpLayerRegistry) into a single executable. muleunit's TEST macro
# self-registers each case via static initialisation, so the merged
# binary runs every test that used to live in its own process.
#
# Production-code source files are listed once here, de-duped from the
# old per-test target_sources blocks. UdpReceiveBufferStat.cpp + the
# NetworkInfo.cpp dep are pulled in so the linker resolves
# GetUdpKernelRecvBufferBytes (called by CUtpLayer::ApplySocketBuffersLocked)
# and NetworkInfo::BestInterfaceFor (called by UtpCallbacks's MTU probe).
# ---------------------------------------------------------------------------
add_executable (NatUtpUnitTests
	UtpEnvironmentTest.cpp
	UtpCallbacksTest.cpp
	UtpEncryptionTest.cpp
	UtpKeyFrameTest.cpp
	UtpLayerRegistryTest.cpp
	UtpTimerTest.cpp
	UtpLayerTest.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayer.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEnvironment.cpp
	${CMAKE_SOURCE_DIR}/src/UtpCallbacks.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEncryption.cpp
	${CMAKE_SOURCE_DIR}/src/UtpKeyFrame.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayerRegistry.cpp
	${CMAKE_SOURCE_DIR}/src/UtpTimer.cpp
	${CMAKE_SOURCE_DIR}/src/UdpReceiveBufferStat.cpp
	${CMAKE_SOURCE_DIR}/src/NetworkInfo.cpp
)

add_test (NAME NatUtpUnitTests
	COMMAND NatUtpUnitTests
)

target_include_directories (NatUtpUnitTests
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (NatUtpUnitTests
	muleunit
)

if (ENABLE_NAT_T)
	target_link_libraries (NatUtpUnitTests
		utp
	)
endif()


# ---------------------------------------------------------------------------
# NatUtpIntegrationTests — protocol-level flows + multi-component
# orchestration. Folds:
#   - UtpConnectFlowTest        (B6: Connect → KeyFrame → utp_connect)
#   - UtpLoopbackIntegrationTest (B8: bidirectional handshake + bulk RT)
#   - NatTraversalTest           (A3: connect-options bit decode)
#   - NatTraversalRendezvousTest (C2: OP_RENDEZVOUS / OP_HOLEPUNCH wire)
#   - NatTraversalCoordinatorTest (D1: pending table + timeout mgmt)
#   - NatTraversalIntegrationTest (D6: 3-node rendezvous end-to-end)
# ---------------------------------------------------------------------------
add_executable (NatUtpIntegrationTests
	UtpConnectFlowTest.cpp
	UtpLoopbackIntegrationTest.cpp
	NatTraversalTest.cpp
	NatTraversalRendezvousTest.cpp
	NatTraversalCoordinatorTest.cpp
	NatTraversalIntegrationTest.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayer.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEnvironment.cpp
	${CMAKE_SOURCE_DIR}/src/UtpCallbacks.cpp
	${CMAKE_SOURCE_DIR}/src/UtpEncryption.cpp
	${CMAKE_SOURCE_DIR}/src/UtpKeyFrame.cpp
	${CMAKE_SOURCE_DIR}/src/UtpLayerRegistry.cpp
	${CMAKE_SOURCE_DIR}/src/UtpTimer.cpp
	${CMAKE_SOURCE_DIR}/src/UdpReceiveBufferStat.cpp
	${CMAKE_SOURCE_DIR}/src/NetworkInfo.cpp
	${CMAKE_SOURCE_DIR}/src/NatTraversal.cpp
	${CMAKE_SOURCE_DIR}/src/NatTraversalCoordinator.cpp
)

add_test (NAME NatUtpIntegrationTests
	COMMAND NatUtpIntegrationTests
)

target_include_directories (NatUtpIntegrationTests
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (NatUtpIntegrationTests
	muleunit
)

if (ENABLE_NAT_T)
	target_link_libraries (NatUtpIntegrationTests
		utp
	)
endif()
