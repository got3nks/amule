add_executable (CTagTest
	CTagTest.cpp
	${CMAKE_SOURCE_DIR}/src/SafeFile.cpp
	${CMAKE_SOURCE_DIR}/src/MemFile.cpp
	${CMAKE_SOURCE_DIR}/src/Tag.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
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
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
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
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
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
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
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
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
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
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
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
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
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
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
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
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
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
