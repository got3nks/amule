add_library (muleunit OBJECT
	test.cpp
	main.cpp
	testcase.cpp
	testregistry.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/MuleDebug.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/StringFunctions.cpp
	# Format.cpp is required because MuleDebug.cpp uses CFormat (e.g.
	# `CFormat("[%u] ") % frame.GetLevel()` at MuleDebug.cpp:133).
	# Stricter linkers (e.g. the GH Actions Ubuntu runner's ld) reject
	# the undefined refs to CFormat::Init / GetString / operator% without
	# this — observed in CI as "undefined reference to `CFormat::Init...`"
	# during NatTraversalTest linking. Apple ld and Ubuntu 24.04's GNU ld
	# happen to accept the build with weak template symbols, masking the
	# missing dep locally; this entry makes the link sound everywhere.
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	# strerror_r.c provides mule_strerror_r() used by Format.cpp's
	# CFormat's %s with errno-derived strings (Format.cpp:301).
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

target_compile_definitions (muleunit
	PUBLIC MULEUNIT
	PUBLIC wxUSE_GUI=0
)

target_include_directories (muleunit
	PUBLIC ${amule_BINARY_DIR}
	PUBLIC ${CMAKE_SOURCE_DIR}/src/libs
	INTERFACE ${CMAKE_SOURCE_DIR}/unittests
)

target_link_libraries (muleunit
	wxWidgets::BASE
)

if (HAVE_BFD)
	target_link_libraries (muleunit
		${BFD_LIBRARY}
	)
endif()
