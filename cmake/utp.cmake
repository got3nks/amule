# libutp — vendored from github.com/bittorrent/libutp.
# See utp/VENDORED.md for upstream provenance.
#
# Only compiled when ENABLE_NAT_T=YES. Builds as a static library so
# downstream packagers don't need to install a libutp-dev package.
# Consumers link against the `utp` target and #include <utp.h> (note: the
# vendored header is at utp/utp.h; target_include_directories adds it to
# the consumer's search path).

set (LIBUTP_SOURCES
	utp/utp_internal.cpp
	utp/utp_utils.cpp
	utp/utp_hash.cpp
	utp/utp_callbacks.cpp
	utp/utp_api.cpp
	utp/utp_packedsockaddr.cpp
)

# libutp_inet_ntop.cpp is an inet_ntop / inet_pton fallback for old MSVC
# runtimes. POSIX builds get those symbols from libc, so only compile it
# in on Windows.
if (WIN32)
	list (APPEND LIBUTP_SOURCES utp/libutp_inet_ntop.cpp)
endif()

add_library (utp STATIC ${LIBUTP_SOURCES})

# Anything linking utp gets utp/ on its include path so #include <utp.h>
# resolves to our vendored header.
target_include_directories (utp PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/utp
)

# POSIX selects sockaddr_in / sys/socket.h paths inside libutp; Windows
# auto-detects via _WIN32 and doesn't need this.
if (NOT WIN32)
	target_compile_definitions (utp PRIVATE POSIX)
endif()

# libutp emits sign-compare warnings and uses some pre-C++11 idioms that
# need -fpermissive on modern g++/clang. Silence both; we're not editing
# upstream code here.
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
	target_compile_options (utp PRIVATE
		-Wno-sign-compare
		-fpermissive
	)
endif()

# clock_gettime() lives in librt on older glibc (pre-2.17). Detect and
# link if present; on musl, macOS, and recent glibc it's in libc and the
# find_library returns NOTFOUND, which we ignore.
find_library (RT_LIB rt)
if (RT_LIB)
	target_link_libraries (utp PUBLIC ${RT_LIB})
endif()

# Even though static, force PIC so consumers can be linked into shared
# libraries / loadable modules later.
set_target_properties (utp PROPERTIES POSITION_INDEPENDENT_CODE ON)

message (STATUS "libutp: built from vendored sources at utp/ (POSIX=${IS_POSIX})")
