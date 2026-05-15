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

#include "UtpEnvironment.h"


#ifdef ENABLE_NAT_T

#include <utp.h>

#include "UtpCallbacks.h"

namespace UtpEnvironment {

namespace {

// File-static singletons. g_context is the live libutp context (or NULL
// when not initialised); g_lifecycleLock guards Init()/Shutdown() against
// concurrent callers (e.g. two daemon-startup paths racing) so the
// idempotency contract holds. g_runtimeLock is the long-lived mutex
// callers acquire around every libutp API call — it has nothing to do
// with init/shutdown.
utp_context* g_context = NULL;
std::mutex   g_lifecycleLock;
std::mutex   g_runtimeLock;

} // anonymous namespace

utp_context* Init()
{
	std::lock_guard<std::mutex> lock(g_lifecycleLock);

	if (g_context != NULL) {
		// Idempotent: already initialised, return the existing context.
		return g_context;
	}

	// libutp's API version is 2 in the vendored revision. utp_init can
	// return NULL on allocation failure; callers (CClientUDPSocket) must
	// be tolerant of that — running without NAT-T is a degraded but
	// valid mode.
	g_context = utp_init(2);
	if (g_context != NULL) {
		// Phase B2: register the five required callbacks immediately so
		// the context is fully wired before any utp_create_socket /
		// utp_process_udp call has a chance to fire. InstallOnContext
		// only returns false on a NULL context — defensively check for
		// completeness, but we just confirmed non-NULL above.
		UtpCallbacks::InstallOnContext(g_context);
	}
	return g_context;
}

void Shutdown()
{
	std::lock_guard<std::mutex> lock(g_lifecycleLock);

	if (g_context == NULL) {
		return;
	}

	utp_destroy(g_context);
	g_context = NULL;
}

utp_context* GetContext()
{
	// No lock: the pointer itself is published atomically by Init()
	// (single store after utp_init completes) and cleared atomically by
	// Shutdown(). Readers race against Shutdown() are the caller's
	// problem to avoid — see the Shutdown() contract in the header.
	return g_context;
}

std::mutex& RuntimeLock()
{
	return g_runtimeLock;
}

void ProcessInboundUtpPacket(const unsigned char* bytes, std::size_t len,
                             const struct sockaddr* src,
                             unsigned int src_len)
{
	if (bytes == NULL || len == 0 || src == NULL || src_len == 0) {
		return;
	}
	std::lock_guard<std::mutex> lock(g_runtimeLock);
	if (g_context == NULL) {
		return;
	}
	const ssize_t result = utp_process_udp(g_context, bytes, len, src, src_len);
}

} // namespace UtpEnvironment

#endif // ENABLE_NAT_T
