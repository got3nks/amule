//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2011 aMule Team ( admin@amule.org / http://www.amule.org )
// Copyright (c) 2002-2011 Merkur ( devs@emule-project.net / http://www.emule-project.net )
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

#ifndef CLIENTLIST_H
#define CLIENTLIST_H

#include "DeadSourceList.h"	// Needed for CDeadSourceList
#include "ClientRef.h"

#include <deque>
#include <set>

class CUpDownClient;
class CClientTCPSocket;
class CDeletedClient;
class CMD4Hash;
namespace Kademlia {
	class CContact;
	class CUInt128;
}

enum buddyState
{
	Disconnected,
	Connecting,
	Connected
};


#define BAN_CLEANUP_TIME	1200000 // 20 min


/**
 * This class takes care of managing existing clients.
 *
 * This class tracks a number of attributes related to existing and deleted
 * clients. Among other things, it keeps track of existing, banned, dead and
 * dying clients, as well as offers support for matching new client-instances
 * against already exist clients to avoid duplicates.
 */
class CClientList
{
public:
	/**
	 * Constructor.
	 */
	CClientList();

	/**
	 * Destructor.
	 */
	~CClientList();


	/**
	 * Adds a client to the global list of clients.
	 *
	 * @param toadd The new client.
	 */
	void	AddClient( CUpDownClient* toadd );

	/**
	 * Removes a client from the  client lists.
	 *
	 * @param client The client to be removed.
	 *
	 * To be called from CUpDownClient::Safe_Delete only.
	 */
	void	RemoveClient( CUpDownClient* client );


	/**
	 * Updates the recorded IP of the specified client.
	 *
	 * @param client The client to have its entry updated.
	 * @param newIP The new IP address of the client.
	 *
	 * This function is to be called before the client actually changes its
	 * IP-address, and will update the old entry with the new value. There
	 * will only be added an entry if the new IP isn't zero.
	 */
	void	UpdateClientIP( CUpDownClient* client, uint32 newIP );

	/**
	 * Updates the recorded ID of the specified client.
	 *
	 * @param client The client to have its entry updated.
	 * @param newID The new ID of the client.
	 *
	 * This function is to be called before the client actually changes its
	 * ID, and will update the old entry with the new value. Unlike the other
	 * two functions, this function will always ensure that there is an entry
	 * for the client, regardless of the value of newID.
	 */
	void	UpdateClientID( CUpDownClient* client, uint32 newID );

	/**
	 * Updates the recorded hash of the specified client.
	 *
	 * @param client The client to have its entry updated.
	 * @param newHash The new user-hash.
	 *
	 * This function is to be called before the client actually changes its
	 * user-hash, and will update the old entry with the new value. There will
	 * only be added an entry if the new hash is valid.
	 */
	void	UpdateClientHash( CUpDownClient* client, const CMD4Hash& newHash );


	/**
	 * Returns the number of listed clients.
	 */
	uint32	GetClientCount() const;


	/**
	 * Deletes all tracked clients.
	 */
	void	DeleteAll();


	/**
	 * Replaces a new client-instance with the an already existing client, if one such exist.
	 *
	 * @param client A pointer to the pointer of the new instance.
	 * @param sender The socket associated with the new instance.
	 *
	 * Call this function when a new client-instance has been created. This function will then
	 * compare it against all existing clients and see if we already have an instance matching
	 * the new one. If that is the case, it will delete the new instance and set the pointer to
	 * the existing one.
	 */
	bool	AttachToAlreadyKnown( CUpDownClient** client, CClientTCPSocket* sender );


	/**
	 * Finds a client with the specified ip and port.
	 *
	 * @param clientip The IP of the client to find.
	 * @param port The port used by the client.
	 */
	CUpDownClient* FindClientByIP( uint32 clientip, uint16 port );


	/**
	 * Finds a client with the specified ip.
	 *
	 * @param clientip The IP of the client to find.
	 *
	 * Returns the first client found if there are several with same ip.
	 */
	CUpDownClient* FindClientByIP( uint32 clientip );


	/**
	 * Finds a client with the specified ECID.
	 *
	 * @param clientip The IP of the client to find.
	 *
	 */
	CUpDownClient* FindClientByECID(uint32 ecid) const;


	//! The list-type used to store clients IPs and other information
	typedef std::map<uint32, uint32> ClientMap;


	/**
	 * Adds a client to the list of tracked clients.
	 *
	 * @param toadd The client to track.
	 *
	 * This function is used to keep track of clients after they
	 * have been deleted and makes it possible to spot port or hash
	 * changes.
	 */
	void	AddTrackClient(CUpDownClient* toadd);

	/**
	 * Returns the number of tracked client.
	 *
	 * @param dwIP The IP-address which of the clients.
	 * @return The number of clients tracked at the specified IP.
	 */
	uint16	GetClientsFromIP(uint32 dwIP);

	/**
	 * Checks if a client has changed its user-hash.
	 *
	 * @param dwIP The IP of the client.
	 * @param nPort The port of the client.
	 * @param pNewHash The userhash associated with the client.
	 *
	 */
	bool	ComparePriorUserhash( uint32 dwIP, uint16 nPort, void* pNewHash );


	/**
	 * Bans an IP address for 2 hours.
	 *
	 * @param dwIP The IP from which all clients will be banned.
	 */
	void	AddBannedClient(uint32 dwIP);

	/**
	 * Checks if a client has been banned.
	 *
	 * @param dwIP The IP to check.
	 * @return True if the IP is banned, false otherwise.
	 */
	bool	IsBannedClient(uint32 dwIP);

	/**
	 * Unbans an IP address, if it has been banned.
	 *
	 * @param dwIP The IP address to unban.
	 */
	void	RemoveBannedClient(uint32 dwIP);


	/**
	 * Main loop.
	 *
	 * This function takes care of cleaning the various lists and deleting
	 * pending clients on the deletion-queue.
	 */
	void	Process();


	/**
	 * This function removes all clients filtered by the current IPFilter.
	 *
	 * Call this function after changing the current IPFiler list, to ensure
	 * that no client-connections to illegal IPs exist. These would otherwise
	 * be allowed to exist, bypassing the IPFilter.
	 */
	void	FilterQueues();


	//! The type of the list used to store client-pointers for a couple of tasks.
	typedef std::deque<CClientRef> SourceList;


	/**
	 * Returns a list of clients with the specified user-hash.
	 *
	 * @param hash The userhash to search for.
	 *
	 * This function will return a list of clients with the specified userhash,
	 * provided that the hash is a valid non-empty userhash. Empty hashes will
	 * simply result in nothing being found.
	 */
	SourceList	GetClientsByHash( const CMD4Hash& hash );

	/**
	 * Returns a list of clients with the specified IP.
	 *
	 * @param ip The IP-address to search for.
	 *
	 * This function will return a list of clients with the specified IP,
	 * provided that the IP is a non-zero value. A value of zero will not
	 * result in any results.
	 */
	SourceList	GetClientsByIP( unsigned long ip );


	//! The type of the lists used to store IPs and IDs.
	typedef std::multimap<uint32, CClientRef> IDMap;
	//! The pairs of the IP/ID list.
	typedef std::pair<uint32, CClientRef> IDMapPair;


	/**
	 * Returns a list of all clients.
	 *
	 * @return The complete list of clients.
	 */
	const IDMap& GetClientList();


	/**
	 * Adds a source to the list of dead sources.
	 *
	 * @param client The source to be recorded as dead.
	 */
	void		AddDeadSource(const CUpDownClient* client);

	/**
	 * Checks if a source is recorded as being dead.
	 *
	 * @param client The client to evaluate.
	 * @return True if dead, false otherwise.
	 *
	 * Sources that are dead are not to be considered valid
	 * sources and should not be added to partfiles.
	 */
	bool		IsDeadSource(const CUpDownClient* client);

	/**
	 * Sends a message to a client, identified by a GUI_ID
	 *
	 * @return Success
	 */
	 bool	SendChatMessage(uint64 client_id, const wxString& message);

	/**
	 * Stops a chat session with a client.
	 *
	 */
	 void	SetChatState(uint64 client_id, uint8 state);

	uint8	GetBuddyStatus() const {return m_nBuddyStatus;}
	// This must be used on CreateKadSourceLink and if we ever add the columns
	// on shared files control.
	CUpDownClient* GetBuddy() { return m_pBuddy.GetClient(); }
	uint32 GetBuddyIP();
	uint16 GetBuddyPort();
	bool RequestTCP(Kademlia::CContact* contact, uint8_t connectOptions);
	void RequestBuddy(Kademlia::CContact* contact, uint8_t connectOptions);
	bool IncomingBuddy(Kademlia::CContact* contact, Kademlia::CUInt128* buddyID);

	// === Phase D5c: multi-served-buddy infrastructure ============
	//
	// In aMule's legacy single-buddy model, m_pBuddy is the ONE
	// served-buddy slot — slot 1. D5c adds m_servedBuddies as a
	// parallel list of ADDITIONAL LowID peers we serve, each
	// indexed by their Kad ID so the older eMule UDP-callback flow
	// (OP_REASKCALLBACKUDP → KADEMLIA_CALLBACK_REQ →
	// FindServedBuddyByKadID → forward OP_CALLBACK via the served
	// LowID's TCP socket) can route correctly when a non-NAT-T peer
	// uses us as their relay.
	//
	// Slot-1 behavior is unchanged (preserves zero regression risk
	// for aMule's existing single-buddy UDP-callback behavior).
	// Additional slots are gated on the requester advertising NAT-T
	// support — mirrors eMuleAI's KademliaUDPListener.cpp:1742-1748
	// policy.
	//
	// Lifecycle: clients enter via IncomingServedBuddy (after
	// FINDBUDDY_REQ acceptance in ProcessFindBuddyRequest), get
	// processed through the same Kad state machine as slot-1
	// clients (KS_INCOMING_BUDDY → KS_CONNECTED_BUDDY on TCP
	// connection), but in CClientList::Process we route them to the
	// served-buddy list instead of competing for m_pBuddy. They're
	// removed when the underlying CUpDownClient is removed from
	// the client list (RemoveClient).

	// Cap on simultaneous served buddies beyond the single-buddy
	// slot. eMuleAI uses a configurable max with default 4-8; our
	// constant is conservative — bump to a pref if real-world
	// data justifies it. Phase F test-mesh bumps this to 1024 so
	// the buddy accepts every LowID peer bond attempt during a closed-mesh
	// soak; production builds stay at 8.
#ifdef PHASE_F_BUDDY
	static constexpr uint32 kMaxServedBuddies = 1024;
#else
	static constexpr uint32 kMaxServedBuddies = 8;
#endif

	// Accept an additional served-buddy beyond the single-buddy
	// slot. Returns true if accepted (created and queued for the
	// state machine); false on conflict (duplicate IP/port, kad
	// firewall check in progress, self-connect, capacity full).
	bool IncomingServedBuddy(Kademlia::CContact* contact,
	                         Kademlia::CUInt128* buddyID);

	// Look up a served buddy by their Kad ID. Used by
	// ProcessCallbackRequest to route OP_CALLBACK forwards (older
	// eMule UDP-callback flow). Returns NULL if not served.
	CUpDownClient* FindServedBuddyByKadID(const Kademlia::CUInt128& kadID);

	// Number of currently-tracked served buddies (excludes slot 1).
	uint32 GetServedBuddyCount() const { return static_cast<uint32>(m_servedBuddies.size()); }

	uint32 GetMaxServedBuddies() const { return kMaxServedBuddies; }

	// Returns true if `client` is currently in our served-buddy
	// list. Used by CClientList::Process to avoid linking served
	// buddies into the slot-1 m_pBuddy slot when they reach
	// KS_CONNECTED_BUDDY.
	bool IsServedBuddy(CUpDownClient* client) const;

	// Remove a client from the served-buddy list. Called from
	// RemoveClient on disconnection. Idempotent.
	void RemoveServedBuddy(CUpDownClient* client);
	void RemoveFromKadList(CUpDownClient* torem);
	void AddToKadList(CUpDownClient* toadd);
	bool DoRequestFirewallCheckUDP(const Kademlia::CContact& contact);

	void AddKadFirewallRequest(uint32 ip);
	bool IsKadFirewallCheckIP(uint32 ip) const;

	// Direct Callback list
	void	AddDirectCallbackClient(CUpDownClient *toAdd);
	void	RemoveDirectCallback(CUpDownClient *toRemove) { m_currentDirectCallbacks.remove(CCLIENTREF(toRemove, "")); }
	void	AddTrackCallbackRequests(uint32_t ip);
	bool	AllowCallbackRequest(uint32_t ip) const;

protected:
	/*
	 * Avoids unwanted clients to be forever in the client list
	 */
	void	CleanUpClientList();

	void	ProcessDirectCallbackList();

private:
	/**
	 * Helperfunction which finds a client matching the specified client.
	 *
	 * @param client The client to search for.
	 * @return The matching client or NULL.
	 *
	 * This functions searches through the list of clients and finds the first match
	 * using the same checks as CUpDownClient::Compare, but without the overhead.
	 */
	CUpDownClient* FindMatchingClient( CUpDownClient* client );


	/**
	 * Check if we already know this IP.
	 *
	 * This function is used to determine if the given IP address
	 * is already known.
	 *
	 * @param ip The IP address to check.
	 */
	bool IsIPAlreadyKnown(uint32_t ip);


	/**
	 * Helperfunction which removes the client from the IP-list.
	 */
	void	RemoveIPFromList( CUpDownClient* client );
	/**
	 * Helperfunction which removes the client from the ID-list.
	 */
	bool	RemoveIDFromList( CUpDownClient* client );
	/**
	 * Helperfunction which removes the client from the hash-list.
	 */
	void	RemoveHashFromList( CUpDownClient* client );


	//! The type of the list used to store user-hashes.
	typedef std::multimap<CMD4Hash, CClientRef> HashMap;
	//! The pairs of the Hash-list.
	typedef std::pair<CMD4Hash, CClientRef> HashMapPair;


	//! The map of clients with valid hashes
	HashMap	m_hashList;

	//! The map of clients with valid IPs
	IDMap	m_ipList;

	//! The full lists of clients
	IDMap	m_clientList;

	//! This is the map of banned clients.
	ClientMap m_bannedList;
	//! This variable is used to keep track of the last time the banned-list was pruned.
	uint32	m_dwLastBannCleanUp;

	//! This is the map of tracked clients.
	std::map<uint32, CDeletedClient*> m_trackedClientsList;
	//! This keeps track of the last time the tracked-list was pruned.
	uint32	m_dwLastTrackedCleanUp;

	//! This keeps track of the last time the client-list was pruned.
	uint32 m_dwLastClientCleanUp;

	//! List of unusable sources.
	CDeadSourceList	m_deadSources;

	/* Kad Stuff */
	CClientRefSet	m_KadSources;
	CClientRef		m_pBuddy;
	uint8 m_nBuddyStatus;

	// Phase D5c: served-buddy list — LowIDs we serve as relay
	// beyond the slot-1 m_pBuddy. Keyed by Kad ID (BuddyID from
	// the FINDBUDDY_REQ body) so ProcessCallbackRequest can route
	// OP_CALLBACK forwards to the right TCP socket without
	// scanning the full client list. Capacity capped at
	// kMaxServedBuddies.
	std::map<Kademlia::CUInt128, CClientRef> m_servedBuddies;

	typedef struct {
		uint32 ip;
		uint32 inserted;
	} IpAndTicks;
	typedef std::list<IpAndTicks>	IpAndTicksList;
	IpAndTicksList			m_firewallCheckRequests;

	typedef CClientRefList	DirectCallbackList;
	DirectCallbackList		m_currentDirectCallbacks;
	IpAndTicksList			m_directCallbackRequests;
};

#endif
// File_checked_for_headers
