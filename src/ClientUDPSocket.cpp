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


#include "ClientUDPSocket.h"	// Interface declarations

#include <protocol/Protocols.h>
#include <protocol/ed2k/Client2Client/TCP.h> // Sometimes we reply with TCP packets.
#include <protocol/ed2k/Client2Client/UDP.h>
#include <protocol/kad2/Client2Client/UDP.h>
#include <common/EventIDs.h>
#include <common/Format.h>	// Needed for CFormat

#include "Preferences.h"		// Needed for CPreferences
#include "PartFile.h"			// Needed for CPartFile
#include "updownclient.h"		// Needed for CUpDownClient
#include "UploadQueue.h"		// Needed for CUploadQueue
#include "Packet.h"				// Needed for CPacket
#include "SharedFileList.h"		// Needed for CSharedFileList
#include "DownloadQueue.h"		// Needed for CDownloadQueue
#include "Statistics.h"			// Needed for theStats
#include "amule.h"				// Needed for theApp
#include "ClientList.h"			// Needed for clientlist (buddy support)
#include "ClientTCPSocket.h"	// Needed for CClientTCPSocket
#include "MemFile.h"			// Needed for CMemFile
#include "Logger.h"
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/utils/KadUDPKey.h"
#include <zlib.h>
#include "EncryptedDatagramSocket.h"
#include "NatTraversal.h"
#ifdef ENABLE_NAT_T
#include "UtpEncryption.h"
#include "UtpEnvironment.h"
#include "UtpKeyFrame.h"
#include "UtpLayer.h"
#include "UtpLayerRegistry.h"
#include "UtpTimer.h"
// NOTE: do NOT #include <utp.h> here — libutp's utp_types.h defines
// `typedef long long int64` which collides with aMule's
// `typedef uint64_t int64` in src/Types.h. UtpEnvironment exposes
// ProcessInboundUtpPacket as the lock-aware utp_process_udp wrapper
// callers should use instead.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <vector>
#endif

//
// CClientUDPSocket -- Extended eMule UDP socket
//

CClientUDPSocket::CClientUDPSocket(const amuleIPV4Address& address, const CProxyData* ProxyData)
	: CMuleUDPSocket("Client UDP-Socket", ID_CLIENTUDPSOCKET_EVENT, address, ProxyData)
{
	if (!thePrefs::IsUDPDisabled()) {
		Open();
	}

#ifdef ENABLE_NAT_T
	// Phase B1: bring up the global libutp context. eMuleAI does the
	// same here: there's exactly one utp_context per process, owned by
	// the UDP socket because all NAT-T traffic flows over this single
	// socket. utp_init returning NULL is non-fatal — NAT-T just stays
	// dormant and HighID/LowID transfers continue over TCP as today.
	if (UtpEnvironment::Init() == NULL) {
		AddDebugLogLineN(logClientUDP,
			wxT("NAT-T: utp_init failed; NAT-T disabled for this session"));
	}

	// Phase B6: wire the encryption thunks so any Key Frame / uTP
	// frame WrapKeyFrame / UnwrapKeyFrame call routes through
	// CEncryptedDatagramSocket. Idempotent — calling this twice (in
	// the unlikely event of multiple CClientUDPSocket lifetimes per
	// process) just re-overwrites the delegate pointers.
	UtpEncryption::InstallProductionDelegates();

	// Phase B7: start the periodic libutp tick driver. The worker
	// thread fires every 50 ms, locks UtpEnvironment::RuntimeLock,
	// and runs utp_check_timeouts + utp_issue_deferred_acks against
	// the global context. Idempotent (Start() while already running
	// is a no-op). If utp_init failed above, the tick safely no-ops
	// each iteration (GetContext() returns NULL).
	UtpTimer::Start();
#endif
}


CClientUDPSocket::~CClientUDPSocket()
{
#ifdef ENABLE_NAT_T
	// Phase B7: stop the tick driver before tearing down the libutp
	// context. Stop() joins the worker thread, so by the time it
	// returns no callback is in flight that could touch a destroyed
	// context. Then it's safe to destroy.
	UtpTimer::Stop();

	// Tear down the global libutp context. Safe to call even if Init()
	// failed — Shutdown() is a no-op when there is no live context.
	UtpEnvironment::Shutdown();
#endif
}


void CClientUDPSocket::OnReceive(int errorCode)
{
	CMuleUDPSocket::OnReceive(errorCode);

	// TODO: A better solution is needed.
	if (thePrefs::IsUDPDisabled()) {
		Close();
	}
}


void CClientUDPSocket::OnPacketReceived(uint32 ip, uint16 port, uint8_t* buffer, size_t length)
{
	wxCHECK_RET(length >= 2, "Invalid packet.");

	uint8_t *decryptedBuffer;
	uint32_t receiverVerifyKey;
	uint32_t senderVerifyKey;
	int packetLen = CEncryptedDatagramSocket::DecryptReceivedClient(buffer, length, &decryptedBuffer, ip, &receiverVerifyKey, &senderVerifyKey);

	uint8_t protocol = decryptedBuffer[0];
	uint8_t opcode	 = decryptedBuffer[1];

	if (packetLen >= 1) {
		try {
			switch (protocol) {
				case OP_EMULEPROT:
					ProcessPacket(decryptedBuffer + 2, packetLen - 2, opcode, ip, port);
					break;

				case OP_KADEMLIAHEADER:
					theStats::AddDownOverheadKad(length);
					if (packetLen >= 2) {
						Kademlia::CKademlia::ProcessPacket(decryptedBuffer, packetLen, wxUINT32_SWAP_ALWAYS(ip), port, (Kademlia::CPrefs::GetUDPVerifyKey(ip) == receiverVerifyKey), Kademlia::CKadUDPKey(senderVerifyKey, theApp->GetPublicIP(false)));
					} else {
						throw wxString("Kad packet too short");
					}
					break;

#ifdef ENABLE_NAT_T
				case OP_UDPRESERVEDPROT2:
					// NAT-T / uTP envelope: OP_UDPRESERVEDPROT2 (0xB2)
					// carries either a Key Frame (sub-byte 0xFF) or a
					// uTP frame (sub-byte 0x00). Vanilla aMule peers
					// without ENABLE_NAT_T fall through to the
					// default "Unknown opcode" branch and drop the
					// packet — correct interop behavior.
					//
					// Phase B7.5 wiring:
					//   sub-byte 0xFF: UnwrapKeyFrame → look up the
					//     CUtpLayer registered for the recovered
					//     sender_hash → call layer->OnPeerKeyFrame.
					//     If no layer is waiting (unsolicited Key
					//     Frame), log + drop.
					//   sub-byte 0x00: UnwrapUtpFrame → feed the
					//     plaintext uTP packet to utp_process_udp
					//     under RuntimeLock. libutp's internal
					//     routing finds the matching utp_socket by
					//     source address; the on_read / state-change
					//     callbacks then dispatch to the layer via
					//     utp_get_userdata.
					if (packetLen >= 2) {
						uint8_t natSubByte = decryptedBuffer[1];
						if (natSubByte == UtpKeyFrame::kSubByte) {
							uint8_t sender_hash[UtpKeyFrame::kUserHashSize];
							if (UtpEncryption::UnwrapKeyFrame(
									decryptedBuffer,
									static_cast<std::size_t>(packetLen),
									ip,
									sender_hash)) {
								CUtpLayer* layer = UtpLayerRegistry::FindByPeerHash(sender_hash);
								if (layer != NULL) {
									layer->OnPeerKeyFrame(sender_hash);
								} else {
									AddDebugLogLineN(logClientUDP, CFormat(
										"NAT-T: Key Frame from %s — no layer registered "
										"for that peer hash (unsolicited; dropping)")
										% Uint32_16toStringIP_Port(ip, port));
								}
							} else {
								AddDebugLogLineN(logClientUDP, CFormat(
									"NAT-T: malformed Key Frame from %s "
									"(rejected by UnwrapKeyFrame)")
									% Uint32_16toStringIP_Port(ip, port));
							}
						} else if (natSubByte == UtpKeyFrame::kUtpFrameSubByte) {
							std::vector<uint8_t> plaintext;
							if (UtpEncryption::UnwrapUtpFrame(
									decryptedBuffer,
									static_cast<std::size_t>(packetLen),
									ip,
									plaintext)) {
								// Build a sockaddr_in for libutp's
								// per-connection routing (it matches
								// inbound packets against the utp_socket's
								// stored peer address).
								struct sockaddr_in src;
								std::memset(&src, 0, sizeof(src));
								src.sin_family      = AF_INET;
								src.sin_port        = htons(port);
								src.sin_addr.s_addr = htonl(ip);

								UtpEnvironment::ProcessInboundUtpPacket(
									plaintext.data(), plaintext.size(),
									reinterpret_cast<struct sockaddr*>(&src),
									sizeof(src));
							} else {
								AddDebugLogLineN(logClientUDP, CFormat(
									"NAT-T: malformed uTP frame from %s "
									"(rejected by UnwrapUtpFrame)")
									% Uint32_16toStringIP_Port(ip, port));
							}
						} else {
							AddDebugLogLineN(logClientUDP, CFormat(
								"NAT-T: OP_UDPRESERVEDPROT2 from %s with unknown "
								"sub-byte 0x%02x (len=%d) — dropping")
								% Uint32_16toStringIP_Port(ip, port)
								% (unsigned)natSubByte % packetLen);
						}
					}
					break;
#endif // ENABLE_NAT_T

				case OP_KADEMLIAPACKEDPROT:
					theStats::AddDownOverheadKad(length);
					if (packetLen >= 2) {
						uint32_t newSize = packetLen * 10 + 300; // Should be enough...
						std::vector<uint8_t> unpack(newSize);
						uLongf unpackedsize = newSize - 2;
						uint16_t result = uncompress(&(unpack[2]), &unpackedsize, decryptedBuffer + 2, packetLen - 2);
						if (result == Z_OK) {
							AddDebugLogLineN(logClientKadUDP, "Correctly uncompressed Kademlia packet");
							unpack[0] = OP_KADEMLIAHEADER;
							unpack[1] = opcode;
							Kademlia::CKademlia::ProcessPacket(&(unpack[0]), unpackedsize + 2, wxUINT32_SWAP_ALWAYS(ip), port, (Kademlia::CPrefs::GetUDPVerifyKey(ip) == receiverVerifyKey), Kademlia::CKadUDPKey(senderVerifyKey, theApp->GetPublicIP(false)));
						} else {
							AddDebugLogLineN(logClientKadUDP, "Failed to uncompress Kademlia packet");
						}
					} else {
						throw wxString("Kad packet (compressed) too short");
					}
					break;

				default:
					AddDebugLogLineN(logClientUDP, CFormat("Unknown opcode on received packet: 0x%x") % protocol);
			}
		} catch (const wxString& DEBUG_ONLY(e)) {
			AddDebugLogLineN(logClientUDP, "Error while parsing UDP packet: " + e);
		} catch (const CInvalidPacket& DEBUG_ONLY(e)) {
			AddDebugLogLineN(logClientUDP, "Invalid UDP packet encountered: " + e.what());
		} catch (const CEOFException& DEBUG_ONLY(e)) {
			AddDebugLogLineN(logClientUDP, "Malformed packet encountered while parsing UDP packet: " + e.what());
		}
	}
}


void CClientUDPSocket::ProcessPacket(uint8_t* packet, int16 size, int8 opcode, uint32 host, uint16 port)
{
	switch (opcode) {
		case OP_REASKCALLBACKUDP: {
			AddDebugLogLineN( logClientUDP, "Client UDP socket; OP_REASKCALLBACKUDP" );
			theStats::AddDownOverheadOther(size);
			CUpDownClient* buddy = theApp->clientlist->GetBuddy();
			if( buddy ) {
				if( size < 17 || buddy->GetSocket() == NULL ) {
					break;
				}
				if (!md4cmp(packet, buddy->GetBuddyID())) {
					/*
						The packet has an initial 16 bytes key for the buddy.
						This is currently unused, so to make the transformation
						we discard the first 10 bytes below and then overwrite
						the other 6 with ip/port.
					*/
					CMemFile mem_packet(packet+10,size-10);
					// Change the ip and port while leaving the rest untouched
					mem_packet.Seek(0,wxFromStart);
					mem_packet.WriteUInt32(host);
					mem_packet.WriteUInt16(port);
					CPacket* response = new CPacket(mem_packet, OP_EMULEPROT, OP_REASKCALLBACKTCP);
					AddDebugLogLineN( logClientUDP, "Client UDP socket: send OP_REASKCALLBACKTCP" );
					theStats::AddUpOverheadFileRequest(response->GetPacketSize());
					buddy->GetSocket()->SendPacket(response);
				}
			}
			break;
		}
		case OP_REASKFILEPING: {
			AddDebugLogLineN( logClientUDP, "Client UDP socket: OP_REASKFILEPING" );
			theStats::AddDownOverheadFileRequest(size);

			CMemFile data_in(packet, size);
			CMD4Hash reqfilehash = data_in.ReadHash();
			CKnownFile* reqfile = theApp->sharedfiles->GetFileByID(reqfilehash);
			bool bSenderMultipleIpUnknown = false;
			CUpDownClient* sender = theApp->uploadqueue->GetWaitingClientByIP_UDP(host, port, true, &bSenderMultipleIpUnknown);

			if (!reqfile) {
				CPacket* response = new CPacket(OP_FILENOTFOUND,0,OP_EMULEPROT);
				theStats::AddUpOverheadFileRequest(response->GetPacketSize());
				if (sender) {
					SendPacket(response, host, port, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash().GetHash(), false, 0);
				} else {
					SendPacket(response, host, port, false, NULL, false, 0);
				}

				break;
			}

			if (sender){
				sender->CheckForAggressive();

				//Make sure we are still thinking about the same file
				if (reqfilehash == sender->GetUploadFileID()) {
					sender->AddAskedCount();
					sender->SetUDPPort(port);
					sender->SetLastUpRequest();

					if (sender->GetUDPVersion() > 3) {
						sender->ProcessExtendedInfo(&data_in, reqfile);
					} else  if (sender->GetUDPVersion() > 2) {
						uint16 nCompleteCountLast = sender->GetUpCompleteSourcesCount();
						uint16 nCompleteCountNew = data_in.ReadUInt16();
						sender->SetUpCompleteSourcesCount(nCompleteCountNew);
						if (nCompleteCountLast != nCompleteCountNew) {
							reqfile->UpdatePartsInfo();
						}
					}

					CMemFile data_out(128);
					if(sender->GetUDPVersion() > 3) {
						if (reqfile->IsPartFile()) {
							static_cast<CPartFile*>(reqfile)->WritePartStatus(&data_out);
						} else {
							data_out.WriteUInt16(0);
						}
					}

					data_out.WriteUInt16(sender->GetUploadQueueWaitingPosition());
					CPacket* response = new CPacket(data_out, OP_EMULEPROT, OP_REASKACK);
					theStats::AddUpOverheadFileRequest(response->GetPacketSize());
					AddDebugLogLineN( logClientUDP, "Client UDP socket: OP_REASKACK to " + sender->GetFullIP());
					SendPacket(response, host, port, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash().GetHash(), false, 0);
				} else {
					AddDebugLogLineN( logClientUDP, "Client UDP socket; ReaskFilePing; reqfile does not match" );
				}
			} else {
				if (!bSenderMultipleIpUnknown) {
					if ((theStats::GetWaitingUserCount() + 50) > thePrefs::GetQueueSize()) {
						CPacket* response = new CPacket(OP_QUEUEFULL,0,OP_EMULEPROT);
						theStats::AddUpOverheadFileRequest(response->GetPacketSize());
						SendPacket(response,host,port, false, NULL, false, 0); // we cannot answer this one encrypted since we dont know this client
					}
				} else {
					AddDebugLogLineN(logClientUDP, CFormat("UDP Packet received - multiple clients with the same IP but different UDP port found. Possible UDP Portmapping problem, enforcing TCP connection. IP: %s, Port: %u") % Uint32toStringIP(host) % port);
				}
			}
			break;
		}
		case OP_QUEUEFULL: {
			AddDebugLogLineN( logClientUDP, "Client UDP socket: OP_QUEUEFULL" );
			theStats::AddDownOverheadOther(size);
			CUpDownClient* sender = theApp->downloadqueue->GetDownloadClientByIP_UDP(host,port);
			if (sender) {
				sender->SetRemoteQueueFull(true);
				sender->UDPReaskACK(0);
			}
			break;
		}
		case OP_REASKACK: {
			theStats::AddDownOverheadFileRequest(size);
			CUpDownClient* sender = theApp->downloadqueue->GetDownloadClientByIP_UDP(host,port);
			if (sender) {
				CMemFile data_in(packet,size);
				if ( sender->GetUDPVersion() > 3 ) {
					sender->ProcessFileStatus(true, &data_in, sender->GetRequestFile());
				}
				uint16 nRank = data_in.ReadUInt16();
				sender->SetRemoteQueueFull(false);
				sender->UDPReaskACK(nRank);
			}
			break;
		}
		case OP_FILENOTFOUND: {
			AddDebugLogLineN( logClientUDP, "Client UDP socket: OP_FILENOTFOUND" );
			theStats::AddDownOverheadFileRequest(size);
			CUpDownClient* sender = theApp->downloadqueue->GetDownloadClientByIP_UDP(host,port);
			if (sender){
				sender->UDPReaskFNF(); // may delete 'sender'!
				sender = NULL;
			}
			break;
		}
		case OP_DIRECTCALLBACKREQ:
		{
			AddDebugLogLineN( logClientUDP, "Client UDP socket: OP_DIRECTCALLBACKREQ" );
			theStats::AddDownOverheadOther(size);
			if (!theApp->clientlist->AllowCallbackRequest(host)) {
				AddDebugLogLineN(logClientUDP, "Ignored DirectCallback Request because this IP (" + Uint32toStringIP(host) + ") has sent too many requests within a short time");
				break;
			}
			// do we accept callbackrequests at all?
			if (Kademlia::CKademlia::IsRunning() && Kademlia::CKademlia::IsFirewalled()) {
				theApp->clientlist->AddTrackCallbackRequests(host);
				CMemFile data(packet, size);
				uint16_t remoteTCPPort = data.ReadUInt16();
				CMD4Hash userHash(data.ReadHash());
				uint8_t connectOptions = data.ReadUInt8();
				CUpDownClient* requester = NULL;
				CClientList::SourceList clients = theApp->clientlist->GetClientsByHash(userHash);
				for (CClientList::SourceList::iterator it = clients.begin(); it != clients.end(); ++it) {
					if ((host == 0 || it->GetIP() == host) && (remoteTCPPort == 0 || it->GetUserPort() == remoteTCPPort)) {
						requester = it->GetClient();
						break;
					}
				}
				if (requester == NULL) {
					requester = new CUpDownClient(remoteTCPPort, host, 0, 0, NULL, true, true);
					requester->SetUserHash(CMD4Hash(userHash));
					theApp->clientlist->AddClient(requester);
				}
				// DirectCallbackReq context: bit 7 of connectOptions is the
				// NAT-T capability bit. Pass natTraversal=true so the byte
				// gets parsed as the eMule wire protocol intends here.
				requester->SetConnectOptions(connectOptions, true, false, true);
				requester->SetDirectUDPCallbackSupport(false);
				requester->SetIP(host);
				requester->SetUserPort(remoteTCPPort);
				AddDebugLogLineN(logClientUDP, "Accepting incoming DirectCallback Request from " + Uint32toStringIP(host));
				requester->TryToConnect();
			} else {
				AddDebugLogLineN(logClientUDP, "Ignored DirectCallback Request because we do not accept Direct Callbacks at all (" + Uint32toStringIP(host) + ")");
			}
			break;
		}
#ifdef ENABLE_NAT_T
		case NatTraversal::OP_RENDEZVOUS_OPCODE: {
			// Phase C1 dispatch — parse the body and log. The full
			// rendezvous state-machine handler lives in the NAT-T
			// coordinator that arrives in Phase D (cluster 8). Until
			// then we just verify the wire format end-to-end and
			// drop. Vanilla aMule builds without ENABLE_NAT_T fall
			// through to the default branch and AddDownOverheadOther
			// — same interop behavior as any unknown opcode.
			theStats::AddDownOverheadOther(size);
			NatTraversal::RendezvousRequest req;
			if (NatTraversal::DecodeRendezvous(packet,
			                                  static_cast<std::size_t>(size),
			                                  req)) {
				AddDebugLogLineN(logClientUDP, CFormat(
					"NAT-T: received OP_RENDEZVOUS from %s "
					"(connect_options=0x%02x, has_file_hash=%d, "
					"has_ext_endpoint=%d) — Phase D handler not wired yet")
					% Uint32_16toStringIP_Port(host, port)
					% (unsigned)req.connect_options
					% (int)req.has_file_hash
					% (int)req.has_ext_endpoint);
			} else {
				AddDebugLogLineN(logClientUDP, CFormat(
					"NAT-T: malformed OP_RENDEZVOUS from %s "
					"(size=%d, rejected by DecodeRendezvous)")
					% Uint32_16toStringIP_Port(host, port) % size);
			}
			break;
		}
		case NatTraversal::OP_HOLEPUNCH_OPCODE: {
			// HOLEPUNCH carries no body — the source address is the
			// signal. Phase D will use it to drive the symmetric-NAT
			// hole-punch retry; here we just log + count.
			theStats::AddDownOverheadOther(size);
			AddDebugLogLineN(logClientUDP, CFormat(
				"NAT-T: received OP_HOLEPUNCH from %s (size=%d) — "
				"Phase D handler not wired yet")
				% Uint32_16toStringIP_Port(host, port) % size);
			break;
		}
#endif // ENABLE_NAT_T
		default:
			theStats::AddDownOverheadOther(size);
	}
}
// File_checked_for_headers
