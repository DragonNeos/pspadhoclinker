#include "StdAfx.h"
#include "AdhocClient.h"

#include <mmsystem.h>
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "winmm.lib")


AdhocClient::AdhocClient(const da_socket::socket_config &config /*= da_socket::socket_config()*/)
	: da_socket(config)
{
	m_config.nodelay = true;

	m_hPcap = NULL;
	m_PacketBuffer.resize(m_config.writebuffer_size);

	InitializeCriticalSection(&m_MacLock);

	CHAR name[MAX_PATH];
	DWORD len = MAX_PATH;
	GetUserNameA(name, &len);
	name[ADHOC_STRLEN-1] = NULL;
	m_Name = name;

	m_hWLan = INVALID_HANDLE_VALUE;
	DWORD ver;
	WlanOpenHandle(2, NULL, &ver, &m_hWLan);

	if(m_hWLan != INVALID_HANDLE_VALUE)
	{
		WlanRegisterNotification(m_hWLan, WLAN_NOTIFICATION_SOURCE_ALL,
			FALSE, WlanNotificationProc, this, NULL, NULL);
	}

	m_Event_ScanCmpl = CreateEvent(NULL, TRUE, FALSE, NULL);
}

AdhocClient::~AdhocClient(void)
{
	Close();

	if(m_hWLan != INVALID_HANDLE_VALUE)
	{
		WlanRegisterNotification(m_hWLan, WLAN_NOTIFICATION_SOURCE_NONE,
			FALSE, WlanNotificationProc, this, NULL, NULL);

		WlanCloseHandle(m_hWLan, NULL);
	}

	CloseHandle(m_Event_ScanCmpl);

	DeleteCriticalSection(&m_MacLock);
}

bool AdhocClient::Connect(LPCTSTR address, LPCTSTR service, LPCWSTR adaptor)
{
	if(m_socket || m_hWLan == INVALID_HANDLE_VALUE)
		return false;

	m_LastPacket = 0;
	m_LastPacketLen = 0;

	m_LocalMac.clear();
	m_PeerMac.clear();

	m_Adaptor = adaptor;
	if(!GetAdaptorGUID())
		return false;
	if(!GetAdaptorMAC())
		return false;

	WlanDisconnect(m_hWLan, &m_AdaptorGUID, NULL);


	ZeroMemory(&m_AdhocStatus, sizeof(m_AdhocStatus));

	if(!da_socket::Connect(address, service))
		return false;

	ADHOC_GENERIC gpkt;
	InitPacket(&gpkt, ADHOC_REQ_CONNECT, sizeof(gpkt));
	Send(&gpkt, sizeof(gpkt));

	ADHOC_CLIENT cpkt;
	InitPacket(&cpkt, ADHOC_REQ_CLIENT, sizeof(cpkt));
	strcpy_s(cpkt.Name, ADHOC_STRLEN, m_Name.c_str());
	Send(&cpkt, sizeof(cpkt));


	m_InCleanup = false;

	m_ScanSSID.create(
		da_thread::thread_proc(
			std::tr1::bind(&AdhocClient::ScanSSID, this)));


	m_PacketCapture.create(
		da_thread::thread_proc(
			std::tr1::bind(&AdhocClient::PacketCapture, this)));

	return true;
}

void AdhocClient::InitPacket(PADHOC_GENERIC pkt, ULONG request, ULONG length)
{
	memset(pkt, 0, length);

	pkt->Signature = ADHOC_SIGNATURE;
	pkt->Length = length - sizeof(ADHOC_GENERIC);
	pkt->TimeStamp = timeGetTime();
	pkt->Request = request;
}

void AdhocClient::OnReceived(LPVOID pBuffer, DWORD length)
{
	DWORD offset = 0;
	while((offset+sizeof(ADHOC_GENERIC)) <= length)
	{
		PADHOC_GENERIC pkt = (PADHOC_GENERIC)((LPBYTE)pBuffer + offset);
		offset += sizeof(ADHOC_GENERIC);

		if(pkt->Signature != ADHOC_SIGNATURE)
			break;

		if((offset + pkt->Length) > length)
			break;

		if(!ProcPacket(pkt))
			break;

		offset += pkt->Length;
	}
}

void AdhocClient::OnDisconnect(void)
{
	m_InCleanup = true;
	SetEvent(m_Event_ScanCmpl);

	m_PacketCapture.wait();
	m_PacketCapture.close();

	m_ScanSSID.wait();
	m_ScanSSID.close();


	if(m_Notify)
	{
		if(m_close_by_peer)
			(*m_Notify)(ADHOC_DISCONNECT_PEER);
		else (*m_Notify)(ADHOC_DISCONNECT);
	}
}

bool AdhocClient::ProcPacket(PADHOC_GENERIC packet)
{
	switch(packet->Request)
	{
	case ADHOC_REQ_STATUS:
		{
			PADHOC_STATUS spkt = (PADHOC_STATUS)packet;

			Lock();
			m_AdhocStatus = *spkt;
			Unlock();

			ADHOC_PING ppkt;
			InitPacket(&ppkt, ADHOC_REQ_PING, sizeof(ppkt));
			ppkt.QueryTime = spkt->TimeStamp;
			Send(&ppkt, sizeof(ppkt));

			if(m_Notify)
			{
				(*m_Notify)(ADHOC_UPDATE_STATUS);
			}

			EnterCriticalSection(&m_MacLock);

			m_PeerMac.clear();
			m_PeerIP.clear();

			for(ULONG i = 0; i < spkt->DeviceInfoCount; i++)
			{
				ADHOC_DEVICEINFO &di = spkt->DeviceInfo[i];

				if(m_LocalMac.find(di.MacAddress) != m_LocalMac.end())
					continue;

				m_PeerMac.insert(di.MacAddress);
				m_PeerIP[di.IPAddress] = di.MacAddress;
			}

			mac_map::iterator itr = m_LocalMac.begin();
			ULONG i;
			while(itr != m_LocalMac.end())
			{
				for(i = 0; i < spkt->DeviceInfoCount; i++)
				{
					if(itr->first == spkt->DeviceInfo[i].MacAddress)
						break;
				}

				if(i >= spkt->DeviceInfoCount)
					m_LocalMac.erase(itr++);
				else itr++;
			}

			LeaveCriticalSection(&m_MacLock);
		}
		break;

	case ADHOC_REQ_PACKET:
		{
			PADHOC_GENERIC gpkt = (PADHOC_GENERIC)packet;

			PETHERNET eth = (PETHERNET)(packet+1);

			EnterCriticalSection(&m_MacLock);
			bool issend = m_PeerMac.find((ULONGLONG)eth->Source) != m_PeerMac.end();
			LeaveCriticalSection(&m_MacLock);

			if(m_hPcap && issend)
			{
				if(eth->Type != PROTOCOL_PSP)
					eth->Source = m_AdaptorMAC;

				int ret = pcap_sendpacket(m_hPcap, (LPBYTE)(gpkt+1), gpkt->Length);
				if(ret != 0)
				{
					// cannot send packet to wlan
				}
			}
		}
		break;
	}

	return true;
}

bool AdhocClient::GetAdhocStatus(ADHOC_STATUS &adhoc_status)
{
	if(!m_socket)
		return false;

	Lock();
	adhoc_status = m_AdhocStatus;
	Unlock();

	return true;
}

bool AdhocClient::GetAdaptors(adaptor_list &adaptors)
{
	adaptors.clear();

	if(m_hWLan == INVALID_HANDLE_VALUE)
		return false;

	PWLAN_INTERFACE_INFO_LIST ilist;

	if(WlanEnumInterfaces(m_hWLan, NULL, &ilist) != ERROR_SUCCESS)
		return false;

	for(DWORD i = 0; i < ilist->dwNumberOfItems; i++)
	{
		adaptors.push_back(ilist->InterfaceInfo[i].strInterfaceDescription);
	}

	WlanFreeMemory(ilist);

	return true;
}

bool AdhocClient::GetAdaptorGUID(void)
{
	ZeroMemory(&m_AdaptorGUID, sizeof(m_AdaptorGUID));

	PWLAN_INTERFACE_INFO_LIST ilist;

	if(WlanEnumInterfaces(m_hWLan, NULL, &ilist) != ERROR_SUCCESS)
		return false;

	bool ret = false;

	for(DWORD i = 0; i < ilist->dwNumberOfItems; i++)
	{
		if(!wcscmp(m_Adaptor.c_str(), ilist->InterfaceInfo[i].strInterfaceDescription))
		{
			m_AdaptorGUID = ilist->InterfaceInfo[i].InterfaceGuid;
			ret = true;
			break;
		}
	}

	WlanFreeMemory(ilist);

	return ret;
}

bool AdhocClient::GetAdaptorMAC(void)
{
	ULONG sz = 0;
	if(GetAdaptersInfo(NULL, &sz) != ERROR_BUFFER_OVERFLOW)
		return false;

	if(!sz) return false;

	std::vector<BYTE> buf;
	buf.resize(sz);

	IP_ADAPTER_INFO *pInfo = (IP_ADAPTER_INFO*)&buf[0];

	if(GetAdaptersInfo(pInfo, &sz) != ERROR_SUCCESS)
		return false;

	CHAR devname[MAX_PATH];

	GUID &g = m_AdaptorGUID;
	sprintf_s(devname, MAX_PATH, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);

	while(pInfo)
	{
		do {
			if(strcmp(devname, pInfo->AdapterName))
				break;

			if(pInfo->AddressLength != 6)
				break;

			m_AdaptorMAC = *(PULONGLONG)(pInfo->Address) & 0x0000FFFFFFFFFFFF;
			return true;

		} while(false);

		pInfo = pInfo->Next;
	}

	return false;
}

void AdhocClient::WlanNotification(PWLAN_NOTIFICATION_DATA data)
{
	switch(data->NotificationCode)
	{
	case wlan_notification_acm_scan_complete:
		SetEvent(m_Event_ScanCmpl);
		break;
	}
}

VOID WINAPI AdhocClient::WlanNotificationProc(PWLAN_NOTIFICATION_DATA data, PVOID context)
{
	AdhocClient *pthis = (AdhocClient*)context;
	pthis->WlanNotification(data);
}

DWORD AdhocClient::ScanSSID(void)
{
	if(m_hWLan == INVALID_HANDLE_VALUE)
		return 0;

	while(!m_InCleanup)
	{
		if((timeGetTime() - m_LastPacket) < 4000)
		{
			Sleep(1);
			continue;
		}

		WlanDisconnect(m_hWLan, &m_AdaptorGUID, NULL);

		ResetEvent(m_Event_ScanCmpl);

		if(WlanScan(m_hWLan, &m_AdaptorGUID, NULL, NULL, NULL) == ERROR_SUCCESS)
			WaitForSingleObject(m_Event_ScanCmpl, 4000);
		else
		{
			for(long i = 0; i < 40; i++)
			{
				if(m_InCleanup)
					break;

				Sleep(100);
			}
		}

		if(m_InCleanup)
			break;

		long index = -1;

		PWLAN_AVAILABLE_NETWORK_LIST panl;
		if(WlanGetAvailableNetworkList(m_hWLan, &m_AdaptorGUID,
			WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES, NULL, &panl) == ERROR_SUCCESS)
		{
			const LPCSTR prefix_pspp = "PSP_",
				prefix_psvita = "SCE_PSP2_";

			for(DWORD i = 0; i < panl->dwNumberOfItems; i++)
			{
				if(!strncmp((CHAR*)panl->Network[i].dot11Ssid.ucSSID, prefix_pspp, strlen(prefix_pspp)) ||
					!strncmp((CHAR*)panl->Network[i].dot11Ssid.ucSSID, prefix_psvita, strlen(prefix_psvita)))
				{
					index = i;
					break;
				}
			}
		}

		ADHOC_CLIENT cpkt;
		InitPacket(&cpkt, ADHOC_REQ_CLIENT, sizeof(cpkt));

		strcpy_s(cpkt.Name, ADHOC_STRLEN, m_Name.c_str());

		if(index >= 0 && ConnectSSID(panl->Network[index].dot11Ssid))
		{
			memcpy(cpkt.SSID,
				(CHAR*)panl->Network[index].dot11Ssid.ucSSID,
				panl->Network[index].dot11Ssid.uSSIDLength);

			m_LastPacket = timeGetTime();
		}

		Send(&cpkt, sizeof(cpkt));
	}

	return 0;
}

bool AdhocClient::ConnectSSID(DOT11_SSID ssid)
{
	CHAR _ssid[DOT11_SSID_MAX_LENGTH+1] = {0,};
	WCHAR wssid[DOT11_SSID_MAX_LENGTH+1];
	memcpy(_ssid, ssid.ucSSID, ssid.uSSIDLength);
	wsprintfW(wssid, L"%hs", _ssid);

	std::wstring xml = 
		L"<?xml version=\"1.0\"?>\n"
		L"<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n"
		L"        <name>";

	xml += wssid;

	xml += L"</name>\n"
		L"        <SSIDConfig>\n"
		L"                <SSID>\n"
		L"                        <name>";


	xml += wssid;

	xml += L"</name>\n"
		L"                </SSID>\n"
		L"                <nonBroadcast>false</nonBroadcast>\n"
		L"        </SSIDConfig>\n"
		L"        <connectionType>IBSS</connectionType>\n"
		L"        <connectionMode>manual</connectionMode>\n"
		L"        <MSM>\n"
		L"                <security>\n"
		L"                        <authEncryption>\n"
		L"                                <authentication>open</authentication>\n"
		L"                                <encryption>none</encryption>\n"
		L"                                <useOneX>false</useOneX>\n"
		L"                        </authEncryption>\n"
		L"                </security>\n"
		L"        </MSM>\n"
		L"</WLANProfile>\n";

	DWORD res;
	if(WlanSetProfile(m_hWLan, &m_AdaptorGUID, WLAN_PROFILE_USER, xml.c_str(), NULL, TRUE, NULL, &res) != ERROR_SUCCESS)
	{
		return false;
	}


	WLAN_CONNECTION_PARAMETERS wcp;

	wcp.wlanConnectionMode = wlan_connection_mode_profile;
	wcp.strProfile = wssid;
	wcp.pDot11Ssid = NULL;
	wcp.pDesiredBssidList = NULL;
	wcp.dot11BssType = dot11_BSS_type_independent;
	wcp.dwFlags = NULL;

	return WlanConnect(m_hWLan, &m_AdaptorGUID, &wcp, NULL) == ERROR_SUCCESS;
}

DWORD AdhocClient::PacketCapture(void)
{
	CHAR devname[MAX_PATH];

	GUID &g = m_AdaptorGUID;
	sprintf_s(devname, MAX_PATH, "\\Device\\NPF_{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);

	char errbuf[PCAP_ERRBUF_SIZE];
	m_hPcap = pcap_open_live(devname,		// name of the device
							65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							1,				// promiscuous mode (nonzero means promiscuous)
							1,				// read timeout
							errbuf			// error buffer
							);

	if(!m_hPcap)
	{
		if(m_Notify)
		{
			(*m_Notify)(ADHOC_CAPTURE_FAIL);
		}
		return 0;
	}

	const u_char *pkt_data;
	struct pcap_pkthdr *pkt_header;

	while(!m_InCleanup)
	{
		if(pcap_next_ex(m_hPcap, &pkt_header, &pkt_data) == 1)
		{
			PacketHandler(pkt_header, pkt_data);
		}
	}

	pcap_close(m_hPcap);
	m_hPcap = NULL;

	return 0;
}

void AdhocClient::PacketHandler(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ULONG sendsize = header->len + sizeof(ADHOC_GENERIC);

	if(sendsize > m_PacketBuffer.size())
	{
		// skip large packet
		return;
	}

	PETHERNET eth = (PETHERNET)pkt_data;

	ULONGLONG dest = eth->Destination;
	ULONGLONG src = eth->Source;
	WORD type = eth->Type;

	if(src == m_AdaptorMAC)
	{
		// skip echo/ICMP packet
		return;
	}

	switch(type)
	{
	case PROTOCOL_ARP:
		ReplyARP((PARPHEADER)eth);
		return;

	case PROTOCOL_PSP:
	case PROTOCOL_INTERNET:
		// Process PSP/IP Packet
		break;

	default:
		// Not processing packet
		return;
	}


	EnterCriticalSection(&m_MacLock);
	if(m_PeerMac.find(src) != m_PeerMac.end())
	{
		LeaveCriticalSection(&m_MacLock);
		// Peer packet
		return;
	}

	mac_map::iterator i = m_LocalMac.find(src);
	if(i == m_LocalMac.end())
	{
		switch(type)
		{
		case PROTOCOL_PSP:
			{
				PPSPHEADER ph = (PPSPHEADER)eth;

				if(header->len < sizeof(PSPHEADER) ||
					ph->Signature != 0x02010100 ||
					ph->Code != 0x8000)
					break;

				// New PSP device arrival
				m_LocalMac[src];
				i = m_LocalMac.find(src);

				// PSP Device name packet
				InitPacket(&i->second, ADHOC_REQ_DEVICE, sizeof(i->second));
				i->second.MacAddress = src;
				strcpy_s(i->second.Name, ADHOC_STRLEN, ph->Name);
				Send(&i->second, sizeof(i->second));
			}
			break;

		case PROTOCOL_INTERNET:
			{
				// Internet Protocol
				PIPHEADER ip = (PIPHEADER)eth;
				BYTE hlen = (ip->HeaderInfo&0x0F) << 2;

				do {
					if(header->len < ULONG(sizeof(ETHERNET)+hlen))
						break;

					if(ip->Protocol != PROTOCOL_UDP)
						break;

					if(header->len < ULONG(sizeof(ETHERNET)+hlen+sizeof(UDPHEADER)))
						break;

					PUDPHEADER udp = (PUDPHEADER)(LPBYTE(eth+1)+hlen);
					if(udp->SourcePort != PORT_PSAMS ||
						udp->DestinationPort != PORT_PSAMS)
						break;

					WORD ulen = (udp->Length>>8) | (udp->Length<<8);

					if(header->len < ULONG(sizeof(ETHERNET)+hlen+ulen))
						break;

					const BYTE head[] = {0xFF, 0xA3, 0x82, 0x36, 0x82, 0x35, 0xC2,
						0x2B, 0x24, 0x62, 0x01, 0x02, 0x01, 0x00, 0x01, 0x01};

					if(udp->Length < (sizeof(UDPHEADER) + sizeof(head)))
						break;

					if(memcmp(udp+1, head, sizeof(head)))
						break;

					// New PSVITA device arrival
					m_LocalMac[src];
					i = m_LocalMac.find(src);

					// PSVITA Device name packet
					InitPacket(&i->second, ADHOC_REQ_DEVICE, sizeof(i->second));
					i->second.MacAddress = src;
					i->second.IPAddress = ip->SourceAddr;
					strcpy_s(i->second.Name, ADHOC_STRLEN, (CHAR*)(udp+1)+sizeof(head));
					Send(&i->second, sizeof(i->second));

				} while(false);
			}
			break;
		}

		if(i == m_LocalMac.end())
		{
			LeaveCriticalSection(&m_MacLock);
			// Unknown device
			return;
		}
	}
	else
	{
		switch(type)
		{
		case PROTOCOL_INTERNET:
			{
				// Internet Protocol
				PIPHEADER ip = (PIPHEADER)eth;

				if(ip->SourceAddr != i->second.IPAddress)
				{
					// PSVITA IP Address changed
					i->second.TimeStamp = timeGetTime();
					i->second.IPAddress = ip->SourceAddr;
					Send(&i->second, sizeof(i->second));
				}

				ip_map::iterator imap = m_PeerIP.find(ip->DestinationAddr);
				if(imap == m_PeerIP.end())
					break;

				// Address transform
				dest = imap->second;
			}
			break;
		}
	}

	if(dest != 0x0000FFFFFFFFFFFF)
	{
		if(m_PeerMac.find(dest) == m_PeerMac.end())
		{
			LeaveCriticalSection(&m_MacLock);
			// Target is unknown
			return;
		}
	}

	LeaveCriticalSection(&m_MacLock);


	PADHOC_GENERIC pkt = (PADHOC_GENERIC)(&m_PacketBuffer[0]);

	pkt->Signature = ADHOC_SIGNATURE;
	pkt->Length = header->len;
	pkt->TimeStamp = timeGetTime();
	pkt->Request = ADHOC_REQ_PACKET;

	memcpy(pkt+1, pkt_data, header->len);

	if(eth->Destination != dest)
	{
		eth = (PETHERNET)(pkt+1);
		eth->Destination = dest;
	}

	Send(pkt, sendsize);

	m_LastPacketLen = header->len;

	m_LastPacket = pkt->TimeStamp;
}

void AdhocClient::ReplyARP(const PARPHEADER arp)
{
	if(arp->HardwareType != 0x0100 ||
		arp->ProtocolType != PROTOCOL_INTERNET ||
		arp->HardwareSize != 6 ||
		arp->ProtocolSize != 4 ||
		arp->Opcode != OPCODE_REQUEST)
		return;

	EnterCriticalSection(&m_MacLock);

	bool isreply = m_PeerIP.find(arp->TargetIP) != m_PeerIP.end();

	LeaveCriticalSection(&m_MacLock);

	if(!isreply)
		return;


	// Reply ARP Packet
	ARPHEADER reply = *arp;

	reply.Source = m_AdaptorMAC;
	reply.Destination = arp->SenderMAC;

	reply.Opcode = OPCODE_REPLY;

	reply.SenderMAC = m_AdaptorMAC;
	reply.SenderIP = arp->TargetIP;

	reply.TargetMAC = arp->SenderMAC;
	reply.TargetIP = arp->SenderIP;

	pcap_sendpacket(m_hPcap, (LPBYTE)&reply, sizeof(reply));
}
