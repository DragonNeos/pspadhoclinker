#include "StdAfx.h"
#include "CastSocket.h"

#include <mmsystem.h>

#pragma comment(lib, "winmm.lib")


CastSocket::CastSocket(const da_socket::socket_config &config /*= da_socket::socket_config()*/)
	: da_socket(config)
{
	ZeroMemory(&m_CleintInfo, sizeof(m_CleintInfo));

	strcpy_s(m_CleintInfo.Name, ADHOC_STRLEN, "unknown");

	InitializeCriticalSection(&m_DevLock);
}

CastSocket::~CastSocket(void)
{
	Close();

	DeleteCriticalSection(&m_DevLock);
}

void CastSocket::OnReceived(LPVOID pBuffer, DWORD length)
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

void CastSocket::OnDisconnect(void)
{
}

void CastSocket::InitPacket(PADHOC_GENERIC pkt, ULONG request, ULONG length)
{
	memset(pkt, 0, length);

	pkt->Signature = ADHOC_SIGNATURE;
	pkt->Length = length - sizeof(ADHOC_GENERIC);
	pkt->TimeStamp = timeGetTime();
	pkt->Request = request;
}

bool CastSocket::ProcPacket(PADHOC_GENERIC packet)
{
	switch(packet->Request)
	{
	case ADHOC_REQ_PING:
		{
			PADHOC_PING ppkt = (PADHOC_PING)packet;
			m_CleintInfo.Ping = timeGetTime() - ppkt->QueryTime;
		}
		break;

	case ADHOC_REQ_CLIENT:
		{
			PADHOC_CLIENT cpkt = (PADHOC_CLIENT)packet;

			Lock();
			memcpy(m_CleintInfo.Name, cpkt->Name, ADHOC_STRLEN);
			memcpy(m_CleintInfo.SSID, cpkt->SSID, ADHOC_STRLEN);
			Unlock();
		}
		break;

	case ADHOC_REQ_DEVICE:
		{
			PADHOC_DEVICE dpkt = (PADHOC_DEVICE)packet;

			EnterCriticalSection(&m_DevLock);

			DEVICEINFO &dev = m_DeviceInfo[dpkt->MacAddress];
			if(dev.MacAddress != dpkt->MacAddress)
			{
				dev.MacAddress = dpkt->MacAddress;
				dev.LastPacket = timeGetTime();
				dev.Broadcast = 0;
				dev.P2P = 0;
			}
			dev.IPAddress = dpkt->IPAddress;
			strcpy_s(dev.Name, ADHOC_STRLEN, dpkt->Name);

			LeaveCriticalSection(&m_DevLock);
		}
		break;

	case ADHOC_REQ_PACKET:
		PeerPacket(packet);
		break;
	}

	return true;
}

void CastSocket::GetClientInfo(ADHOC_STATUS &spkt)
{
	if(spkt.ClientInfoCount >= ADHOC_MAXCLIENTS)
		return;

	Lock();

	spkt.ClientInfo[spkt.ClientInfoCount++] = m_CleintInfo;

	EnterCriticalSection(&m_DevLock);

	device_map::iterator i = m_DeviceInfo.begin();
	while(i != m_DeviceInfo.end())
	{
		if((timeGetTime() - i->second.LastPacket) > 8000)
			m_DeviceInfo.erase(i++);
		else i++;
	}

	i = m_DeviceInfo.begin();
	while(i != m_DeviceInfo.end())
	{
		if(spkt.DeviceInfoCount >= ADHOC_MAXDEVICES)
			break;

		strcpy_s(i->second.Owner, ADHOC_STRLEN, m_CleintInfo.Name);

		spkt.DeviceInfo[spkt.DeviceInfoCount++] = i->second;

		i++;
	}

	LeaveCriticalSection(&m_DevLock);

	Unlock();
}

void CastSocket::PeerPacket(PADHOC_GENERIC packet)
{
	LPBYTE pkt_data = (LPBYTE)(packet+1);

	ULONGLONG dest = *(PULONGLONG)(pkt_data) & 0x0000FFFFFFFFFFFF;
	ULONGLONG src = *(PULONGLONG)(pkt_data+6) & 0x0000FFFFFFFFFFFF;

	EnterCriticalSection(&m_DevLock);

	device_map::iterator i = m_DeviceInfo.find(src);
	if(i == m_DeviceInfo.end())
	{
		LeaveCriticalSection(&m_DevLock);
		return;
	}

	i->second.LastPacket = timeGetTime();

	if(dest == 0x0000FFFFFFFFFFFF)
		i->second.Broadcast++;
	else i->second.P2P++;

	LeaveCriticalSection(&m_DevLock);

	if(m_Casting)
	{
		(*m_Casting)(m_socket, dest, packet);
	}
}

void CastSocket::Casting(ULONGLONG dest, PADHOC_GENERIC packet)
{
	EnterCriticalSection(&m_DevLock);

	if(dest == 0x0000FFFFFFFFFFFF ||
		m_DeviceInfo.find(dest) != m_DeviceInfo.end())
	{
		Send(packet, sizeof(ADHOC_GENERIC)+packet->Length);
	}

	LeaveCriticalSection(&m_DevLock);
}
