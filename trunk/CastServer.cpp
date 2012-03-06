#include "StdAfx.h"
#include "CastServer.h"

#include "mmsystem.h"

#pragma comment(lib, "winmm.lib")


CastServer::CastServer(void)
{
	m_config.nodelay = true;
	m_config.firstdata = sizeof(ADHOC_GENERIC);
}

CastServer::~CastServer(void)
{
	Close();
}

bool CastServer::OnAccept(client_ptr client, SOCKADDR address,
						  BYTE *firstdata, ULONG firstdata_size, bool &waitnext)
{
	if(firstdata_size != sizeof(ADHOC_GENERIC))
		return false;

	PADHOC_GENERIC pkt = (PADHOC_GENERIC)firstdata;

	if(pkt->Signature != ADHOC_SIGNATURE ||
		pkt->Length != 0 ||
		pkt->Request != ADHOC_REQ_CONNECT)
	{
		return false;
	}

	client->SetCastProc(
		CastSocket::cast_proc(
			std::tr1::bind(&CastServer::Casting,
				this,
				std::tr1::placeholders::_1,
				std::tr1::placeholders::_2,
				std::tr1::placeholders::_3)));

	return true;
}

void CastServer::OnDisconnect(SOCKET invalid_socket)
{
}

void CastServer::InitPacket(PADHOC_GENERIC pkt, ULONG request, ULONG length)
{
	memset(pkt, 0, length);

	pkt->Signature = ADHOC_SIGNATURE;
	pkt->Length = length - sizeof(ADHOC_GENERIC);
	pkt->TimeStamp = timeGetTime();
	pkt->Request = request;
}

void CastServer::UpdateStatus(void)
{
	if(!m_socket)
		return;

	ADHOC_STATUS spkt;
	InitPacket(&spkt, ADHOC_REQ_STATUS, sizeof(spkt));

	Lock();

	client_map::iterator i = m_clients.begin();
	while(i != m_clients.end())
	{
		i->second->GetClientInfo(spkt);

		i++;
	}

	i = m_clients.begin();
	while(i != m_clients.end())
	{
		i->second->Send(&spkt, sizeof(spkt));

		i++;
	}

	Unlock();
}

void CastServer::Casting(SOCKET src, ULONGLONG dest, PADHOC_GENERIC packet)
{
	Lock();

	client_map::iterator i = m_clients.begin();
	while(i != m_clients.end())
	{
		if(i->first != src)
			i->second->Casting(dest, packet);

		i++;
	}

	Unlock();
}
