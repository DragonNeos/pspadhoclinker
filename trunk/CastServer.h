#pragma once

#include "CastSocket.h"
#include "da_libs/da_socket.h"

#include "adhoc.h"

#include <functional>

using namespace da_libs;
using namespace adhoc;


class CastServer :
	public da_host<CastSocket>
{
protected:
	void InitPacket(PADHOC_GENERIC pkt, ULONG request, ULONG length);

	void Casting(SOCKET src, ULONGLONG dest, PADHOC_GENERIC packet);

	virtual bool OnAccept(client_ptr client, SOCKADDR address,
		BYTE *firstdata, ULONG firstdata_size, bool &waitnext);
	virtual void OnDisconnect(SOCKET invalid_socket);

public:
	void UpdateStatus(void);

	CastServer(void);
	virtual ~CastServer(void);
};
