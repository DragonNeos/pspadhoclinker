#pragma once

#include "da_libs/da_socket.h"
#include "adhoc.h"

#include <map>
#include <memory>
#include <functional>

using namespace da_libs;
using namespace adhoc;


class CastSocket :
	public da_socket
{
public:
	typedef std::tr1::function<void(SOCKET, ULONGLONG, PADHOC_GENERIC)>		cast_proc;

protected:
	typedef struct DEVICEINFO : public ADHOC_DEVICEINFO {
		ULONG LastPacket;
	} DEVICEINFO, *PDEVICEINFO;

	typedef std::map<ULONGLONG, DEVICEINFO>		device_map;

	ADHOC_CLIENTINFO m_CleintInfo;
	device_map m_DeviceInfo;

	std::tr1::shared_ptr<cast_proc> m_Casting;

	CRITICAL_SECTION m_DevLock;

	void InitPacket(PADHOC_GENERIC pkt, ULONG request, ULONG length);
	bool ProcPacket(PADHOC_GENERIC packet);
	void PeerPacket(PADHOC_GENERIC packet);

	virtual void OnReceived(LPVOID pBuffer, DWORD length);
	virtual void OnDisconnect(void);

public:
	template <class TProcedure>
	void SetCastProc(TProcedure proc)
	{
		m_Casting.reset(new cast_proc(proc));
	}

	void ResetCastProc(void)
	{
		m_Casting.reset();
	}

	void GetClientInfo(ADHOC_STATUS &spkt);

	void Casting(ULONGLONG dest, PADHOC_GENERIC packet);

	CastSocket(const da_socket::socket_config &config = da_socket::socket_config());
	virtual ~CastSocket(void);
};
