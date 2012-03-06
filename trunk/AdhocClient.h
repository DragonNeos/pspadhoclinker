#pragma once

#include "da_libs/da_socket.h"

#include <string>
#include <list>
#include <map>
#include <set>
#include <functional>

#include <Wlanapi.h>

#include <pcap.h>
#include <packet32.h>

#include "adhoc.h"

using namespace da_libs;
using namespace adhoc;


class AdhocClient :
	public da_socket
{
public:
	typedef enum ADHOC_EVENT {
		ADHOC_DISCONNECT,
		ADHOC_DISCONNECT_PEER,
		ADHOC_UPDATE_STATUS,
		ADHOC_CAPTURE_FAIL,
	} ADHOC_EVENT;

	typedef std::tr1::function<void(ADHOC_EVENT)>		notify_proc;

	typedef std::list<std::wstring>						adaptor_list;

protected:

#pragma pack(push, 1)

	typedef struct IPHEADER {
		BYTE HeaderInfo;
		BYTE Type;
		WORD Length;
		WORD Identifier;
		WORD Flags;
		BYTE TimeToAlive;
		BYTE Protocol;
		WORD Checksum;
		DWORD SourceAddr;
		DWORD DestinationAddr;
	} IPHEADER, *PIPHEADER;

	typedef struct UDPHEADER {
		WORD SourcePort;
		WORD DestinationPort;
		WORD Length;
		WORD Checksum;
	} UDPHEADER, *PUDPHEADER;

#pragma pack(pop)

	typedef std::map<ULONGLONG, std::string>			mac_map;


	std::string m_Name;

	std::tr1::shared_ptr<notify_proc> m_Notify;
	ADHOC_STATUS m_AdhocStatus;

	HANDLE m_hWLan;
	std::wstring m_Adaptor;
	GUID m_AdaptorGUID;
	bool m_InCleanup;
	HANDLE m_Event_ScanExec;
	HANDLE m_Event_ScanCmpl;
	da_thread m_ScanSSID;

	pcap_t *m_hPcap;
	da_thread m_PacketCapture;
	std::vector<BYTE> m_PacketBuffer;
	ULONG m_LastPaket;

	mac_map m_LocalMac;
	std::set<ULONGLONG> m_PeerMac;
	CRITICAL_SECTION m_MacLock;


	bool ProcPacket(PADHOC_GENERIC packet);
	inline void InitPacket(PADHOC_GENERIC pkt, ULONG request, ULONG length);
	void GetAdaptorGUID(void);
	bool ConnectSSID(DOT11_SSID ssid);

	DWORD ScanSSID(void);
	void WlanNotification(PWLAN_NOTIFICATION_DATA data);

	DWORD PacketCapture(void);
	void PacketHandler(const struct pcap_pkthdr *header, const u_char *pkt_data);
	static void PacketHandlerProc(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

	virtual void OnReceived(LPVOID pBuffer, DWORD length);
	virtual void OnDisconnect(void);

	static VOID WINAPI WlanNotificationProc(PWLAN_NOTIFICATION_DATA data, PVOID context);

public:
	template <class TProcedure>
	void SetNotify(TProcedure proc)
	{
		m_Notify.reset(new notify_proc(proc));
	}

	void ResetNotify(void)
	{
		m_Notify.reset();
	}

	bool Connect(LPCTSTR address, LPCTSTR service, LPCWSTR adaptor);

	bool GetAdhocStatus(ADHOC_STATUS &adhoc_status);

	bool GetAdaptors(adaptor_list &adaptors);

	AdhocClient(const da_socket::socket_config &config = da_socket::socket_config());
	virtual ~AdhocClient(void);
};
