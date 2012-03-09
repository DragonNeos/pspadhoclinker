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

	enum {
		PROTOCOL_PSP		= 0xC888,
		PROTOCOL_INTERNET	= 0x0008,
		PROTOCOL_ARP		= 0x0608,

		PROTOCOL_UDP		= 0x11,

		PORT_PSAMS			= 0x4A0E,

		OPCODE_REQUEST		= 0x0100,
		OPCODE_REPLY		= 0x0200,
	};

#pragma pack(push, 1)

	typedef struct MACADDRESS {
		BYTE Data[6];

		operator ULONGLONG(void) const {
			ULONGLONG ret = 0;
			memcpy(&ret, &Data, 6);
			return ret;
		}

		MACADDRESS& operator =(ULONGLONG ropr) {
			memcpy(&Data, &ropr, 6);
			return *this;
		}
	} MACADDRESS, *PMACADDRESS;

	typedef struct ETHERNET {
		MACADDRESS Destination;
		MACADDRESS Source;
		WORD Type;
	} ETHERNET, *PETHERNET;

	typedef struct IPHEADER : public ETHERNET {
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

	typedef struct PSPHEADER : public ETHERNET {
		DWORD Signature;
		WORD Code;
		CHAR Name[16];
	} PSPHEADER, *PPSPHEADER;

	typedef struct ARPHEADER : public ETHERNET {
		WORD HardwareType;
		WORD ProtocolType;
		BYTE HardwareSize;
		BYTE ProtocolSize;
		WORD Opcode;
		MACADDRESS SenderMAC;
		DWORD SenderIP;
		MACADDRESS TargetMAC;
		DWORD TargetIP;
	} ARPHEADER, *PARPHEADER;

#pragma pack(pop)

	// MAC Address, IP Address
	typedef std::map<ULONGLONG, ADHOC_DEVICE>	mac_map;
	typedef std::map<ULONG, ULONGLONG>			ip_map;


	std::string m_Name;

	std::tr1::shared_ptr<notify_proc> m_Notify;
	ADHOC_STATUS m_AdhocStatus;

	HANDLE m_hWLan;
	std::wstring m_Adaptor;
	GUID m_AdaptorGUID;
	ULONGLONG m_AdaptorMAC;
	bool m_InCleanup;
	HANDLE m_Event_ScanCmpl;
	da_thread m_ScanSSID;

	pcap_t *m_hPcap;
	da_thread m_PacketCapture;
	std::vector<BYTE> m_PacketBuffer;
	ULONG m_LastPacket;
	ULONG m_LastPacketLen;

	mac_map m_LocalMac;
	std::set<ULONGLONG> m_PeerMac;
	ip_map m_PeerIP;
	CRITICAL_SECTION m_MacLock;


	bool ProcPacket(PADHOC_GENERIC packet);
	inline void InitPacket(PADHOC_GENERIC pkt, ULONG request, ULONG length);
	bool GetAdaptorGUID(void);
	bool GetAdaptorMAC(void);
	bool ConnectSSID(DOT11_SSID ssid);

	DWORD ScanSSID(void);
	void WlanNotification(PWLAN_NOTIFICATION_DATA data);

	DWORD PacketCapture(void);
	void PacketHandler(const struct pcap_pkthdr *header, const u_char *pkt_data);

	void ReplyARP(const PARPHEADER arp);

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
