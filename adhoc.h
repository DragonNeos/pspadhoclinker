#pragma once

namespace adhoc
{

#define ADHOC_SIGNATURE			0x33484441		// "ADH3"
#define ADHOC_STRLEN			(32+1)			// DOT11_SSID_MAX_LENGTH+1
#define ADHOC_PINGSIZE			512
#define ADHOC_MAXCLIENTS		8
#define ADHOC_MAXDEVICES		16


	enum ADHOC_REQ {
		ADHOC_REQ_CONNECT		= 0,		// ADHOC_GENERIC
		ADHOC_REQ_STATUS		= 1,		// ADHOC_STATUS
		ADHOC_REQ_PING			= 2,		// ADHOC_PING
		ADHOC_REQ_CLIENT		= 3,		// ADHOC_CLIENT
		ADHOC_REQ_DEVICE		= 4,		// ADHOC_DEVICE
		ADHOC_REQ_PACKET		= 5,		// ADHOC_GENERIC
	};


#pragma pack(push, 1)

	typedef struct ADHOC_GENERIC {
		ULONG	Signature;
		ULONG	Length;
		ULONG	TimeStamp;
		ULONG	Request;
	} ADHOC_GENERIC, *PADHOC_GENERIC;

	typedef struct ADHOC_CLIENTINFO {
		ULONG	Ping;
		CHAR	Name[ADHOC_STRLEN];
		CHAR	SSID[ADHOC_STRLEN];
	} ADHOC_CLIENTINFO, *PADHOC_CLIENTINFO;

	typedef struct ADHOC_DEVICEINFO {
		ULONGLONG	MacAddress;
		DWORD		IPAddress;
		ULONGLONG	P2P;
		ULONGLONG	Broadcast;
		CHAR		Name[ADHOC_STRLEN];
		CHAR		Owner[ADHOC_STRLEN];
	} ADHOC_DEVICEINFO, *PADHOC_DEVICEINFO;

	typedef struct ADHOC_STATUS : public ADHOC_GENERIC {
		ULONG	ClientInfoCount;
		ULONG	DeviceInfoCount;
		ADHOC_CLIENTINFO ClientInfo[ADHOC_MAXCLIENTS];
		ADHOC_DEVICEINFO DeviceInfo[ADHOC_MAXDEVICES];
	} ADHOC_STATUS, *PADHOC_STATUS;

	typedef struct ADHOC_PING : public ADHOC_GENERIC {
		union {
			ULONG	QueryTime;
			BYTE	Dummy[ADHOC_PINGSIZE];
		};
	} ADHOC_PING, *PADHOC_PING;

	typedef struct ADHOC_CLIENT : public ADHOC_GENERIC {
		CHAR	Name[ADHOC_STRLEN];
		CHAR	SSID[ADHOC_STRLEN];
	} ADHOC_CLIENT, *PADHOC_CLIENT;

	typedef struct ADHOC_DEVICE : public ADHOC_GENERIC {
		ULONGLONG	MacAddress;
		DWORD		IPAddress;
		CHAR		Name[ADHOC_STRLEN];
	} ADHOC_DEVICE, *PADHOC_DEVICE;

#pragma pack(pop)

}
