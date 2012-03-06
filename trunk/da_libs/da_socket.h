#pragma once

#include <tchar.h>
#include <winsock2.h>
#include <Mswsock.h>
#include <ws2tcpip.h>

#include "da_libs.h"
#include "da_thread.h"
#include "da_iocp.h"

#include <string>
#include <list>
#include <map>
#include <vector>
#include <memory>
#include <functional>


#pragma comment(lib, "Ws2_32.lib")


DALIBS_IMPLEMENT_BEGIN


class da_socket {
public:
	class socket_config {
	public:
		int family;
		int type;
		int protocol;
		DWORD connect_timeout;
		bool nodelay;

		int readbuffer_size;				// Read buffer size
//		int readbuffer_count;
		DWORD readbuffer_timeout;

		int writebuffer_size;				// write buffer size
		int writebuffer_count;
		DWORD writebuffer_timeout;

		bool GetAddress(LPCTSTR address, LPCTSTR service, struct sockaddr &saddr) {
			ADDRINFOT hints = {0,}, *res;

			hints.ai_family = family;
			hints.ai_socktype = type;
			hints.ai_protocol = protocol;

			if(GetAddrInfo(address, service, &hints, &res) != 0)
				return false;

			if(!res)
			{
				if(res) FreeAddrInfo(res);
				return false;
			}

			if(!res->ai_addr)
			{
				if(res) FreeAddrInfo(res);
				return false;
			}

			saddr = *res->ai_addr;

			FreeAddrInfo(res);

			return true;
		}

		socket_config(void)
		{
			family = AF_INET;
			type = SOCK_STREAM;
			protocol = IPPROTO_TCP;
			connect_timeout = 5000;
			nodelay = false;

			readbuffer_size = 256*1024;		// 256KB
//			readbuffer_count = 16;			// 4MB
			readbuffer_timeout = 100;		// 100ms

			writebuffer_size = 256*1024;	// 256KB
			writebuffer_count = 16;			// 4MB
			writebuffer_timeout = 100;		// 100ms
		}

		~socket_config(void) {
		}
	};

	class hsocket {
	protected:
		SOCKET Handle;

	public:
		bool create(const socket_config &config) {
			SOCKET s = WSASocket(config.family, config.type, config.protocol,
				NULL, NULL, WSA_FLAG_OVERLAPPED);

			if(config.nodelay)
			{
				int iOptVal = 1;
				int iOptLen = sizeof(int);
				setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&iOptVal, iOptLen);
			}

			reset(s);
			return Handle != INVALID_SOCKET;
		}

		void reset(SOCKET hsock = INVALID_SOCKET) {
			if(Handle != INVALID_SOCKET)
				closesocket(Handle);
			Handle = hsock;
		}

		SOCKET release(void) {
			SOCKET hsock = Handle;
			Handle = INVALID_SOCKET;
			return hsock;
		}

		SOCKET get(void) {
			return Handle;
		}

		hsocket& operator =(SOCKET hsock) {
			reset(hsock);
			return *this;
		}

		operator SOCKET(void) {
			return Handle;
		}

		operator bool(void) {
			return Handle != INVALID_SOCKET;
		}


		hsocket(SOCKET hsock = INVALID_SOCKET) {
			Handle = hsock;
		}

		~hsocket(void) {
			if(Handle != INVALID_SOCKET)
				closesocket(Handle);
		}
	};


protected:
	class trans_buffer {
	public:
		class Buffer : public WSABUF, public WSAOVERLAPPED {
		private:
			std::vector<char> buffer;
			bool inuse;

		public:
			int maxlen;
			trans_buffer *parent;

			friend class trans_buffer;
		};

	private:
		typedef std::vector<Buffer>		buffer_list;

		bool isread;
		bool destroy;
		buffer_list buffers;

		HANDLE hSemaphore;
		CRITICAL_SECTION m_crit;

		void lock(void) {
			EnterCriticalSection(&m_crit);
		}

		void unlock(void) {
			LeaveCriticalSection(&m_crit);
		}

	public:
		bool isreadbuffer(void) {
			return isread;
		}

		Buffer* get(DWORD timeout = INFINITE) {
			if(WaitForSingleObject(hSemaphore, timeout) != WAIT_OBJECT_0)
				return NULL;

			if(destroy)
			{
				ReleaseSemaphore(hSemaphore, 1, NULL);
				return NULL;
			}

			lock();

			Buffer *buf = NULL;
			for(ULONG i = 0; i < buffers.size(); i++)
			{
				if(!buffers[i].inuse)
				{
					buffers[i].inuse = true;
					unlock();

					return &buffers[i];
				}
			}

			unlock();

			ASSERT(false);

			return NULL;
		}

		void release(Buffer *buffer) {
			if(!buffer->inuse)
				return;

			buffer->inuse = false;

			ReleaseSemaphore(hSemaphore, 1, NULL);
		}

		trans_buffer(bool isreadbuffer, const socket_config &config) {
			isread = isreadbuffer;
			destroy = false;

			long bufsize, bufcount;
			if(isread)
			{
				bufsize = config.readbuffer_size;
				bufcount = 1;	//config.readbuffer_count;
			}
			else
			{
				bufsize = config.writebuffer_size;
				bufcount = config.writebuffer_count;
			}

			buffers.resize(bufcount);
			for(ULONG i = 0; i < buffers.size(); i++)
			{
				Buffer &buf = buffers[i];

				buf.parent = this;
				buf.buffer.resize(bufsize);
				buf.inuse = false;
				buf.buf = &buf.buffer[0];
				buf.len = isread ? bufsize : 0;
				buf.maxlen = bufsize;
			}

			hSemaphore = CreateSemaphore(NULL, bufcount, bufcount, NULL);

			InitializeCriticalSection(&m_crit);
		}

		virtual ~trans_buffer(void) {
			destroy = true;

			for(ULONG i = 0; i < buffers.size(); i++)
				WaitForSingleObject(hSemaphore, INFINITE);

			CloseHandle(hSemaphore);

			DeleteCriticalSection(&m_crit);
		}
	};

	typedef std::tr1::function<void(BOOL, DWORD, LPOVERLAPPED)>		iocp_func;

	typedef std::tr1::shared_ptr<trans_buffer>		buffer_ptr;

	socket_config m_config;

	std::basic_string<TCHAR> m_address;
	std::basic_string<TCHAR> m_service;

	hsocket m_socket;
	bool m_close_by_peer;

	buffer_ptr m_recv_buffer;
	buffer_ptr m_send_buffer;

	da_iocp m_iocp;
	da_iocp::proc_ptr m_iocp_proc;
	da_iocp::proc_ptr m_discon_proc;

	da_thread m_thread_close;

	CRITICAL_SECTION m_crit;


	inline void Lock(void)
	{
		EnterCriticalSection(&m_crit);
	}

	inline void Unlock(void)
	{
		LeaveCriticalSection(&m_crit);
	}

	void InitializeBuffer(void)
	{
		m_recv_buffer.reset(new trans_buffer(true, m_config));
		m_send_buffer.reset(new trans_buffer(false, m_config));
	}

	void ReleaseBuffer(void)
	{
		m_recv_buffer.reset();
		m_send_buffer.reset();
	}

	bool Recv(void)
	{
		trans_buffer::Buffer *buf = m_recv_buffer->get(m_config.readbuffer_timeout);
		if(!buf) return false;

		ZeroMemory((LPWSAOVERLAPPED)buf, sizeof(WSAOVERLAPPED));

		DWORD flags = 0;
		if(WSARecv(m_socket, buf, 1, NULL, &flags, buf, NULL) == SOCKET_ERROR)
		{
			if(WSAGetLastError() != WSA_IO_PENDING)
			{
				m_recv_buffer->release(buf);
				return false;
			}
		}

		return true;
	}

	void CallClose(bool closeByPeer)
	{
		if(!m_socket || m_thread_close)
			return;

		Lock();

		m_close_by_peer = closeByPeer;

		m_thread_close.create(
			da_thread::thread_proc(
				std::tr1::bind(&da_socket::CloseProc, this)));

		Unlock();
	}


	void ReadWriteProc(BOOL bResult, DWORD nTransBytes, LPOVERLAPPED pOverlapped)
	{
		trans_buffer::Buffer *buffer = (trans_buffer::Buffer*)pOverlapped;
		if(!buffer)
		{
			CallClose(true);
			return;
		}

		if(!bResult || !m_socket)
		{
			buffer->parent->release(buffer);
			CallClose(true);
			return;
		}

		if(buffer->parent->isreadbuffer())
		{
			OnReceived(buffer->buf, nTransBytes);
			buffer->parent->release(buffer);

			if(!Recv())
			{
				CallClose(true);
				return;
			}
		}
		else
		{
			buffer->parent->release(buffer);
		}
	}

	DWORD CloseProc(void)
	{
		SOCKET s = m_socket.get();
		m_socket.reset();

		ReleaseBuffer();

		Lock();

		if(m_discon_proc)
		{
			m_discon_proc->Post(0, (LPOVERLAPPED)s);
			m_discon_proc.reset();
		}

		OnDisconnect();

		m_iocp.close();

		m_iocp_proc.reset();

		Unlock();

		return 0;
	}

	virtual void OnDisconnect(void) = 0;
	virtual void OnReceived(LPVOID pBuffer, DWORD length) = 0;

public:
	bool Connect(LPCTSTR address, LPCTSTR service)
	{
		Lock();

		if(m_socket || m_thread_close.isactive())
		{
			Unlock();
			return false;
		}

		Unlock();

		m_thread_close.close();

		m_close_by_peer = false;

		m_address = address;
		m_service = service;

		struct sockaddr addr;
		if(!m_config.GetAddress(m_address.c_str(), m_service.c_str(), addr))
			return false;

		hsocket tsocket;
		if(!tsocket.create(m_config))
			return false;

		WSAEVENT hEvent = WSACreateEvent();
		if(WSAEventSelect(tsocket, hEvent, FD_CONNECT) == SOCKET_ERROR)
		{
			WSACloseEvent(hEvent);
			return false;
		}

		if(connect(tsocket, &addr, sizeof(addr)) != 0)
		{
			if(WSAGetLastError() != WSAEWOULDBLOCK)
			{
				WSACloseEvent(hEvent);
				return false;
			}
		}

		DWORD ret = WSAWaitForMultipleEvents(1, &hEvent, FALSE, m_config.connect_timeout, FALSE);
		if(ret != WSA_WAIT_EVENT_0)
		{
			WSACloseEvent(hEvent);
			return false;
		}

		if(!m_iocp.create())
		{
			return false;
		}

		m_iocp_proc = m_iocp.attach((HANDLE)tsocket.get(),
			iocp_func(
				std::tr1::bind(
					&da_socket::ReadWriteProc,
					this,
					std::tr1::placeholders::_1,
					std::tr1::placeholders::_2,
					std::tr1::placeholders::_3)));
		if(!m_iocp_proc)
		{
			m_iocp.close();
			return false;
		}

		InitializeBuffer();

		m_socket = tsocket.release();

		if(!Recv())
		{
			m_socket.reset();
			m_iocp.close();
			m_iocp_proc.reset();
			ReleaseBuffer();
			return false;
		}

		return true;
	}

	bool Attach(SOCKET hsock, da_iocp &iocp, da_iocp::proc_ptr discon = da_iocp::proc_ptr())
	{
		if(m_socket || m_thread_close.isactive())
			return false;

		m_thread_close.close();

		m_close_by_peer = false;

		m_discon_proc = discon;

		m_iocp_proc = iocp.attach((HANDLE)hsock,
			iocp_func(
				std::tr1::bind(
					&da_socket::ReadWriteProc,
					this,
					std::tr1::placeholders::_1,
					std::tr1::placeholders::_2,
					std::tr1::placeholders::_3)));
		if(!m_iocp_proc)
		{
			return false;
		}

		InitializeBuffer();

		m_socket.reset(hsock);

		if(!Recv())
		{
			m_socket.reset();
			m_iocp_proc.reset();
			ReleaseBuffer();
			return false;
		}

		return true;
	}

	bool Send(LPVOID pBuffer, DWORD length)
	{
		if(!m_socket)
			return false;

		trans_buffer::Buffer *buf = m_send_buffer->get(m_config.writebuffer_timeout);
		if(!buf) return false;

		if(length > (ULONG)buf->maxlen)
		{
			m_send_buffer->release(buf);
			return false;
		}

		ZeroMemory((LPWSAOVERLAPPED)buf, sizeof(WSAOVERLAPPED));

		memcpy(buf->buf, pBuffer, length);
		buf->len = length;

		if(WSASend(m_socket, buf, 1, NULL, 0, buf, NULL) == SOCKET_ERROR)
		{
			DWORD err = WSAGetLastError();
			if(err != WSA_IO_PENDING)
			{
				m_send_buffer->release(buf);
				return false;
			}
		}

		return true;
	}

	void Close(void)
	{
		CallClose(false);

		if(m_thread_close)
			m_thread_close.wait();

		m_thread_close.close();
	}

	SOCKET GetSocket(void)
	{
		return m_socket;
	}

	operator bool(void)
	{
		return m_socket;
	}

	da_socket(const socket_config &config = socket_config())
		: m_config(config)
	{
		InitializeCriticalSection(&m_crit);
	}

	virtual ~da_socket(void)
	{
		Close();

		DeleteCriticalSection(&m_crit);
	}


	static bool Startup(BYTE major = 2, BYTE minor = 2) {
		WSADATA wd;
		return WSAStartup(MAKEWORD(major, minor), &wd) == 0;
	}

	static bool Cleanup(void) {
		return WSACleanup() == 0;
	}
};


template <class TSocket>
class da_host {
public:
	class host_config : public da_socket::socket_config {
	public:
		DWORD firstdata;				// first data stream size

		host_config(void) {
			firstdata = 0;
		}

		~host_config(void) {
		}
	};

protected:
	typedef struct OVL_ACCEPT : public OVERLAPPED {
		da_socket::hsocket accept_socket;
		std::vector<BYTE> buffer;
		ULONG addrsize;
		ULONG firstdata_size;
	} OVL_ACCEPT, *POVL_ACCEPT;


	typedef std::tr1::function<void(BOOL, DWORD, LPOVERLAPPED)>		iocp_func;

	typedef std::tr1::shared_ptr<TSocket>			client_ptr;
	typedef std::map<SOCKET, client_ptr>			client_map;


	host_config m_config;

	std::basic_string<TCHAR> m_service;
	da_socket::hsocket m_socket;

	OVL_ACCEPT m_ovl_accept;
	da_iocp m_iocp;
	da_iocp::proc_ptr m_iocp_proc;
	da_iocp::proc_ptr m_discon_proc;

	client_map m_clients;

	CRITICAL_SECTION m_crit;

	LPFN_ACCEPTEX m_AcceptEx;
	LPFN_GETACCEPTEXSOCKADDRS m_GetAcceptExSockAddrs;


	inline void Lock(void)
	{
		EnterCriticalSection(&m_crit);
	}

	inline void Unlock(void)
	{
		LeaveCriticalSection(&m_crit);
	}

	bool GetFunctionPtr(GUID &fguid, LPVOID *pfunc)
	{
		DWORD dwBytes;
		WSAOVERLAPPED wovl;

		ZeroMemory(&wovl, sizeof(wovl));

		int res = WSAIoctl(m_socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
			&fguid, sizeof(fguid),
			pfunc, sizeof(LPVOID), &dwBytes, &wovl, NULL);
		if(res != 0 || dwBytes != sizeof(LPVOID))
			return false;

		return true;
	}

	bool CallAcceptEx(void)
	{
		OVERLAPPED &ovl = m_ovl_accept;
		ZeroMemory(&ovl, sizeof(ovl));

		if(!m_ovl_accept.accept_socket.create(m_config))
			return false;

		m_ovl_accept.addrsize = sizeof(SOCKADDR)+16;
		m_ovl_accept.firstdata_size = m_config.firstdata;

		int bufsize = m_ovl_accept.addrsize*2 + m_ovl_accept.firstdata_size;
		m_ovl_accept.buffer.resize(bufsize);
		ZeroMemory(&m_ovl_accept.buffer[0], bufsize);

		BOOL res = m_AcceptEx(m_socket,
			m_ovl_accept.accept_socket,
			&m_ovl_accept.buffer[0],
			m_ovl_accept.firstdata_size,
			m_ovl_accept.addrsize, m_ovl_accept.addrsize, NULL, &m_ovl_accept);
		if(!res)
		{
			if(WSAGetLastError() != ERROR_IO_PENDING)
			{
				m_ovl_accept.accept_socket.reset();
				return false;
			}
		}

		return true;
	}

	void AcceptExProc(BOOL bResult, DWORD nTransBytes, LPOVERLAPPED pOverlapped)
	{
		POVL_ACCEPT pAccept = (POVL_ACCEPT)pOverlapped;
		if(!pAccept)
			return;

		if(bResult == FALSE)
		{
			pAccept->accept_socket.reset();
			return;
		}

		bool waitnext = true;
		BYTE *pBuffer = NULL;
		SOCKADDR *laddr, *raddr;
		INT laddrsz, raddrsz;

		pBuffer = &pAccept->buffer[0];

		m_GetAcceptExSockAddrs(pBuffer, pAccept->firstdata_size,
			pAccept->addrsize, pAccept->addrsize,
			&laddr, &laddrsz, &raddr, &raddrsz);

		client_ptr cl(new TSocket(m_config));
		if(cl->Attach(pAccept->accept_socket.release(), m_iocp, m_discon_proc))
		{
			if(OnAccept(cl, *raddr, pBuffer, pAccept->firstdata_size, waitnext))
			{
				Lock();
				m_clients[cl->GetSocket()] = cl;
				Unlock();
			}
			else
			{
				cl->Close();
				cl.reset();
			}
		}
		else
		{
			pAccept->accept_socket.reset();
			cl.reset();
		}

		if(waitnext)
		{
			if(!CallAcceptEx())
			{
				// cannot create accept socket
				pAccept->accept_socket.reset();
			}
		}
	}

	void DisconnectProc(BOOL bResult, DWORD nTransBytes, LPOVERLAPPED pOverlapped)
	{
		SOCKET s = (SOCKET)pOverlapped;

		Lock();

		client_map::iterator i = m_clients.find(s);
		if(i == m_clients.end())
		{
			Unlock();
			return;
		}

		OnDisconnect(s);

		i->second->Close();
		m_clients.erase(i);

		Unlock();
	}

	virtual bool OnAccept(client_ptr client, SOCKADDR address,
		BYTE *firstdata, ULONG firstdata_size, bool &waitnext) = 0;

	virtual void OnDisconnect(SOCKET invalid_socket) = 0;

public:
	bool Open(LPCTSTR service)
	{
		if(m_socket)
			return false;

		bool isSuccess = false;

		do {
			m_service = service;

			struct sockaddr addr;
			if(!m_config.GetAddress(_T(""), m_service.c_str(), addr))
				break;

			if(!m_socket.create(m_config))
				break;

			GUID guid_acceptex = WSAID_ACCEPTEX;
			if(!GetFunctionPtr(guid_acceptex, (LPVOID*)&m_AcceptEx))
				break;

			GUID guid_getacceptexsockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
			if(!GetFunctionPtr(guid_getacceptexsockaddrs, (LPVOID*)&m_GetAcceptExSockAddrs))
				break;

			if(bind(m_socket, &addr, sizeof(addr)) != 0)
				break;

			if(listen(m_socket, SOMAXCONN) != 0)
				break;

			if(!m_iocp.create())
				break;

			m_discon_proc = m_iocp.attach(INVALID_HANDLE_VALUE,
				iocp_func(
					std::tr1::bind(
						&da_host::DisconnectProc,
						this,
						std::tr1::placeholders::_1,
						std::tr1::placeholders::_2,
						std::tr1::placeholders::_3)));
			if(!m_discon_proc)
				break;

			m_iocp_proc = m_iocp.attach((HANDLE)m_socket.get(),
				iocp_func(
					std::tr1::bind(
						&da_host::AcceptExProc,
						this,
						std::tr1::placeholders::_1,
						std::tr1::placeholders::_2,
						std::tr1::placeholders::_3)));
			if(!m_iocp_proc)
				break;

			if(!CallAcceptEx())
				break;

			isSuccess = true;

		} while(false);

		if(!isSuccess)
		{
			m_ovl_accept.accept_socket.reset();
			m_socket.reset();
			m_iocp.close();
			m_discon_proc.reset();
			m_iocp_proc.reset();
		}

		return isSuccess;
	}

	void Close(void)
	{
		m_socket.reset();

		while(m_ovl_accept.accept_socket)
			Sleep(1);

		Lock();
		m_clients.clear();
		Unlock();

		m_iocp.close();
		m_discon_proc.reset();
		m_iocp_proc.reset();
	}

	operator bool(void)
	{
		return m_socket;
	}

	da_host(const host_config &config = host_config())
		: m_config(config)
	{
		InitializeCriticalSection(&m_crit);
	}

	virtual ~da_host(void) {
		Close();

		DeleteCriticalSection(&m_crit);
	}
};


DALIBS_IMPLEMENT_END
