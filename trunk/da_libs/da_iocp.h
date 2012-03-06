#pragma once

#include "da_libs.h"
#include "da_thread.h"

#include <list>

#include <windows.h>


DALIBS_IMPLEMENT_BEGIN


class da_iocp
{
public:
	class iocp_proc_base {
	public:
		virtual void Procedure(BOOL bResult, DWORD nTransBytes, LPOVERLAPPED pOverlapped) = 0;
		virtual bool Post(DWORD nTransBytes, LPOVERLAPPED pOverlapped) = 0;
	};

	typedef std::tr1::shared_ptr<iocp_proc_base>	proc_ptr;

protected:
	template <class TProcedure>
	class iocp_proc : public iocp_proc_base {
	protected:
		HANDLE m_hIOCP;
		TProcedure m_procedure;

	public:
		virtual void Procedure(BOOL bResult, DWORD nTransBytes, LPOVERLAPPED pOverlapped) {
			return m_procedure(bResult, nTransBytes, pOverlapped);
		}

		virtual bool Post(DWORD nTransBytes, LPOVERLAPPED pOverlapped) {
			return PostQueuedCompletionStatus(
				m_hIOCP, nTransBytes, (ULONG_PTR)this, pOverlapped) != FALSE;
		}

		iocp_proc(HANDLE hIOCP, TProcedure proc) {
			m_hIOCP = hIOCP;
			m_procedure = proc;
		}
	};

	typedef std::tr1::shared_ptr<da_thread>			thread_ptr;


	HANDLE m_iocp;
	std::list<thread_ptr> m_threads;

	DWORD ThreadProc(void)
	{
		BOOL res, destroy = FALSE;
		DWORD size;
		ULONG_PTR key;
		LPOVERLAPPED pOverlapped;
		iocp_proc_base *proc;

		while(true)
		{
			size = 0;
			pOverlapped = NULL;
			res = GetQueuedCompletionStatus(m_iocp, &size, &key, (LPOVERLAPPED*)&pOverlapped, INFINITE);

			if(!m_iocp)
			{
				// Request or dequeue failed
				break;
			}

			if(!key)
				continue;

			proc = (iocp_proc_base*)key;
			proc->Procedure(res, size, pOverlapped);
		}

		return 0;
	}

public:
	bool create(int threads = 0)
	{
		if(m_iocp != NULL)
			return false;

		m_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0);
		if(m_iocp == NULL)
			return false;

		SYSTEM_INFO si;
		GetSystemInfo(&si);

		if(threads <= 0)
		{
			threads = si.dwNumberOfProcessors;
			threads *= 2;

			if(threads < 4)
				threads = 4;
		}

		for(int i = 0; i < threads; i++)
		{
			thread_ptr thr(new da_thread);
			if(!thr->create(
				da_thread::thread_proc(
					std::tr1::bind(&da_iocp::ThreadProc, this))))
				break;

			m_threads.push_back(thr);
		}

		if(m_threads.empty())
		{
			CloseHandle(m_iocp);
			m_iocp = NULL;
			return false;
		}

		return true;
	}

	template <class TProcedure>
	proc_ptr attach(HANDLE handle, TProcedure proc) {
		if(!m_iocp) return proc_ptr();

		proc_ptr pobj(new iocp_proc<TProcedure>(m_iocp, proc));

		if(handle != INVALID_HANDLE_VALUE)
		{
			if(CreateIoCompletionPort(handle, m_iocp, (ULONG_PTR)pobj.get(), 0) == NULL)
				return proc_ptr();
		}

		return pobj;
	}

	void close(void) {
		if(!m_iocp)
			return;

		CloseHandle(m_iocp);
		m_iocp = NULL;

		std::list<thread_ptr>::iterator i = m_threads.begin();
		while(i != m_threads.end())
		{
			thread_ptr thr = *i++;

			thr->wait();
			thr->close();
		}

		m_threads.clear();
	}


	da_iocp(void) {
		m_iocp = NULL;
	}

	virtual ~da_iocp(void) {
		close();
	}
};


DALIBS_IMPLEMENT_END
