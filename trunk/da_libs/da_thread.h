#pragma once

#include "da_libs.h"

#include <functional>


DALIBS_IMPLEMENT_BEGIN


class da_thread
{
public:
	typedef std::tr1::function<DWORD(void)>		thread_proc;

private:
	HANDLE m_hthread;

	static DWORD CALLBACK ThreadProc(LPVOID context) {
		thread_proc *proc = (thread_proc*)context;
		if(!proc) return 1;

		DWORD ret = (*proc)();
		delete proc;

		return ret;
	}

public:
	template <class TProcedure>
	bool create(TProcedure proc) {
		if(m_hthread != NULL)
			return false;

		thread_proc *ptr = new thread_proc(proc);

		DWORD id;
		m_hthread = CreateThread(NULL, NULL, ThreadProc, ptr, NULL, &id);
		if(!m_hthread)
		{
			delete ptr;
			return false;
		}

		return true;
	}

	DWORD id(void) {
		return GetThreadId(m_hthread);
	}

	bool wait(unsigned int timeout = INFINITE) {
		HANDLE hThread = m_hthread;

		if(!isactive())
			return true;

		return WaitForSingleObject(hThread, timeout) == WAIT_OBJECT_0;
	}

	DWORD exitcode(void) {
		if(!m_hthread)
			return 0;

		DWORD exitcode = (DWORD)-1;
		GetExitCodeThread(m_hthread, &exitcode);
		return exitcode;
	}

	bool isactive(void) {
		return exitcode() == STILL_ACTIVE;
	}

	bool terminate(DWORD exitcode) {
		if(TerminateThread(m_hthread, exitcode) == FALSE)
			return false;
		return true;
	}

	void close(void) {
		if(m_hthread)
		{
			CloseHandle(m_hthread);
			m_hthread = NULL;
		}
	}

	operator bool(void) const {
		return m_hthread != NULL;
	}

	operator HANDLE(void) const {
		return m_hthread;
	}

	da_thread(void) {
		m_hthread = NULL;
	}

	~da_thread(void) {
		close();
	}
};


DALIBS_IMPLEMENT_END
