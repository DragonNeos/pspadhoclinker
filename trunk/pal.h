
// pal.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CAdhocLinkerApp:
// See pal.cpp for the implementation of this class
//

class CAdhocLinkerApp : public CWinAppEx
{
public:
	CAdhocLinkerApp();

// Overrides
	public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CAdhocLinkerApp theApp;