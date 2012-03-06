
// palDlg.h : header file
//

#pragma once

#include "CastServer.h"
#include "AdhocClient.h"
#include "da_libs/da_thread.h"
#include "afxwin.h"
#include "adhoc.h"
#include "afxcmn.h"

using namespace adhoc;

#define UM_UPDATECTRL		(WM_USER+100)


// CAdhocLinkerDlg dialog
class CAdhocLinkerDlg : public CDialog
{
// Construction
public:
	enum {
		UC_CONNECT_TRY		= 1,
		UC_CONNECT,
		UC_CONNECT_FAIL,
		UC_DISCONNECT,
		UC_DISCONNECT_PEER,
		UC_UPDATE_STATUS,
		UC_CAPTURE_FAIL,
	};

	CAdhocLinkerDlg(CWnd* pParent = NULL);	// standard constructor

	CastServer m_Server;
	AdhocClient m_Client;

	ADHOC_STATUS m_AdhocStatus;

	da_thread m_ConnThread;

// Dialog Data
	enum { IDD = IDD_PAL_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support

	LRESULT OnUpdateCtrl(WPARAM wParam, LPARAM lParam);
	void OnClientEvent(AdhocClient::ADHOC_EVENT adhoc_event);
	DWORD ConnectProc(void);
	void UpdateList(void);
	void UpdateListItems(ADHOC_STATUS &status);
	void ResetListItems(ADHOC_STATUS &status);
	void LoadAddress(void);
	void StoreAddress(void);


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOpen();
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnBnClickedConnect();
	CEdit m_Port;
	CEdit m_Address;
	CButton m_Open;
	CButton m_Connect;
	CComboBox m_Adaptor;
	afx_msg void OnBnClickedRefresh();
	CButton m_Refresh;
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnDestroy();
	CListCtrl m_ClientList;
	CListCtrl m_DeviceList;
};
