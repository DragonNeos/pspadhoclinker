
// palDlg.cpp : implementation file
//

#include "stdafx.h"
#include "pal.h"
#include "palDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAdhocLinkerDlg dialog




CAdhocLinkerDlg::CAdhocLinkerDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CAdhocLinkerDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

	m_Client.SetNotify(
		AdhocClient::notify_proc(
			std::tr1::bind(&CAdhocLinkerDlg::OnClientEvent, this, std::tr1::placeholders::_1)));
}

void CAdhocLinkerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PORT, m_Port);
	DDX_Control(pDX, IDC_SERVER, m_Address);
	DDX_Control(pDX, IDC_OPEN, m_Open);
	DDX_Control(pDX, IDC_CONNECT, m_Connect);
	DDX_Control(pDX, IDC_ADAPTOR, m_Adaptor);
	DDX_Control(pDX, IDC_REFRESH, m_Refresh);
	DDX_Control(pDX, IDC_CLIENT, m_ClientList);
	DDX_Control(pDX, IDC_DEVICE, m_DeviceList);
}

BEGIN_MESSAGE_MAP(CAdhocLinkerDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_OPEN, &CAdhocLinkerDlg::OnBnClickedOpen)
	ON_BN_CLICKED(IDOK, &CAdhocLinkerDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CAdhocLinkerDlg::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_CONNECT, &CAdhocLinkerDlg::OnBnClickedConnect)
	ON_BN_CLICKED(IDC_REFRESH, &CAdhocLinkerDlg::OnBnClickedRefresh)
	ON_MESSAGE(UM_UPDATECTRL, &CAdhocLinkerDlg::OnUpdateCtrl)
	ON_WM_TIMER()
	ON_WM_DESTROY()
END_MESSAGE_MAP()


// CAdhocLinkerDlg message handlers

BOOL CAdhocLinkerDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	ZeroMemory(&m_AdhocStatus, sizeof(m_AdhocStatus));

	CRect cr;
	GetClientRect(cr);

	long w = cr.Width();

	m_ClientList.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	m_DeviceList.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

	m_ClientList.InsertColumn(0, _T("Name"), LVCFMT_LEFT, long(w*0.15));
	m_ClientList.InsertColumn(1, _T("Ping"), LVCFMT_LEFT, long(w*0.1));
	m_ClientList.InsertColumn(2, _T("SSID"), LVCFMT_LEFT, long(w*0.7));


	m_DeviceList.InsertColumn(0, _T("Name"), LVCFMT_LEFT, long(w*0.15));
	m_DeviceList.InsertColumn(1, _T("Broadcast"), LVCFMT_LEFT, long(w*0.2));
	m_DeviceList.InsertColumn(2, _T("P2P"), LVCFMT_LEFT, long(w*0.2));
	m_DeviceList.InsertColumn(3, _T("Owner"), LVCFMT_LEFT, long(w*0.15));


	OnBnClickedRefresh();


	m_Port.SetWindowText(_T("4649"));
	m_Address.SetWindowText(_T(""));


	LoadAddress();


	SetTimer(0, 500, NULL);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CAdhocLinkerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CAdhocLinkerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CAdhocLinkerDlg::OnBnClickedOpen()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.

	CString port;
	m_Port.GetWindowText(port);

	if(m_Server)
	{
		m_Server.Close();
		OnUpdateCtrl(0 , 0);
	}
	else
	{
		if(!m_Server.Open(port))
		{
			MessageBox(_T("Cannot open server"));
			return;
		}

		OnUpdateCtrl(0 , 0);
	}
}

void CAdhocLinkerDlg::OnBnClickedOk()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
}

void CAdhocLinkerDlg::OnBnClickedCancel()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	if(m_ConnThread.isactive())
		return;

	m_Client.Close();
	m_Server.Close();

	OnCancel();
}

void CAdhocLinkerDlg::OnBnClickedConnect()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.

	if(m_Client)
	{
		m_Client.Close();
		OnUpdateCtrl(0 , 0);
	}
	else
	{
		m_ConnThread.wait();
		m_ConnThread.close();

		StoreAddress();

		m_ConnThread.create(
			da_thread::thread_proc(
				std::tr1::bind(&CAdhocLinkerDlg::ConnectProc, this)));

		OnUpdateCtrl(UC_CONNECT_TRY, 0);
	}
}

void CAdhocLinkerDlg::OnClientEvent(AdhocClient::ADHOC_EVENT adhoc_event)
{
	if(!IsWindow(m_hWnd))
		return;

	switch(adhoc_event)
	{
	case AdhocClient::ADHOC_DISCONNECT_PEER:
		PostMessage(UM_UPDATECTRL, UC_DISCONNECT_PEER, NULL);
		break;

	case AdhocClient::ADHOC_DISCONNECT:
		PostMessage(UM_UPDATECTRL, UC_DISCONNECT, NULL);
		break;

	case AdhocClient::ADHOC_UPDATE_STATUS:
		PostMessage(UM_UPDATECTRL, UC_UPDATE_STATUS, NULL);
		break;

	case AdhocClient::ADHOC_CAPTURE_FAIL:
		PostMessage(UM_UPDATECTRL, UC_CAPTURE_FAIL, NULL);
		break;
	}
}

DWORD CAdhocLinkerDlg::ConnectProc(void)
{
	CString port, addr, dev;
	m_Port.GetWindowText(port);
	m_Address.GetWindowText(addr);
	m_Adaptor.GetWindowText(dev);

	if(!m_Client.Connect(addr, port, dev))
	{
		PostMessage(UM_UPDATECTRL, UC_CONNECT_FAIL, NULL);

		return 0;
	}

	PostMessage(UM_UPDATECTRL, UC_CONNECT, NULL);

	return 0;
}

void CAdhocLinkerDlg::OnBnClickedRefresh()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.

	int index = m_Adaptor.GetCurSel();

	m_Adaptor.SetRedraw(FALSE);

	m_Adaptor.ResetContent();

	AdhocClient::adaptor_list alist;
	m_Client.GetAdaptors(alist);

	AdhocClient::adaptor_list::iterator i = alist.begin();
	while(i != alist.end())
	{
		m_Adaptor.AddString(i->c_str());
		i++;
	}

	if(m_Adaptor.SetCurSel(index) == CB_ERR)
		m_Adaptor.SetCurSel(0);

	m_Adaptor.SetRedraw(TRUE);
}

LRESULT CAdhocLinkerDlg::OnUpdateCtrl(WPARAM wParam, LPARAM lParam)
{
	if(!IsWindow(m_hWnd))
		return 0;

	bool s = m_Server;
	int c = -1;

	switch(wParam)
	{
	case UC_CONNECT_TRY:
		c = true;
		m_Connect.EnableWindow(FALSE);
		m_Connect.SetWindowText(_T("Try connect ..."));
		break;

	case UC_CONNECT:
		c = true;
		m_Connect.EnableWindow(TRUE);
		m_Connect.SetWindowText(_T("Disconnect"));
		break;

	case UC_CONNECT_FAIL:
		MessageBox(_T("Cannot connect server"));

		m_Connect.EnableWindow(TRUE);
		m_Connect.SetWindowText(_T("Connect"));
		c = false;
		break;

	case UC_DISCONNECT:
		c = false;
		m_Connect.EnableWindow(TRUE);
		m_Connect.SetWindowText(_T("Connect"));

		m_ClientList.DeleteAllItems();
		m_DeviceList.DeleteAllItems();

		ZeroMemory(&m_AdhocStatus, sizeof(m_AdhocStatus));
		break;

	case UC_DISCONNECT_PEER:
		MessageBox(_T("Disconnect by peer"));

		c = false;
		m_Connect.EnableWindow(TRUE);
		m_Connect.SetWindowText(_T("Connect"));

		m_ClientList.DeleteAllItems();
		m_DeviceList.DeleteAllItems();

		ZeroMemory(&m_AdhocStatus, sizeof(m_AdhocStatus));
		break;

	case UC_UPDATE_STATUS:
		UpdateList();
		return 0;

	case UC_CAPTURE_FAIL:
		MessageBox(_T("Cannot capture packet.\nCheck for WinPcap."));
		return 0;

	default:
		break;
	}

	if(c >= 0)
	{
		m_Adaptor.EnableWindow(!c);
		m_Refresh.EnableWindow(!c);
		m_Address.EnableWindow(!c);
		m_Port.EnableWindow(!c && !s);
	}
	else m_Port.EnableWindow(!s);

	if(s) m_Open.SetWindowText(_T("Server close"));
	else m_Open.SetWindowText(_T("Server open"));

	return 0;
}

void CAdhocLinkerDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: 여기에 메시지 처리기 코드를 추가 및/또는 기본값을 호출합니다.

	if(m_Server)
	{
		m_Server.UpdateStatus();
	}

	CDialog::OnTimer(nIDEvent);
}

void CAdhocLinkerDlg::OnDestroy()
{
	CDialog::OnDestroy();

	// TODO: 여기에 메시지 처리기 코드를 추가합니다.

	KillTimer(0);

	StoreAddress();
}

void CAdhocLinkerDlg::UpdateList(void)
{
	ADHOC_STATUS status;

	if(!m_Client.GetAdhocStatus(status))
	{
		m_ClientList.DeleteAllItems();
		m_DeviceList.DeleteAllItems();
		return;
	}

	if(!memcmp(&m_AdhocStatus, &status, sizeof(m_AdhocStatus)))
		return;

	if(m_AdhocStatus.ClientInfoCount != status.ClientInfoCount ||
		m_AdhocStatus.DeviceInfoCount != status.DeviceInfoCount)
	{
		ResetListItems(status);
	}
	else
	{
		UpdateListItems(status);
	}

	m_AdhocStatus = status;
}

void CAdhocLinkerDlg::UpdateListItems(ADHOC_STATUS &status)
{
	if(memcmp(m_AdhocStatus.ClientInfo, status.ClientInfo, sizeof(m_AdhocStatus.ClientInfo)))
	{
		for(ULONG i = 0; i < status.ClientInfoCount; i++)
		{
			CString str;

			if(strcmp(status.ClientInfo[i].Name, m_AdhocStatus.ClientInfo[i].Name))
			{
				str.Format(_T("%hs"), status.ClientInfo[i].Name);
				m_ClientList.SetItemText(i, 0, str);
			}

			if(status.ClientInfo[i].Ping != m_AdhocStatus.ClientInfo[i].Ping)
			{
				str.Format(_T("%u"), status.ClientInfo[i].Ping);
				m_ClientList.SetItemText(i, 1, str);
			}

			if(strcmp(status.ClientInfo[i].SSID, m_AdhocStatus.ClientInfo[i].SSID))
			{
				str.Format(_T("%hs"), status.ClientInfo[i].SSID);
				m_ClientList.SetItemText(i, 2, str);
			}
		}
	}

	if(memcmp(m_AdhocStatus.DeviceInfo, status.DeviceInfo, sizeof(m_AdhocStatus.DeviceInfo)))
	{
		for(ULONG i = 0; i < status.DeviceInfoCount; i++)
		{
			CString str;

			if(strcmp(status.DeviceInfo[i].Name, m_AdhocStatus.DeviceInfo[i].Name))
			{
				str.Format(_T("%hs"), status.DeviceInfo[i].Name);
				m_DeviceList.SetItemText(i, 0, str);
			}

			if(status.DeviceInfo[i].Broadcast, m_AdhocStatus.DeviceInfo[i].Broadcast)
			{
				str.Format(_T("%u"), status.DeviceInfo[i].Broadcast);
				m_DeviceList.SetItemText(i, 1, str);
			}

			if(status.DeviceInfo[i].P2P, m_AdhocStatus.DeviceInfo[i].P2P)
			{
				str.Format(_T("%u"), status.DeviceInfo[i].P2P);
				m_DeviceList.SetItemText(i, 2, str);
			}

			if(strcmp(status.DeviceInfo[i].Owner, m_AdhocStatus.DeviceInfo[i].Owner))
			{
				str.Format(_T("%hs"), status.DeviceInfo[i].Owner);
				m_DeviceList.SetItemText(i, 3, str);
			}
		}
	}
}

void CAdhocLinkerDlg::ResetListItems(ADHOC_STATUS &status)
{
	m_ClientList.SetRedraw(FALSE);
	m_DeviceList.SetRedraw(FALSE);

	m_ClientList.DeleteAllItems();
	m_DeviceList.DeleteAllItems();

	for(ULONG i = 0; i < status.ClientInfoCount; i++)
	{
		CString str;
		str.Format(_T("%hs"), status.ClientInfo[i].Name);
		m_ClientList.InsertItem(i, str);

		str.Format(_T("%u"), status.ClientInfo[i].Ping);
		m_ClientList.SetItemText(i, 1, str);

		str.Format(_T("%hs"), status.ClientInfo[i].SSID);
		m_ClientList.SetItemText(i, 2, str);
	}

	for(ULONG i = 0; i < status.DeviceInfoCount; i++)
	{
		CString str;
		str.Format(_T("%hs"), status.DeviceInfo[i].Name);
		m_DeviceList.InsertItem(i, str);

		str.Format(_T("%u"), status.DeviceInfo[i].Broadcast);
		m_DeviceList.SetItemText(i, 1, str);

		str.Format(_T("%u"), status.DeviceInfo[i].P2P);
		m_DeviceList.SetItemText(i, 2, str);

		str.Format(_T("%hs"), status.DeviceInfo[i].Owner);
		m_DeviceList.SetItemText(i, 3, str);
	}

	m_ClientList.SetRedraw(TRUE);
	m_DeviceList.SetRedraw(TRUE);
}

void CAdhocLinkerDlg::LoadAddress(void)
{
	HKEY  hKey;

	LSTATUS lRet = RegOpenKeyEx(HKEY_CURRENT_USER, _T("Software\\PSPAdhocLinker"), 0, KEY_READ, &hKey);
	if(lRet != ERROR_SUCCESS)
		return;

	do {
		TCHAR Value[MAX_PATH];
		DWORD cbSize = sizeof(Value);
		DWORD Type = REG_SZ;
		lRet = RegQueryValueEx(hKey, _T("Port"), 0, &Type, (LPBYTE)Value, &cbSize);
		if(lRet != ERROR_SUCCESS)
			break;

		m_Port.SetWindowText(Value);

		cbSize = sizeof(Value);
		Type = REG_SZ;
		lRet = RegQueryValueEx(hKey, _T("Address"), 0, &Type, (LPBYTE)Value, &cbSize);
		if(lRet != ERROR_SUCCESS)
			break;

		m_Address.SetWindowText(Value);
	} while(false);

	RegCloseKey(hKey);
}

void CAdhocLinkerDlg::StoreAddress(void)
{
	HKEY  hKey;
	DWORD dwDisp;

	LSTATUS lRet = RegCreateKeyEx(HKEY_CURRENT_USER, _T("Software\\PSPAdhocLinker"), 0, NULL,
		REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisp);
	if(lRet != ERROR_SUCCESS)
		return;

	CString Value;

	m_Port.GetWindowText(Value);
	RegSetValueEx(hKey, _T("Port"), 0, REG_SZ, (LPBYTE)Value.GetString(), (Value.GetLength()+1)*sizeof(TCHAR));

	m_Address.GetWindowText(Value);
	RegSetValueEx(hKey, _T("Address"), 0, REG_SZ, (LPBYTE)Value.GetString(), (Value.GetLength()+1)*sizeof(TCHAR));

	RegCloseKey(hKey);
}
