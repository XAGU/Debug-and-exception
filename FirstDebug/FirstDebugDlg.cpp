
// FirstDebugDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "FirstDebug.h"
#include "FirstDebugDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CFirstDebugDlg 对话框



CFirstDebugDlg::CFirstDebugDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_FIRSTDEBUG_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CFirstDebugDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CFirstDebugDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CFirstDebugDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CFirstDebugDlg 消息处理程序

BOOL CFirstDebugDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CFirstDebugDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CFirstDebugDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CFirstDebugDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

DWORD WINAPI ThreadPro(LPVOID lpParam)
{
	CFirstDebugDlg* firstDebug = (CFirstDebugDlg*)lpParam;
	DWORD process_id = firstDebug->GetDlgItemInt(IDC_EDIT1);
	if (process_id == 0)
	{
		AfxMessageBox(L"请输入要调试进程的Pid！");
		return 0;
	}
	//开始调试
	if (!DebugActiveProcess(process_id))
	{
		AfxMessageBox(L"调试目标进程失败！");
		return 0;
	}
	while (true)
	{
		DEBUG_EVENT debug_info;
		WaitForDebugEvent(&debug_info, INFINITE);
		CString string;
		//firstDebug->GetDlgItemText(IDC_EDIT2, string);
		//string.Format(L"%s \r\n有调试事件到来，事件类型为：%d",string,debug_info.dwDebugEventCode);
		//firstDebug->SetDlgItemText(IDC_EDIT2, string.GetBuffer());
		switch (debug_info.dwDebugEventCode)
		{
		//case CREATE_THREAD_DEBUG_EVENT:
		//{
		//	CString string;
		//	firstDebug->GetDlgItemText(IDC_EDIT2, string);
		//	string.Format(L"%s \r\nMessageId:CREATE_THREAD_DEBUG_EVENT ThreadAddress:%x",
		//		string,
		//		debug_info.u.CreateThread.lpStartAddress);
		//	firstDebug->SetDlgItemText(IDC_EDIT2, string.GetBuffer());
		//	break;
		//}
		case EXCEPTION_DEBUG_EVENT:
		{
			if (debug_info.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
			{
				firstDebug->GetDlgItemText(IDC_EDIT2, string);
				string.Format(L"%s \r\nEXCEPTION_ADDRESS:%X", string, debug_info.u.Exception.ExceptionRecord.ExceptionAddress);
				firstDebug->SetDlgItemText(IDC_EDIT2, string.GetBuffer());
			}
			break;
		}
		default:
			break;
		}
		ContinueDebugEvent(process_id, debug_info.dwThreadId, DBG_CONTINUE);
	}

	//结束调试
	DebugActiveProcessStop(process_id);
	return 0;
}


void CFirstDebugDlg::OnBnClickedButton1()
{
	CreateThread(NULL, NULL, ThreadPro, this, 0, NULL);
}
