// LPE_CAbout.cpp: 实现文件
//

#include "pch.h"
#include "LPE_CAbout.h"
#include "afxdialogex.h"

// CAbout 对话框

IMPLEMENT_DYNAMIC(CAbout, CDialogEx)

CAbout::CAbout(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_ABOUT, pParent)
{
}

CAbout::~CAbout()
{
}

void CAbout::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_STATIC_BMAP, m_bmap);
	DDX_Control(pDX, IDC_STATIC_LINK, m_link);
}

// 初始化	设置图片背景
BOOL CAbout::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	m_bmap.ModifyStyle(0xF, SS_BITMAP | SS_CENTERIMAGE);
	HBITMAP hBitmap = LoadBitmap(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDB_BITMAP1));
	m_bmap.SetBitmap(hBitmap);
	return TRUE;
}

BEGIN_MESSAGE_MAP(CAbout, CDialogEx)
END_MESSAGE_MAP()

