// LPE_CInPack.cpp: 实现文件
//

#include "pch.h"
#include "LPE_CInPack.h"
#include "LPE_Pack.h"

IMPLEMENT_DYNAMIC(CInPack, CDialogEx)

CInPack::CInPack(CWnd* pParent)
	: CDialogEx(IDD_DIALOG_INPACK, pParent)
{
}

CInPack::~CInPack()
{
}

void CInPack::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_INFILE, m_infile);
	DDX_Control(pDX, IDC_EDIT_OUTFILE, m_outfile);
	DDX_Control(pDX, IDC_EDIT_INFILE2, m_shellfile);
}


BEGIN_MESSAGE_MAP(CInPack, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON1, &CInPack::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CInPack::OnBnClickedButton2)
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_BUTTON_INPACK, &CInPack::OnBnClickedButtonInpack)
	ON_BN_CLICKED(IDC_BUTTON4, &CInPack::OnBnClickedButton4)
END_MESSAGE_MAP()


// CInPack 消息处理程序

// 选择文件按钮
void CInPack::OnBnClickedButton1()
{
	TCHAR szFilter[] = TEXT("可执行文件(*.exe)|*.exe||");
	CFileDialog file_browser(TRUE, TEXT(".exe"), NULL, 0, szFilter, this);
	if (file_browser.DoModal() != IDOK) return;

	CString file_path = file_browser.GetPathName();
	CString file_name = file_browser.GetFileName();
	CString folder_path = file_browser.GetFolderPath();
	CString out_path(folder_path);

	m_infile.SetWindowText(file_path);

	out_path.Append(TEXT("\\_"));
	out_path.Append(file_name);
	m_outfile.SetWindowText(out_path);
}

// 保存文件按钮
void CInPack::OnBnClickedButton2()
{
	CString out_path;
	m_outfile.GetWindowText(out_path);

	TCHAR strFilter[] = TEXT("可执行文件(*.exe)|*.exe||");
	CFileDialog file_browser(FALSE, TEXT("exe"), out_path, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, strFilter, this);
	if (file_browser.DoModal() != IDOK) return;
	CString file_path = file_browser.GetPathName();
	m_outfile.SetWindowText(file_path);
}

// 选择壳文件按钮
void CInPack::OnBnClickedButton4()
{
	TCHAR szFilter[] = TEXT("可执行文件(*.dll)|*.dll||");
	CFileDialog file_browser(TRUE, TEXT(".dll"), NULL, 0, szFilter, this);
	if (file_browser.DoModal() != IDOK) return;
	CString file_path = file_browser.GetPathName();
	m_shellfile.SetWindowText(file_path);
}

// 拖拽文件
void CInPack::OnDropFiles(HDROP hDropInfo)
{
	TCHAR szFilename[256] = {};
	DragQueryFile(hDropInfo, 0, szFilename, 254);
	m_infile.SetWindowText(szFilename);

	CString out_file;
	out_file.Format(TEXT("%s"),"D\\pack.exe");
	m_outfile.SetWindowText(out_file);

	CDialogEx::OnDropFiles(hDropInfo);
}

// 一键加壳按钮
void CInPack::OnBnClickedButtonInpack()
{
	CString infile_path;
	CString shellfile_path;
	CString outfile_path;
	m_infile.GetWindowText(infile_path);
	m_shellfile.GetWindowText(shellfile_path);
	m_outfile.GetWindowText(outfile_path);
	if (infile_path.IsEmpty() || shellfile_path.IsEmpty() || outfile_path.IsEmpty()) {
		return;
	}
	// 加壳
	CString info;
	if (InPack(infile_path.GetString(), shellfile_path.GetString(), outfile_path.GetString()))
	{
		info.Format(TEXT("%s\n 输出路径:"),"加壳成功");
		info.Append(outfile_path);
		MessageBox(info, 0, MB_ICONINFORMATION);
	}
	else 
	{
		info.Format(TEXT("%s\n%s\n%s\n%s"),
			"加壳失败", "1、重复加壳会造成加壳不成功", "2、当前程序与目标程序字长不一致", "3、dll错误");
		MessageBox(info, 0, MB_ICONWARNING);
	}
}
