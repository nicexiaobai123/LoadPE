﻿// LPE_CMain.cpp: 实现文件
//

#include "pch.h"
#include "LPE_CMain.h"
#include "LPE_CAbout.h"
#include <TlHelp32.h>
#include <psapi.h>

// CMain 对话框
IMPLEMENT_DYNAMIC(CMain, CDialogEx)

CMain::CMain(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_MAIN, pParent)
{	
}

CMain::~CMain()
{
}

// 变量与控件的绑定关系
void CMain::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PROCESS, m_list_process);
	DDX_Control(pDX, IDC_LIST_MODULES, m_list_modules);
}

// 窗口初始化
BOOL CMain::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	this->InitListView();		// 第一个list 
	this->InitListView2();		// 第二个list 

	return TRUE;
}

// 初始化列表控件		遍历进程
void CMain::InitListView()
{
	// 设置加里奥小图标
	// CImageList img_list; // 函数调用完对象被释放,后面无法显示出来,得是成员函数
	HICON hicon = AfxGetApp()->LoadIcon(IDI_ICON2);
	img_list.Create(20, 20, ILC_COLOR32, 1, 1);
	img_list.Add(hicon);
	m_list_process.SetImageList(&img_list, LVSIL_SMALL);

	// 风格
	int style = m_list_process.GetExtendedStyle();
	m_list_process.SetExtendedStyle(style | LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

	// 三列
	m_list_process.InsertColumn(0, TEXT("进程名"), LVCFMT_LEFT, 220);
	m_list_process.InsertColumn(1, TEXT("PID"), LVCFMT_LEFT, 70);
	m_list_process.InsertColumn(2, TEXT("路径"), LVCFMT_LEFT, 400);
	m_list_process.InsertColumn(3, TEXT(""), LVCFMT_LEFT, 20);

	// 遍历进程 
	int row_index = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		MessageBox(TEXT("创建进程快照失败"));
		exit(0);
	}
	PROCESSENTRY32 pro_entry{ sizeof(PROCESSENTRY32) };
	if (Process32First(hSnap, &pro_entry)) {
		do
		{
			CString pid;
			CString name;
			pid.Format(TEXT("%d"), pro_entry.th32ProcessID);
			name.Format(TEXT("%s"), pro_entry.szExeFile);
			m_list_process.InsertItem(row_index, name);			// 名称
			m_list_process.SetItemText(row_index, 1, pid);		// PID

			char* buff = new char[256]{ 0 };
			DWORD path_size = 256;
			HANDLE hprocess = OpenProcess(PROCESS_QUERY_INFORMATION,false, pro_entry.th32ProcessID);

			// 两种方法,都是根据PID获取完全路径 注释的是从device开始
			// int ret = QueryFullProcessImageName(hprocess, 1, path, &path_size);
			int ret = GetModuleFileNameExA(hprocess,NULL, buff, path_size);		   // NULL表示exe文件
			if (ret) {
				CString path(buff);
				m_list_process.SetItemText(row_index, 2, path);	// 路径
			}
			
			delete[] buff;
			CloseHandle(hprocess);
			
			row_index++;
		} while (Process32Next(hSnap, &pro_entry));
	}
}

// 初始化列表控件		第二个列表控件标题
void CMain::InitListView2()
{
	// 风格
	int style = m_list_modules.GetExtendedStyle();
	m_list_modules.SetExtendedStyle(style | LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

	// 四列
	m_list_modules.InsertColumn(0,TEXT("基址"), LVCFMT_LEFT,125);
	m_list_modules.InsertColumn(1, TEXT("大小"), LVCFMT_LEFT,95);
	m_list_modules.InsertColumn(2, TEXT("路径"), LVCFMT_LEFT, 480);
	m_list_modules.InsertColumn(3, TEXT(""), LVCFMT_LEFT, 20);
}

// 消息映射
BEGIN_MESSAGE_MAP(CMain, CDialogEx)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_PROCESS, &CMain::OnLvnItemchangedListProcess)
	ON_BN_CLICKED(IDC_BUTTON_ABOUT, &CMain::OnBnClickedButtonAbout)
	ON_BN_CLICKED(IDC_BUTTON_QUIT, &CMain::OnBnClickedButtonQuit)
END_MESSAGE_MAP()

// 选中条目改变		遍历模块
void CMain::OnLvnItemchangedListProcess(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// 让其触发一次,过滤
	if (pNMLV->uChanged == LVIF_STATE && pNMLV->uNewState & LVIS_SELECTED) {

		// 先清除所有Items
		m_list_modules.DeleteAllItems();

		int sel_row = m_list_process.GetNextItem(-1, LVNI_SELECTED);				// 获取选中状态的行号
		DWORD dw_pid = _ttoi(m_list_process.GetItemText(sel_row, 1).GetString());	// pid字符转换成数字
		HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS,false, dw_pid);
		if (hprocess == NULL) return;

		// 获取模块总大小
		HMODULE temp = 0;
		DWORD dw_size = 0;
		if (EnumProcessModulesEx(hprocess, &temp, sizeof(HMODULE), &dw_size, LIST_MODULES_ALL) == 0) {
			return;
		}

		// 获取所有模块句柄	必成功
		HMODULE* module_arr = NULL;
		if ((module_arr = new HMODULE[ dw_size / sizeof(HMODULE)] ) == NULL) {
			return;
		}
		EnumProcessModulesEx(hprocess, module_arr, dw_size, &dw_size, LIST_MODULES_ALL);
		
		// 遍历所有模块
		int row_index = 0;
		for (int i = 0; i < (dw_size / sizeof(HMODULE)); i++)
		{
			// 得到基址、大小等信息
			MODULEINFO mo_info{ 0 };
			GetModuleInformation(hprocess, module_arr[i], &mo_info, sizeof(mo_info));

			// 模块路径
			TCHAR file_path[256]{ 0 };
			GetModuleFileNameEx(hprocess, module_arr[i], file_path, 256);

			CString cs_base;
			CString cs_basesize;
			cs_base.Format(TEXT("%p"), mo_info.lpBaseOfDll);
			cs_basesize.Format(TEXT("%08X"), mo_info.SizeOfImage);

			m_list_modules.InsertItem(row_index, cs_base);
			m_list_modules.SetItemText(row_index, 1, cs_basesize);
			m_list_modules.SetItemText(row_index, 2, file_path);
			row_index++;
		}
		delete[] module_arr;
		CloseHandle(hprocess);
	}
	*pResult = 0;
}

// 关于对话框  模态对话框
void CMain::OnBnClickedButtonAbout()
{
	CAbout about_dlg;
	about_dlg.DoModal();
	return;
}

// 退出按钮
void CMain::OnBnClickedButtonQuit()
{
	exit(0);
}