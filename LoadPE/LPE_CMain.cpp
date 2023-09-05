// LPE_CMain.cpp: 实现文件
//
#include "pch.h"
#include <TlHelp32.h>
#include <psapi.h>
#include "LPE_CMain.h"
#include "LPE_CAbout.h"
#include "LPE_Inject.h"
#include "LPE_CInPack.h"
#include "LPE_CPeBasic.h"

// CMain 对话框
IMPLEMENT_DYNAMIC(CMain, CDialogEx)

CMain::CMain(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_MAIN, pParent)
{

}

CMain::~CMain()
{

}

// 私有方法：遍历进程设置到控件上
void CMain::EnumProcessToSetList()
{
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
			int path_size = 256;
			HANDLE hprocess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pro_entry.th32ProcessID);

			// 两种方法,都是根据PID获取完全路径 注释的是从device开始
			// int ret = QueryFullProcessImageName(hprocess, 1, path, &path_size);
			int ret = GetModuleFileNameExA(hprocess, NULL, buff, path_size);		   // NULL表示exe文件
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

// 私有方法：遍历模块设置到控件上
void CMain::EnumMuduleToSetList(HANDLE hprocess)
{
	// 获取模块总大小
	HMODULE temp = 0;
	DWORD dw_size = 0;
	if (EnumProcessModulesEx(hprocess, &temp, sizeof(HMODULE), &dw_size, LIST_MODULES_DEFAULT) == 0) {
		return;
	}

	// 获取所有模块句柄	必成功
	HMODULE* module_arr = NULL;
	if ((module_arr = new HMODULE[dw_size / sizeof(HMODULE)]) == NULL) {
		return;
	}
	EnumProcessModulesEx(hprocess, module_arr, dw_size, &dw_size, LIST_MODULES_DEFAULT);

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
	//	设置程序小图标
	SetIcon(AfxGetApp()->LoadIcon(IDI_ICON1), true);

	// 设置list view小图标
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

	// 遍历
	this->EnumProcessToSetList();
}

// 初始化列表控件		第二个列表控件标题
void CMain::InitListView2()
{
	// 风格
	int style = m_list_modules.GetExtendedStyle();
	m_list_modules.SetExtendedStyle(style | LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

	// 四列
	m_list_modules.InsertColumn(0, TEXT("基址"), LVCFMT_LEFT, 125);
	m_list_modules.InsertColumn(1, TEXT("大小"), LVCFMT_LEFT, 95);
	m_list_modules.InsertColumn(2, TEXT("路径"), LVCFMT_LEFT, 480);
	m_list_modules.InsertColumn(3, TEXT(""), LVCFMT_LEFT, 20);
}

// 消息映射
BEGIN_MESSAGE_MAP(CMain, CDialogEx)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_PROCESS, &CMain::OnLvnItemchangedListProcess)
	ON_BN_CLICKED(IDC_BUTTON_ABOUT, &CMain::OnBnClickedButtonAbout)
	ON_BN_CLICKED(IDC_BUTTON_QUIT, &CMain::OnBnClickedButtonQuit)
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_BUTTON_INDLL, &CMain::OnBnClickedButtonIndll)
	ON_BN_CLICKED(IDC_BUTTON_UNDLL, &CMain::OnBnClickedButtonUndll)
	ON_BN_CLICKED(IDC_BUTTON_INPACK, &CMain::OnBnClickedButtonInpack)
	ON_BN_CLICKED(IDC_BUTTON_PE, &CMain::OnBnClickedButtonPe)
	ON_BN_CLICKED(IDC_BUTTON_REFRESH, &CMain::OnBnClickedButtonRefresh)
	ON_BN_CLICKED(IDC_BUTTON_REFRESH2, &CMain::OnBnClickedButtonRefresh2)
END_MESSAGE_MAP()

// 选中条目改变		遍历模块
void CMain::OnLvnItemchangedListProcess(NMHDR* pNMHDR, LRESULT* pResult)
{
	//	选中一次触发一次
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	if (pNMLV->uChanged != LVIF_STATE || (pNMLV->uNewState & LVIS_SELECTED) != LVIS_SELECTED) {
		return;
	}

	// 先清除所有Items
	m_list_modules.DeleteAllItems();

	int sel_row = m_list_process.GetNextItem(-1, LVNI_SELECTED);						// 获取选中状态的行号
	unsigned int dw_pid = _ttoi(m_list_process.GetItemText(sel_row, 1).GetString());	// pid字符转换成数字
	HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, false, dw_pid);
	if (hprocess == NULL) return;

	// 遍历
	this->EnumMuduleToSetList(hprocess);

	*pResult = 0;
}

// 关于对话框  模态对话框
void CMain::OnBnClickedButtonAbout()
{
	CAbout about_dlg(this);
	about_dlg.DoModal();
	return;
}

// 退出按钮
void CMain::OnBnClickedButtonQuit()
{
	exit(0);
}

// 创建PE查看器对话框
void CMain::Init_PEDlg()
{
	//	模态对话框
	CPeBasic pe_basic(this);
	pe_basic.DoModal();
}

// PE查看器按钮
void CMain::OnBnClickedButtonPe()
{
	TCHAR szFilter[] = TEXT("可执行文件(*.exe;*sys;*dll)|*.exe;*.sys;*.dll|所有文件(*.*)|*.*||");
	CFileDialog file_browser(TRUE, TEXT(".exe"), NULL, 0, szFilter, this);
	if (file_browser.DoModal() != IDOK) return;

	//	CPeBasic的静态变量  ->  pe文件路径
	CPeBasic::exe_path = file_browser.GetPathName();
	Init_PEDlg();
}

// 文件拖拽触发
void CMain::OnDropFiles(HDROP hDropInfo)
{
	TCHAR szFilename[256]{ 0 };
	DragQueryFile(hDropInfo, 0, szFilename, 254);

	//	CPeBasic的静态变量  ->  pe文件路径
	CPeBasic::exe_path = szFilename;
	CDialogEx::OnDropFiles(hDropInfo);
	Init_PEDlg();
}

// 注入dll按钮
void CMain::OnBnClickedButtonIndll()
{
	//	得到选中进程的PID
	int sel_row = -1;
	sel_row = m_list_process.GetNextItem(-1, LVNI_SELECTED);
	int pid = _ttoi(m_list_process.GetItemText(sel_row, 1).GetString());
	if (sel_row == -1) return;

	//	要注入的dll路径
	TCHAR szFilter[] = TEXT("动态链接库(*dll)|*.dll||");
	CFileDialog file_browser(TRUE, TEXT(".dll"), NULL, 0, szFilter, this);
	if (file_browser.DoModal() != IDOK) return;
	CString dll_path = file_browser.GetPathName();

	//	注入->远程线程注入
	CString info;
	HMODULE hModule = RmThread_Inject(pid, dll_path.GetString());
	if (hModule != 0) {
		info.Format(TEXT(" %s \n 基址: %p \n 路径: "), "注入成功", hModule);
		info.Append(dll_path);
		MessageBox(info, 0, MB_ICONINFORMATION);
	}
	else {
		info.Format(TEXT("注入失败\n%s\n%s"), "1.当前注入器无权限", "2.dll与进程字长不一致");
		MessageBox(info, 0, MB_ICONWARNING);
	}
}

// 卸载dll按钮
void CMain::OnBnClickedButtonUndll()
{
	//	得到选中进程的PID
	int sel_row = -1;
	sel_row = m_list_process.GetNextItem(-1, LVNI_SELECTED);
	int pid = _ttoi(m_list_process.GetItemText(sel_row, 1).GetString());
	if (sel_row == -1) return;

	//	得到选中模块的基址
	sel_row = m_list_modules.GetNextItem(-1, LVNI_SELECTED);
	HMODULE dllModule = 0;
	int ret = sscanf_s(m_list_modules.GetItemText(sel_row, 0).GetString(), "%p", &dllModule);
	if (sel_row == -1 || ret == 0) return;

	//	卸载注入 -> FreeLibrary 模块句柄就是基址
	if (RmThread_Unject(pid, dllModule)) {

		MessageBox(TEXT("选中的dll被卸载成功"), 0, MB_ICONINFORMATION);
	}
	else {
		MessageBox(TEXT("卸载失败"), 0, MB_ICONINFORMATION);
	}
}

// 加壳按钮 
void CMain::OnBnClickedButtonInpack()
{
	CInPack inPack(NULL);
	inPack.DoModal();
}

// 刷新进程
void CMain::OnBnClickedButtonRefresh()
{
	m_list_modules.DeleteAllItems();
	m_list_process.DeleteAllItems();
	EnumProcessToSetList();
}

// 刷新模块
void CMain::OnBnClickedButtonRefresh2()
{
	m_list_modules.DeleteAllItems();

	int sel_row = m_list_process.GetNextItem(-1, LVNI_SELECTED);						// 获取选中状态的行号
	unsigned int dw_pid = _ttoi(m_list_process.GetItemText(sel_row, 1).GetString());	// pid字符转换成数字
	HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, false, dw_pid);
	if (hprocess == NULL) return;

	// 遍历
	this->EnumMuduleToSetList(hprocess);
}
