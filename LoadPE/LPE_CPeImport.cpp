// LPE_CPeImport.cpp: 实现文件
//

#include "pch.h"
#include "LPE_CPeImport.h"
#include "PEtools.h"


// CPeImport 对话框

IMPLEMENT_DYNAMIC(CPeImport, CDialogEx)

CPeImport::CPeImport(CWnd* pParent)
	: CDialogEx(IDD_DIALOG_PE_IMPORT, pParent)
{

}

CPeImport::~CPeImport()
{
}

void CPeImport::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list_dll);
	DDX_Control(pDX, IDC_LIST2, m_list_func);
}

//	初始化
BOOL CPeImport::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	//	list_dll标题
	int style = m_list_dll.GetExtendedStyle();
	m_list_dll.SetExtendedStyle(style | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_list_dll.InsertColumn(0, TEXT("DLL名称"), LVCFMT_LEFT, 180);
	m_list_dll.InsertColumn(1, TEXT("DLL名称 RVA"), LVCFMT_LEFT, 120);
	m_list_dll.InsertColumn(2, TEXT("Original Thunk"), LVCFMT_LEFT, 120);
	m_list_dll.InsertColumn(3, TEXT("First Thunk"), LVCFMT_LEFT, 120);

	//	func_dll标题
	m_list_func.SetExtendedStyle(style | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_list_func.InsertColumn(0, TEXT("Thunk_DATA RVA"), LVCFMT_LEFT, 120);
	m_list_func.InsertColumn(1, TEXT("Thunk_DATA FOA"), LVCFMT_LEFT, 120);
	m_list_func.InsertColumn(2, TEXT("Thunk_DATA 值"), LVCFMT_LEFT, 120);
	m_list_func.InsertColumn(3, TEXT("API名称"), LVCFMT_LEFT, 175);

	InitDllList();
	return TRUE;
}

//	初始化dll lsit
void CPeImport::InitDllList()
{
	PEGet pe(CPeBasic::exe_path.GetString());
	if (!pe.is_success()) return;

	//	得到foa 和 bufferbase
	DWORD_PTR base = (DWORD_PTR)pe.pdos_header;
	DWORD ImportFoa = 0;
	if (pe.is_32PE()) {
		PIMAGE_OPTIONAL_HEADER32 pop32 = (PIMAGE_OPTIONAL_HEADER32)pe.poption_header;
		ImportFoa = pe.rva_to_foa(pop32->DataDirectory[1].VirtualAddress);
	}
	else {
		PIMAGE_OPTIONAL_HEADER64 pop64 = (PIMAGE_OPTIONAL_HEADER64)pe.poption_header;
		ImportFoa = pe.rva_to_foa(pop64->DataDirectory[1].VirtualAddress);
	}

	//	导入表遍历
	int i = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(base + ImportFoa);
	while (pImport[i].Name != 0)
	{
		CString dll_name((char*)(base + pe.rva_to_foa(pImport[i].Name)));
		m_list_dll.InsertItem(i, dll_name);

		CString toStr;
		toStr.Format(TEXT("%08X"), pImport[i].Name);
		m_list_dll.SetItemText(i, 1, toStr);

		toStr.Empty();
		toStr.Format(TEXT("%08X"), pImport[i].OriginalFirstThunk);
		m_list_dll.SetItemText(i, 2, toStr);

		toStr.Empty();
		toStr.Format(TEXT("%08X"), pImport[i].FirstThunk);
		m_list_dll.SetItemText(i, 3, toStr);

		i++;

		//	判断地址为无效
		if (PEGet::JudgeMemValid(&pImport[i])) {
			AfxMessageBox("访问内存发生错误");
			EndDialog(0);
			return;
		}
	}
}

//	初始化func lsit
void CPeImport::InitFuncList(DWORD firstThunkRva)
{
	PEGet pe(CPeBasic::exe_path.GetString());
	if (!pe.is_success()) return;

	//	PIMAGE_THUNK_DATA区分编译环境,编译环境是64位则占八字节
	int row = 0;
	CString toStr;
	DWORD_PTR base = (DWORD_PTR)pe.pdos_header;
	DWORD thunkFoa = pe.rva_to_foa(firstThunkRva);

	//	导入表解析需要判断PE文件是否是PE+
	if (pe.is_32PE())
	{
		PIMAGE_THUNK_DATA32 pImgThunk32 = (PIMAGE_THUNK_DATA32)(base + thunkFoa);
		while (pImgThunk32->u1.Function != 0)
		{
			DWORD tkFoa = (DWORD_PTR)pImgThunk32 - base;
			DWORD tkRva = pe.foa_to_rva(tkFoa);

			//	每个IMAGE_THUNK_DATA 的 Rva
			toStr.Empty();
			toStr.Format(TEXT("%08X"), tkRva);
			m_list_func.InsertItem(row, toStr);

			//	每个IMAGE_THUNK_DATA 的 Foa
			toStr.Empty();
			toStr.Format(TEXT("%08X"), tkFoa);
			m_list_func.SetItemText(row, 1, toStr);

			//	每个IMAGE_THUNK_DATA的实际指向值,最高位不为1则是指向名称(BY_NAME)的RVA
			toStr.Empty();
			toStr.Format(TEXT("%08X"), pImgThunk32->u1.Function);
			m_list_func.SetItemText(row, 2, toStr);

			//	函数名称或者序号,最高位不为1按名称导入
			if (!IMAGE_SNAP_BY_ORDINAL32(pImgThunk32->u1.Function))
			{
				PIMAGE_IMPORT_BY_NAME byName = (PIMAGE_IMPORT_BY_NAME)(base + pe.rva_to_foa(pImgThunk32->u1.Function));
				toStr.Empty();
				toStr = byName->Name;
				m_list_func.SetItemText(row, 3, toStr);
			}
			else
			{
				DWORD order = (pImgThunk32->u1.Function & ~IMAGE_ORDINAL_FLAG32);
				toStr.Empty();
				toStr.Format(TEXT("是序号: %08X"), order);
				m_list_func.SetItemText(row, 3, toStr);
			}
			pImgThunk32++;
		}
	}
	else
	{
		PIMAGE_THUNK_DATA64 pImgThunk64 = (PIMAGE_THUNK_DATA64)(base + thunkFoa);
		while (pImgThunk64->u1.Function != 0)
		{
			DWORD tkFoa = (DWORD_PTR)pImgThunk64 - base;
			DWORD tkRva = pe.foa_to_rva(tkFoa);

			//	每个IMAGE_THUNK_DATA 的 Rva
			toStr.Empty();
			toStr.Format(TEXT("%08X"), tkRva);
			m_list_func.InsertItem(row, toStr);

			//	每个IMAGE_THUNK_DATA 的 Foa
			toStr.Empty();
			toStr.Format(TEXT("%08X"), tkFoa);
			m_list_func.SetItemText(row, 1, toStr);

			//	每个IMAGE_THUNK_DATA的实际指向值,最高位不为1则是指向名称(BY_NAME)的RVA
			toStr.Empty();
			toStr.Format(TEXT("%p"), (LPVOID)pImgThunk64->u1.Function);
			m_list_func.SetItemText(row, 2, toStr);

			//	函数名称或者序号,最高位不为1按名称导入
			if (!IMAGE_SNAP_BY_ORDINAL64(pImgThunk64->u1.Function))
			{
				PIMAGE_IMPORT_BY_NAME byName = (PIMAGE_IMPORT_BY_NAME)(base + pe.rva_to_foa(pImgThunk64->u1.Function));
				toStr.Empty();
				toStr = byName->Name;
				m_list_func.SetItemText(row, 3, toStr);
			}
			else
			{
				DWORD order = (pImgThunk64->u1.Function & ~IMAGE_ORDINAL_FLAG64);
				toStr.Empty();
				toStr.Format(TEXT("是序号: %08X"), order);
				m_list_func.SetItemText(row, 3, toStr);
			}
			pImgThunk64++;
		}
	}
}


BEGIN_MESSAGE_MAP(CPeImport, CDialogEx)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CPeImport::OnLvnItemchangedList1)
END_MESSAGE_MAP()


// CPeImport 消息处理程序

//	dll list的某一行被选中,导入表详细信息
void CPeImport::OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	//	选中一次触发一次
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	if (pNMLV->uChanged != LVIF_STATE || (pNMLV->uNewState & LVIS_SELECTED) != LVIS_SELECTED) {
		return;
	}

	//	得到 FirstThunk 和 OriginalThunk
	int selRow = -1;
	DWORD firstThunk = 0;
	DWORD OriginalThunk = 0;
	selRow = m_list_dll.GetNextItem(-1, LVNI_SELECTED);
	if (selRow != -1) {
		CString coThunk = m_list_dll.GetItemText(selRow, 2);
		CString cfThunk = m_list_dll.GetItemText(selRow, 3);
		sscanf_s(coThunk.GetString(), "%x", &OriginalThunk);
		sscanf_s(cfThunk.GetString(), "%x", &firstThunk);
	}

	//	遍历每个导入表详细内容,优先使用OriginalThunk遍历,除非没有OriginalThunk
	m_list_func.DeleteAllItems();	//先删除所有项
	if (OriginalThunk != 0) {
		InitFuncList(OriginalThunk);
	}
	else {
		InitFuncList(firstThunk);
	}
	*pResult = 0;
}