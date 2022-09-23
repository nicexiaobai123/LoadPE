// LPE_CPeRelocate.cpp: 实现文件
//

#include "pch.h"
#include "LPE_CPeRelocate.h"
#include "LPE_CPeBasic.h"
#include "PEtools.h"


// CPeRelocate 对话框

IMPLEMENT_DYNAMIC(CPeRelocate, CDialogEx)

CPeRelocate::CPeRelocate(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_PE_RELOCATE, pParent)
{

}

CPeRelocate::~CPeRelocate()
{
}

void CPeRelocate::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_SEC, m_list_sec);
	DDX_Control(pDX, IDC_LIST_BLOCK, m_list_block);
}

//	初始化
BOOL CPeRelocate::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	//	区段
	int style = m_list_sec.GetExtendedStyle();
	m_list_sec.SetExtendedStyle(style | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_list_sec.InsertColumn(0, TEXT("索引"), LVCFMT_LEFT, 80);
	m_list_sec.InsertColumn(1, TEXT("区段"), LVCFMT_LEFT, 150);
	m_list_sec.InsertColumn(2, TEXT("RVA"), LVCFMT_LEFT, 150);
	m_list_sec.InsertColumn(3, TEXT("项目个数"), LVCFMT_LEFT, 100);

	//	块
	m_list_block.SetExtendedStyle(style | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_list_block.InsertColumn(0, TEXT("索引"), LVCFMT_LEFT, 80);
	m_list_block.InsertColumn(1, TEXT("RVA"), LVCFMT_LEFT, 100);
	m_list_block.InsertColumn(2, TEXT("偏移"), LVCFMT_LEFT, 100);
	m_list_block.InsertColumn(3, TEXT("类型"), LVCFMT_LEFT, 80);
	m_list_block.InsertColumn(4, TEXT("FAR地址"), LVCFMT_LEFT, 140);

	InitSecList();
	return TRUE;
}

// 初始化sec_lsit的内容
void CPeRelocate::InitSecList()
{
	PEGet pe(CPeBasic::exe_path.GetString());
	if (!pe.is_success()) return;

	//	得到foa 和 bufferbase
	DWORD_PTR base = (DWORD_PTR)pe.pdos_header;
	DWORD RelocateFoa = 0;
	if (pe.is_32PE()) {
		PIMAGE_OPTIONAL_HEADER32 pop32 = (PIMAGE_OPTIONAL_HEADER32)pe.poption_header;
		RelocateFoa = pe.rva_to_foa(pop32->DataDirectory[5].VirtualAddress);
	}
	else {
		PIMAGE_OPTIONAL_HEADER64 pop64 = (PIMAGE_OPTIONAL_HEADER64)pe.poption_header;
		RelocateFoa = pe.rva_to_foa(pop64->DataDirectory[5].VirtualAddress);
	}

	//	得加一个异常处理，在每次最后看地址是否会发生无效访问，可以使用ReadProcessMemory间接判断
	//	有些应用程序重定位表最后没全0结构
	int row = 0;
	int index = 1;
	PIMAGE_BASE_RELOCATION pRelovate = (PIMAGE_BASE_RELOCATION)(base + RelocateFoa);
	while (pRelovate->SizeOfBlock != 0 && pRelovate->VirtualAddress != 0)
	{
		DWORD virRva = pRelovate->VirtualAddress;
		DWORD blockNum = (pRelovate->SizeOfBlock - 8) / 2;

		CString toCStr;
		CString secName(pe.get_secname_byrva(virRva).c_str());

		toCStr.Empty();
		toCStr.Format(TEXT("%d"), index);
		m_list_sec.InsertItem(row, toCStr);

		m_list_sec.SetItemText(row, 1, secName);

		toCStr.Empty();
		toCStr.Format(TEXT("%08X"), virRva);
		m_list_sec.SetItemText(row, 2, toCStr);

		toCStr.Empty();
		toCStr.Format(TEXT("%d"), blockNum);
		m_list_sec.SetItemText(row, 3, toCStr);

		row++;
		index++;
		pRelovate = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pRelovate + pRelovate->SizeOfBlock);

		//	判断地址为无效
		if (PEGet::JudgeMemValid(pRelovate)) {
			AfxMessageBox("访问内存发生错误");
			EndDialog(0);
			return;
		}
	}
}


BEGIN_MESSAGE_MAP(CPeRelocate, CDialogEx)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_SEC, &CPeRelocate::OnLvnItemchangedListSec)
END_MESSAGE_MAP()


// CPeRelocate 消息处理程序

//	选中条目
void CPeRelocate::OnLvnItemchangedListSec(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	if (pNMLV->uChanged != LVIF_STATE || (pNMLV->uNewState & LVIS_SELECTED) != LVIS_SELECTED) {
		return;
	}
	//先删除所有项
	m_list_block.DeleteAllItems();	

	//	得到 索引、起始vir、大小
	int selRow = -1;
	DWORD index = 0;
	DWORD ViraddrRva = 0;
	DWORD blockSize = 0;
	selRow = m_list_sec.GetNextItem(-1, LVNI_SELECTED);
	if (selRow != -1) {
		CString cindex = m_list_sec.GetItemText(selRow, 0);
		CString cRva = m_list_sec.GetItemText(selRow, 2);
		CString cSize = m_list_sec.GetItemText(selRow, 3);
		sscanf_s(cindex.GetString(), "%d", &index);
		sscanf_s(cRva.GetString(), "%x", &ViraddrRva);
		sscanf_s(cSize.GetString(), "%d", &blockSize);
	}

	//	初始化
	InitListSec(index, ViraddrRva, blockSize);
	*pResult = 0;
}

void CPeRelocate::InitListSec(DWORD index,DWORD ViraddrRva, DWORD blockSize)
{
	PEGet pe(CPeBasic::exe_path.GetString());
	if (!pe.is_success()) return;

	//	遍历重定位块项
	DWORD_PTR base = (DWORD_PTR)pe.pdos_header;
	PIMAGE_BASE_RELOCATION p_relocate = NULL;
	if (pe.is_32PE()) {
		PIMAGE_OPTIONAL_HEADER32 pop32 = (PIMAGE_OPTIONAL_HEADER32)pe.poption_header;
		p_relocate = (PIMAGE_BASE_RELOCATION)(base + pe.rva_to_foa(pop32->DataDirectory[5].VirtualAddress));
	}
	else {
		PIMAGE_OPTIONAL_HEADER64 pop64 = (PIMAGE_OPTIONAL_HEADER64)pe.poption_header;
		p_relocate = (PIMAGE_BASE_RELOCATION)(base + pe.rva_to_foa(pop64->DataDirectory[5].VirtualAddress));
	}

	//	定位到重定位块
	while (--index)
	{
		p_relocate = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)p_relocate + p_relocate->SizeOfBlock);
	}

	short* dataPos = (short*)((DWORD_PTR)p_relocate + 8);
	CString toStr;
	for (int i = 0; i < blockSize; i++)
	{
		DWORD rva = ViraddrRva + (dataPos[i] & 0xFFF);
		DWORD foa = pe.rva_to_foa(ViraddrRva + (dataPos[i] & 0xFFF));

		toStr.Empty();
		toStr.Format(TEXT("%d"), i + 1);
		m_list_block.InsertItem(i, toStr);

		toStr.Empty();
		toStr.Format(TEXT("%08X"), rva);
		m_list_block.SetItemText(i, 1, toStr);

		toStr.Empty();
		toStr.Format(TEXT("%08X"), foa);
		m_list_block.SetItemText(i, 2, toStr);
		
		//	IMAGE_REL_BASED_HIGHLOW		IMAGE_REL_BASED_DIR64
		if ((dataPos[i] & 0x3000) == 0x3000 || (dataPos[i] & 0xa000) == 0xa000) {
			if (pe.is_32PE()) {
				toStr.Empty();
				toStr.Format(TEXT("%s"), "HIGHLOW (3)");
				m_list_block.SetItemText(i, 3, toStr);

				toStr.Empty();
				toStr.Format(TEXT("%08X"), *(ULONG*)(base + foa));
				m_list_block.SetItemText(i, 4, toStr);
			}
			else {
				toStr.Empty();
				toStr.Format(TEXT("%s"), "DIR64 (10)");
				m_list_block.SetItemText(i, 3, toStr);

				toStr.Empty();
				toStr.Format(TEXT("%016llx"), *(ULONGLONG*)(base + foa));
				m_list_block.SetItemText(i, 4, toStr);
			}
		}
		else {
			toStr.Empty();
			toStr.Format(TEXT("%s"), "--");
			m_list_block.SetItemText(i, 3, toStr);
			m_list_block.SetItemText(i, 4, toStr);
		}
	}
}