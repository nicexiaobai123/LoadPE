// LPE_CPeSec.cpp: 实现文件
//
#include "pch.h"
#include "LPE_CPeSec.h"
#include "LPE_CPeBasic.h"
#include "PEtools.h"

IMPLEMENT_DYNAMIC(CPeSec, CDialogEx)

CPeSec::CPeSec(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_PE_SEC, pParent)
{

}

CPeSec::~CPeSec()
{
}

void CPeSec::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_seclist);
}

void CPeSec::InitList()
{
	PEGet pe(CPeBasic::exe_path.GetString());
	if (pe.is_success() == false) return;

	//	节表信息初始化到ListView上
	CString temp;
	PIMAGE_SECTION_HEADER psec = pe.pfirst_section_header;
	for (int i = 0; i < pe.pfile_header->NumberOfSections; i++)
	{
		char name[8]{ 0 };
		memcpy(name, (char*)psec[i].Name, 7);
		m_seclist.InsertItem(i, name);

		temp.Empty();
		temp.Format("%08X", psec[i].VirtualAddress);
		m_seclist.SetItemText(i, 1, temp);

		temp.Empty();
		temp.Format("%08X", psec[i].Misc.VirtualSize);
		m_seclist.SetItemText(i, 2, temp);

		temp.Empty();
		temp.Format("%08X", psec[i].PointerToRawData);
		m_seclist.SetItemText(i, 3, temp);

		temp.Empty();
		temp.Format("%08X", psec[i].SizeOfRawData);
		m_seclist.SetItemText(i, 4, temp);

		temp.Empty();
		temp.Format("%08X", psec[i].Characteristics);
		m_seclist.SetItemText(i, 5, temp);
	}
}

BOOL CPeSec::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	int style = m_seclist.GetExtendedStyle();
	m_seclist.SetExtendedStyle(style | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	m_seclist.InsertColumn(0, TEXT("名称"), LVCFMT_LEFT, 70);
	m_seclist.InsertColumn(1, TEXT("VirtualAddress"), LVCFMT_LEFT, 100);
	m_seclist.InsertColumn(2, TEXT("VirtualSize"), LVCFMT_LEFT, 80);
	m_seclist.InsertColumn(3, TEXT("PointerToRawData"), LVCFMT_LEFT, 120);
	m_seclist.InsertColumn(4, TEXT("SizeOfRawData"), LVCFMT_LEFT, 100);
	m_seclist.InsertColumn(5, TEXT("标志"), LVCFMT_LEFT, 80);

	// PE节表内容初始化到list上
	InitList();

	return TRUE;
}

BEGIN_MESSAGE_MAP(CPeSec, CDialogEx)
END_MESSAGE_MAP()

// CPeSec 消息处理程序