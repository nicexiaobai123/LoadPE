// LPE_CPeExport.cpp: 实现文件
//
#include "pch.h"
#include "LPE_CPeExport.h"
#include "LPE_CPeBasic.h"
#include "PEtools.h"

// CPeExport 对话框

IMPLEMENT_DYNAMIC(CPeExport, CDialogEx)

CPeExport::CPeExport(CWnd* pParent)
	: CDialogEx(IDD_DIALOG_PE_EXPORT, pParent)
	, m_func_num(_T(""))
	, m_name_num(_T(""))
	, m_file_name(_T(""))
	, m_addr_rva(_T(""))
	, m_name_rva(_T(""))
	, m_order_rva(_T(""))
	, m_begin_num(_T(""))
{

}

CPeExport::~CPeExport()
{
}

void CPeExport::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, m_func_num);
	DDX_Text(pDX, IDC_EDIT2, m_name_num);
	DDX_Text(pDX, IDC_EDIT3, m_file_name);
	DDX_Text(pDX, IDC_EDIT4, m_addr_rva);
	DDX_Text(pDX, IDC_EDIT5, m_name_rva);
	DDX_Text(pDX, IDC_EDIT6, m_order_rva);
	DDX_Control(pDX, IDC_LIST1, m_info);
	DDX_Text(pDX, IDC_EDIT7, m_begin_num);
}

//	初始化
BOOL CPeExport::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	PEGet pe(CPeBasic::exe_path.GetString());
	if (!pe.is_success()) return TRUE;

	//	去掉编辑框选中
	CEdit* pEdit = (CEdit*)GetDlgItem(IDC_EDIT1);
	pEdit->SetFocus();

	//	根据PE文件位数得到rva
	DWORD ex_foa;
	if (pe.is_32PE()) {
		PIMAGE_OPTIONAL_HEADER32 poption = (PIMAGE_OPTIONAL_HEADER32)pe.poption_header;
		ex_foa = pe.rva_to_foa(poption->DataDirectory[0].VirtualAddress);
	}
	else{
		PIMAGE_OPTIONAL_HEADER64 poption = (PIMAGE_OPTIONAL_HEADER64)pe.poption_header;
		ex_foa = pe.rva_to_foa(poption->DataDirectory[0].VirtualAddress);
	}

	//	pe文件名
	DWORD_PTR base = (DWORD_PTR)pe.pdos_header;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(base + ex_foa);
	CString file_name((char*)(base + pe.rva_to_foa(pExport->Name)));
	m_file_name = file_name;

	//	导入表其他属性
	m_begin_num.Format(TEXT("%08X"), pExport->Base);
	m_addr_rva.Format(TEXT("%08X"), pExport->AddressOfFunctions);
	m_name_rva.Format(TEXT("%08X"), pExport->AddressOfNames);
	m_order_rva.Format(TEXT("%08X"), pExport->AddressOfNameOrdinals);
	m_name_num.Format(TEXT("%08X"), pExport->NumberOfNames);
	m_func_num.Format(TEXT("%08X"), pExport->NumberOfFunctions);

	//	list view
	int style = m_info.GetExtendedStyle();
	m_info.SetExtendedStyle(style | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_info.InsertColumn(0, TEXT("导出名称"), LVCFMT_LEFT, 180);
	m_info.InsertColumn(1, TEXT("序号"), LVCFMT_LEFT, 90);
	m_info.InsertColumn(2, TEXT("RVA"), LVCFMT_LEFT, 90);
	m_info.InsertColumn(3, TEXT("FOA"), LVCFMT_LEFT, 95);

	//	导出表遍历,所有有名字的
	CString toStr;
	PDWORD pFunctions = (PDWORD)(base + pe.rva_to_foa(pExport->AddressOfFunctions));
	PDWORD pNameRva = (PDWORD)(base + pe.rva_to_foa(pExport->AddressOfNames));
	PWORD pOrder = (PWORD)(base + pe.rva_to_foa(pExport->AddressOfNameOrdinals));
	for (int i = 0; i < pExport->NumberOfNames; i++)
	{
		// 导出名称
		toStr.Empty();
		toStr.Format(TEXT("%s"), (const char*)(base + pe.rva_to_foa(pNameRva[i])));
		m_info.InsertItem(i, toStr);
		
		// 导出序号
		toStr.Empty();
		toStr.Format(TEXT("%04X"), pOrder[i] + pExport->Base);
		m_info.SetItemText(i, 1, toStr);
	
		// 导出地址rva
		toStr.Empty();
		toStr.Format(TEXT("%08X"), pFunctions[pOrder[i]]);
		m_info.SetItemText(i, 2,toStr);

		// 导出地址foa
		toStr.Empty();
		toStr.Format(TEXT("%08X"), pe.rva_to_foa(pFunctions[pOrder[i]]));
		m_info.SetItemText(i, 3, toStr);
	}
	UpdateData(false);
	return false;
}


BEGIN_MESSAGE_MAP(CPeExport, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON1, &CPeExport::OnBnClickedButton1)
END_MESSAGE_MAP()


// CPeExport 消息处理程序

//	确定按钮
void CPeExport::OnBnClickedButton1()
{
	CDialogEx::OnOK();
}
