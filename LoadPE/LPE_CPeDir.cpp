// LPE_CPeDir.cpp: 实现文件
//

#include "pch.h"
#include "LPE_CPeDir.h"
#include "LPE_CPeBasic.h"
#include "LPE_CPeExport.h"
#include "LPE_CPeImport.h"
#include "LPE_CPeRelocate.h"
#include "PEtools.h"

// CPeDir 对话框

IMPLEMENT_DYNAMIC(CPeDir, CDialogEx)

CPeDir::CPeDir(CWnd* pParent)
	: CDialogEx(IDD_DIALOG_PE_DIR, pParent)
{
	for (size_t i = 0; i < 15; i++)
	{
		m_rva[i] = TEXT("");
		m_size[i] = TEXT("");
	}
}
CPeDir::~CPeDir()
{

}
//	变量与控件的绑定关系
void CPeDir::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, m_rva[0]);
	DDX_Text(pDX, IDC_EDIT3, m_rva[1]);
	DDX_Text(pDX, IDC_EDIT5, m_rva[2]);
	DDX_Text(pDX, IDC_EDIT7, m_rva[3]);
	DDX_Text(pDX, IDC_EDIT9, m_rva[4]);
	DDX_Text(pDX, IDC_EDIT11, m_rva[5]);
	DDX_Text(pDX, IDC_EDIT13, m_rva[6]);
	DDX_Text(pDX, IDC_EDIT15, m_rva[7]);
	DDX_Text(pDX, IDC_EDIT17, m_rva[8]);
	DDX_Text(pDX, IDC_EDIT19, m_rva[9]);
	DDX_Text(pDX, IDC_EDIT21, m_rva[10]);
	DDX_Text(pDX, IDC_EDIT23, m_rva[11]);
	DDX_Text(pDX, IDC_EDIT25, m_rva[12]);
	DDX_Text(pDX, IDC_EDIT27, m_rva[13]);
	DDX_Text(pDX, IDC_EDIT29, m_rva[14]);

	DDX_Text(pDX, IDC_EDIT2, m_size[0]);
	DDX_Text(pDX, IDC_EDIT4, m_size[1]);
	DDX_Text(pDX, IDC_EDIT6, m_size[2]);
	DDX_Text(pDX, IDC_EDIT8, m_size[3]);
	DDX_Text(pDX, IDC_EDIT10, m_size[4]);
	DDX_Text(pDX, IDC_EDIT12, m_size[5]);
	DDX_Text(pDX, IDC_EDIT14, m_size[6]);
	DDX_Text(pDX, IDC_EDIT16, m_size[7]);
	DDX_Text(pDX, IDC_EDIT18, m_size[8]);
	DDX_Text(pDX, IDC_EDIT20, m_size[9]);
	DDX_Text(pDX, IDC_EDIT22, m_size[10]);
	DDX_Text(pDX, IDC_EDIT24, m_size[11]);
	DDX_Text(pDX, IDC_EDIT26, m_size[12]);
	DDX_Text(pDX, IDC_EDIT28, m_size[13]);
	DDX_Text(pDX, IDC_EDIT30, m_size[14]);
	DDX_Control(pDX, IDC_BUTTON_EXPORT, m_export_but);
	DDX_Control(pDX, IDC_BUTTON_IMPORT, m_import_but);
	DDX_Control(pDX, IDC_BUTTON_RELOCATE, m_relocate_but);
}

//	初始化
BOOL CPeDir::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	//	编辑框去掉选中状态 init最后返回false
	CEdit* pEdit = (CEdit*)GetDlgItem(IDC_EDIT1);
	pEdit->SetFocus();

	PEGet pe(CPeBasic::exe_path.GetString());
	if (!pe.is_success()) return TRUE;

	//	64位因为可选pe头中的一些字段，由四字节变成了八字节，导致DataDirectory后移了，所以区分
	//	PEtool用的是泛型的PIMAGE_OPTIONAL_HEADER，由编译环境决定可选头
	if (pe.is_32PE()) {
		PIMAGE_OPTIONAL_HEADER32 poption32 = (PIMAGE_OPTIONAL_HEADER32)pe.poption_header;
		for (int i = 0; i < 15; i++)
		{
			m_rva[i].Format(TEXT("%08X"), poption32->DataDirectory[i].VirtualAddress);
			m_size[i].Format(TEXT("%08X"), poption32->DataDirectory[i].Size);
		}
	}
	else{
		PIMAGE_OPTIONAL_HEADER64 poption64 = (PIMAGE_OPTIONAL_HEADER64)pe.poption_header;
		for (int i = 0; i < 15; i++)
		{
			m_rva[i].Format(TEXT("%08X"), poption64->DataDirectory[i].VirtualAddress);
			m_size[i].Format(TEXT("%08X"), poption64->DataDirectory[i].Size);
		}
	}
	UpdateData(false);

	//	初始化按钮是否可用
	InitButtonState();
	return false;
}

void CPeDir::InitButtonState()
{
	CString cmpstr = TEXT("00000000");
	if (cmpstr == m_rva[0] || m_rva[0].IsEmpty()) {
		m_export_but.EnableWindow(false);
	}
	if (cmpstr == m_rva[1] || m_rva[0].IsEmpty()) {
		m_import_but.EnableWindow(false);
	}
	if (cmpstr == m_rva[5] || m_rva[0].IsEmpty()) {
		m_relocate_but.EnableWindow(false);
	}
}
BEGIN_MESSAGE_MAP(CPeDir, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON1, &CPeDir::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON5, &CPeDir::OnBnClickedButton5)
	ON_BN_CLICKED(IDC_BUTTON_EXPORT, &CPeDir::OnBnClickedButtonExport)
	ON_BN_CLICKED(IDC_BUTTON_IMPORT, &CPeDir::OnBnClickedButtonImport)
	ON_BN_CLICKED(IDC_BUTTON_RELOCATE, &CPeDir::OnBnClickedButtonRelocate)
END_MESSAGE_MAP()

// CPeDir 消息处理程序


//	确定按钮
void CPeDir::OnBnClickedButton1()
{
	CDialogEx::OnOK();
}

//	退出按钮
void CPeDir::OnBnClickedButton5()
{
	CDialogEx::OnOK();
}

//	导出表更多按钮
void CPeDir::OnBnClickedButtonExport()
{
	CPeExport pe_export;
	pe_export.DoModal();
}

//	导入表更多按钮
void CPeDir::OnBnClickedButtonImport()
{
	CPeImport pe_import;
	pe_import.DoModal();
}

//	重定位表更多按钮
void CPeDir::OnBnClickedButtonRelocate()
{
	CPeRelocate pe_relocate;
	pe_relocate.DoModal();
}
