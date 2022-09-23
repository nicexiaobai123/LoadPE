#include "pch.h"
#include "LPE_CPeBasic.h"
#include "LPE_CPeDir.h"
#include "LPE_CPeSec.h"
#include "PEtools.h"

// CPeBasic 对话框
IMPLEMENT_DYNAMIC(CPeBasic, CDialogEx)
CPeBasic::CPeBasic(CWnd* pParent )
	: CDialogEx(IDD_DIALOG_PE_MAIN, pParent)
	, m_oep(_T(""))
	, m_imagebase(_T(""))
	, m_imagesize(_T(""))
	, m_codebase(_T(""))
	, m_database(_T(""))
	, m_secalg(_T(""))
	, m_filealg(_T(""))
	, m_magic(_T(""))
	, m_subsystem(_T(""))
	, m_secnum(_T(""))
	, m_timestamp(_T(""))
	, m_chara(_T(""))
	, m_checksum(_T(""))
	, m_optionsize(_T(""))
	, m_sizeofheaders(_T(""))
	, m_dllchara(_T(""))
{
}
CPeBasic::~CPeBasic()
{
}

//	类的静态变量初始化
CString CPeBasic::exe_path;

//	变量与控件的绑定关系
void CPeBasic::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT0, m_oep);
	DDX_Text(pDX, IDC_EDIT1, m_imagebase);
	DDX_Text(pDX, IDC_EDIT2, m_imagesize);
	DDX_Text(pDX, IDC_EDIT3, m_codebase);
	DDX_Text(pDX, IDC_EDIT4, m_database);
	DDX_Text(pDX, IDC_EDIT5, m_secalg);
	DDX_Text(pDX, IDC_EDIT6, m_filealg);
	DDX_Text(pDX, IDC_EDIT7, m_magic);
	DDX_Text(pDX, IDC_EDIT8, m_subsystem);
	DDX_Text(pDX, IDC_EDIT9, m_secnum);
	DDX_Text(pDX, IDC_EDIT10, m_timestamp);
	DDX_Text(pDX, IDC_EDIT12, m_chara);
	DDX_Text(pDX, IDC_EDIT13, m_checksum);
	DDX_Text(pDX, IDC_EDIT14, m_optionsize);
	DDX_Text(pDX, IDC_EDIT11, m_sizeofheaders);
	DDX_Text(pDX, IDC_EDIT15, m_dllchara);
}

//	初始化
BOOL CPeBasic::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	CString title;
	PEGet pe(CPeBasic::exe_path.GetString());

	if (pe.is_success() == false) { 
		this->GetWindowText(title);
		title.Append(TEXT("\n1、不是PE文件 \n2、文件被其他应用程序打开"));
		AfxMessageBox(title);
		EndDialog(0);
		return TRUE; 
	}

	//	设置对话框标题
	this->GetWindowText(title);
	title.Append(exe_path);
	if (!pe.is_32PE()) {
		title.Append(TEXT("  [ PE64 ]"));
	}
	this->SetWindowText(title);

	//	编辑框去掉选中状态 init最后返回false
	CEdit* pEdit = (CEdit*)GetDlgItem(IDC_EDIT0);
	pEdit->SetFocus();

	this->m_oep.Format(TEXT("%08X"), pe.poption_header->AddressOfEntryPoint);
	this->m_imagesize.Format(TEXT("%08X"), pe.get_imagesize());
	this->m_codebase.Format(TEXT("%08X"), pe.poption_header->BaseOfCode);
	this->m_secalg.Format(TEXT("%08X"), pe.poption_header->SectionAlignment);
	this->m_filealg.Format(TEXT("%08X"), pe.poption_header->FileAlignment);
	this->m_magic.Format(TEXT("%08X"), pe.poption_header->Magic);
	this->m_chara.Format(TEXT("%04X"), pe.pfile_header->Characteristics);
	this->m_subsystem.Format(TEXT("%04X"), pe.poption_header->Subsystem);
	this->m_secnum.Format(TEXT("%04X"), pe.pfile_header->NumberOfSections);
	this->m_timestamp.Format(TEXT("%08X"), pe.pfile_header->TimeDateStamp);
	this->m_sizeofheaders.Format(TEXT("%08X"), pe.poption_header->SizeOfHeaders);
	this->m_chara.Format(TEXT("%04X"), pe.pfile_header->Characteristics);
	this->m_checksum.Format(TEXT("%08X"), pe.poption_header->CheckSum);
	this->m_optionsize.Format(TEXT("%04X"), pe.pfile_header->SizeOfOptionalHeader);
	this->m_dllchara.Format(TEXT("%08X"), pe.poption_header->DllCharacteristics);

	//	64位编译环境特殊处理
#if defined(_WIN64)
	if (pe.is_32PE()) {
		this->m_imagebase.Format(TEXT("%08X"), *((PDWORD)&pe.poption_header->ImageBase+1));
		this->m_database.Format(TEXT("%08X"), *(PDWORD)&pe.poption_header->ImageBase);
	}
	else{
		this->m_imagebase.Format(TEXT("%p"), (LPVOID)pe.poption_header->ImageBase);
		this->m_database = TEXT("无此项");
	}
#else
	if (pe.is_32PE()) {
		this->m_imagebase.Format(TEXT("%p"), (LPVOID)pe.poption_header->ImageBase);
		this->m_database.Format(TEXT("%08X"), pe.poption_header->BaseOfData);
	}
	else {
		this->m_imagebase.Format(TEXT("%08X%08X"), pe.poption_header->ImageBase, pe.poption_header->BaseOfData);
		this->m_database = TEXT("无此项");
	}
#endif
	
	UpdateData(false);
	return false;
}

BEGIN_MESSAGE_MAP(CPeBasic, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON_DOOK, &CPeBasic::OnBnClickedButtonDook)
	ON_BN_CLICKED(IDC_BUTTON_SEC, &CPeBasic::OnBnClickedButtonSec)
	ON_BN_CLICKED(IDC_BUTTON_DIR, &CPeBasic::OnBnClickedButtonDir)
END_MESSAGE_MAP()

// CPeBasic 消息处理程序

//	确定按钮
void CPeBasic::OnBnClickedButtonDook()
{
	CDialogEx::OnOK();
}

//	区段按钮
void CPeBasic::OnBnClickedButtonSec()
{
	CPeSec pe_sec;
	pe_sec.DoModal();
}

//	目录按钮
void CPeBasic::OnBnClickedButtonDir()
{
	CPeDir pe_dir;
	pe_dir.DoModal();
}
