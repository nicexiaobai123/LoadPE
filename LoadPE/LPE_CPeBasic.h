#pragma once
#include "pch.h"

class CPeBasic : public CDialogEx
{
	DECLARE_DYNAMIC(CPeBasic)

public:
	CPeBasic(CWnd* pParent = nullptr);   
	virtual ~CPeBasic();

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_PE_MAIN };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();
public:
	static CString exe_path;

	DECLARE_MESSAGE_MAP()
private:
	CString m_oep;
	CString m_imagebase;
	CString m_imagesize;
	CString m_codebase;
	CString m_database;
	CString m_secalg;
	CString m_filealg;
	CString m_magic;
	CString m_subsystem;
	CString m_secnum;
	CString m_timestamp;
	CString m_chara;
	CString m_checksum;
	CString m_optionsize;
	CString m_sizeofheaders;
	CString m_dllchara;
public:
	afx_msg void OnBnClickedButtonDook();
	afx_msg void OnBnClickedButtonSec();
	afx_msg void OnBnClickedButtonDir();
};

