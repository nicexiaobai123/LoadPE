#pragma once
#include "pch.h"

// CPeDir 对话框
class CPeDir : public CDialogEx
{
	DECLARE_DYNAMIC(CPeDir)

public:
	CPeDir(CWnd* pParent = nullptr);
	virtual ~CPeDir();

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_PE_DIR };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();
	DECLARE_MESSAGE_MAP()
public:
	CString m_rva[15];
	CString m_size[15];
	void InitButtonState();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton5();
	afx_msg void OnBnClickedButtonExport();
private:
	CButton m_export_but;
	CButton m_import_but;
	CButton m_relocate_but;
public:
	afx_msg void OnBnClickedButtonImport();
	afx_msg void OnBnClickedButtonRelocate();
};
