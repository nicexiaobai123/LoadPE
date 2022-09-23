#pragma once
#include "pch.h"

// CPeExport 对话框

class CPeExport : public CDialogEx
{
	DECLARE_DYNAMIC(CPeExport)

public:
	CPeExport(CWnd* pParent = nullptr); 
	virtual ~CPeExport();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_PE_EXPORT};
#endif

protected:
	virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);
	DECLARE_MESSAGE_MAP()
private:
	CString m_func_num;
	CString m_name_num;
	CString m_file_name;
	CString m_addr_rva;
	CString m_name_rva;
	CString m_order_rva;
	CListCtrl m_info;
public:
	afx_msg void OnBnClickedButton1();
	CString m_begin_num;
};
