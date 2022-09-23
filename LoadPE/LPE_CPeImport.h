#pragma once
#include "pch.h"
#include "LPE_CPeBasic.h"
#include "PEtools.h"

class CPeImport : public CDialogEx
{
	DECLARE_DYNAMIC(CPeImport)

public:
	CPeImport(CWnd* pParent = nullptr);
	virtual ~CPeImport();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_PE_IMPORT };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();
	void InitDllList();
	void InitFuncList(DWORD firstThunkRva);

	DECLARE_MESSAGE_MAP()
private:
	CListCtrl m_list_dll;
	CListCtrl m_list_func;
public:

	afx_msg void OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult);
};
