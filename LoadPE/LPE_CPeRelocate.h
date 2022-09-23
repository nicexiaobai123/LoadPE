#pragma once
#include "pch.h"

// CPeRelocate 对话框

class CPeRelocate : public CDialogEx
{
	DECLARE_DYNAMIC(CPeRelocate)

public:
	CPeRelocate(CWnd* pParent = nullptr);
	virtual ~CPeRelocate();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_PE_RELOCATE };
#endif

protected:
	virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX); 
	void InitSecList();
	void InitListSec(DWORD index, DWORD ViraddrRva, DWORD blockSize);


	DECLARE_MESSAGE_MAP()
private:
	CListCtrl m_list_sec;
	CListCtrl m_list_block;
public:
	afx_msg void OnLvnItemchangedListSec(NMHDR* pNMHDR, LRESULT* pResult);
};