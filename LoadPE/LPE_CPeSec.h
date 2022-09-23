#pragma once
#include "pch.h"

class CPeSec : public CDialogEx
{
	DECLARE_DYNAMIC(CPeSec)

public:
	CPeSec(CWnd* pParent = nullptr);
	virtual ~CPeSec();

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_PE_SEC };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX); 
	void InitList();
	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	CListCtrl m_seclist;
};
