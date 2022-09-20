#pragma once
#include "pch.h"

// CAbout 对话框

class CAbout : public CDialogEx
{
	DECLARE_DYNAMIC(CAbout)

public:
	CAbout(CWnd* pParent = nullptr);
	virtual ~CAbout();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_ABOUT};
#endif

protected:
	DECLARE_MESSAGE_MAP()
	virtual void DoDataExchange(CDataExchange* pDX);
	
private:
	CStatic m_bmap;
	CStatic m_link;
public:
	virtual BOOL OnInitDialog();
};
