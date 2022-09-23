#pragma once
#include "pch.h"

class CInPack : public CDialogEx
{
	DECLARE_DYNAMIC(CInPack)

public:
	CInPack(CWnd* pParent = nullptr);
	virtual ~CInPack();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_INPACK };
#endif

protected:
	DECLARE_MESSAGE_MAP()
	virtual void DoDataExchange(CDataExchange* pDX);
public:
	CEdit m_infile;
	CEdit m_outfile;
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnBnClickedButtonInpack();
	CEdit m_shellfile;
	afx_msg void OnBnClickedButton4();
};
