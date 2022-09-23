#pragma once
#include "pch.h"
#include "LPE_CInPack.h"

// CMain 对话框

class CMain : public CDialogEx
{
	DECLARE_DYNAMIC(CMain)
public:
	CMain(CWnd* pParent = nullptr);
	virtual ~CMain();

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_MAIN };
#endif

protected:
	DECLARE_MESSAGE_MAP()
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();
	void InitListView();
	void InitListView2();
public:
private:
	CImageList img_list;
	CListCtrl m_list_process;
	CListCtrl m_list_modules;
public:
	afx_msg void OnLvnItemchangedListProcess(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedButtonAbout();
	afx_msg void OnBnClickedButtonQuit();
	afx_msg void OnBnClickedButtonPeedit();
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnBnClickedButtonIndll();
	afx_msg void OnBnClickedButtonUndll();
	afx_msg void OnBnClickedButtonInpack();
};
