#include "pch.h"
#include "LPE_CMain.h"

class MyApp : public CWinApp
{
public:
	virtual BOOL InitInstance() override{
		CWinApp::InitInstance();
		CMain main_wnd;
		m_pMainWnd = &main_wnd;
		// 模态对话框  阻塞式
		main_wnd.DoModal();
		return TRUE;
	}
};
MyApp theApp;