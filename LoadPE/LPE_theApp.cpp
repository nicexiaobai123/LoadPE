#include "pch.h"
#include "LPE_CMain.h"

class MyApp : public CWinApp
{
public:
	virtual BOOL InitInstance() override{
		CWinApp::InitInstance();
		CMain main_wnd;
		m_pMainWnd = &main_wnd;
		// ģ̬�Ի���  ����ʽ
		main_wnd.DoModal();
		return TRUE;
	}
};
MyApp theApp;