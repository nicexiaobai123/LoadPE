#pragma once
#include <Windows.h>
#include <tchar.h>
// Զ���߳�ע��
HMODULE RmThread_Inject(DWORD pid, LPCSTR dll_path);
// Զ���߳�ж��ע��
BOOL RmThread_Unject(DWORD pid, HMODULE hmod);