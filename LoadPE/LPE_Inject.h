#pragma once
#include <Windows.h>
#include <tchar.h>
// Զ���߳�ע��
HMODULE RmThread_Inject(long pid, LPCSTR dll_path);
// Զ���߳�ж��ע��
BOOL RmThread_Unject(long pid, HMODULE hmod);