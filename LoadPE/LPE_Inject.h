#pragma once
#include <Windows.h>
#include <tchar.h>
// 远程线程注入
HMODULE RmThread_Inject(long pid, LPCSTR dll_path);
// 远程线程卸载注入
BOOL RmThread_Unject(long pid, HMODULE hmod);