#include "LPE_Inject.h"

// LoadLibrary
HMODULE RmThread_Inject(DWORD pid, LPCSTR dll_path)
{
	HMODULE exitCode{ 0 };
	DWORD path_len = _tcslen(dll_path) + 1;
	if (pid == 0 || path_len < 5) return 0;

	HANDLE hProcess = NULL;
	HANDLE hRmThread = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (hProcess == NULL) return exitCode;

	do
	{
		//	申请空间
		LPVOID alloc_addr = VirtualAllocEx(hProcess, NULL, path_len, MEM_COMMIT, PAGE_READWRITE);
		if (alloc_addr == NULL) break;

		// 写入参数	C://xxx.dll
		if (WriteProcessMemory(hProcess, alloc_addr, dll_path, path_len, NULL) == false)break;

		//	创建远程线程
		hRmThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, alloc_addr, 0, NULL);
		if (hRmThread == 0) break;

		//	等待线程结束
		WaitForSingleObject(hRmThread, INFINITE);

		//	得到线程函数结束返回值->模块句柄
		GetExitCodeThread(hRmThread,(LPDWORD)&exitCode);

		//	释放资源
		VirtualFreeEx(hProcess, alloc_addr, 0, MEM_RELEASE);
		alloc_addr = NULL;
		CloseHandle(hRmThread);
	} while (0);

	CloseHandle(hProcess);
	return exitCode;
}

// FreeLibrary();
BOOL RmThread_Unject(DWORD pid, HMODULE hmod)
{
	DWORD exitCode = false;
	if (pid == 0 || hmod == NULL) return false;

	HANDLE hProcess = NULL;
	HANDLE hRmThread = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (hProcess == NULL) return exitCode;

	// 远程线程 使用FreeLibrary
	hRmThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, hmod, 0, 0);
	if(hRmThread == NULL){
		return false;
	}

	WaitForSingleObject(hRmThread, INFINITE);
	GetExitCodeThread(hRmThread, &exitCode);
	CloseHandle(hRmThread);
	CloseHandle(hProcess);
	return exitCode;
}