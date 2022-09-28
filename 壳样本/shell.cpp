#include "PEtools.h"
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")
typedef struct SHARE
{
	long old_oep;
	long tls_rva;
	long reloca_rva;
	long import_rva;
	DWORD_PTR new_oep_va;
}_SHARE, * _PSHARE;

extern "C" _declspec(dllexport)_SHARE share;

void start_execute();
_SHARE share{ 0,0,0,0,(DWORD_PTR)start_execute };

using MyGetModuleHandleA = HMODULE(WINAPI*)(LPCTSTR);
using MyVirtualProtect = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
using MyMessageBoxA = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
MyGetModuleHandleA get_module = nullptr;
MyVirtualProtect vir_protect = nullptr;
MyMessageBoxA message_box = nullptr;

bool init_func()
{
	HMODULE hmod_kernel = LoadLibraryA("kernel32.dll");
	HMODULE hmod_user = LoadLibraryA("user32.dll");
	if (hmod_kernel == NULL || hmod_user == NULL)return false;
	get_module = (MyGetModuleHandleA)GetProcAddress(hmod_kernel, "GetModuleHandleA");
	vir_protect = (MyVirtualProtect)GetProcAddress(hmod_kernel, "VirtualProtect");
	message_box = (MyMessageBoxA)GetProcAddress(hmod_user, "MessageBoxA");
	return true;
}

extern "C" DWORD_PTR  g_oep;
extern "C" void fun1();
DWORD_PTR g_oep;

void start_execute()
{
	//	32λ��dll��64λdll��һ��
	//	Ҫ����32λ��dll�ǵð�.asm����ʱ�ų�
#if defined (_WIN32)
	_asm pushad
#endif

	if (!init_func())return;
	DWORD_PTR imagebase = (DWORD_PTR)get_module(NULL);
	PEtools tools((LPVOID)imagebase);

	//	ԭ��������ض�λ
#if defined (_WIN64)
	tools.repair_reloc(0x140000000, imagebase, share.reloca_rva);
#else
	tools.repair_reloc(0x400000, imagebase, share.reloca_rva);
#endif
	
	//	�ֶ��޸�exe�ĵ����
	tools.repair_import(share.import_rva);

	//	�ֶ�exe��TLS�ص�
	tools.load_TLS(share.tls_rva, imagebase);

	//	��ִ��
	message_box(0, 0, 0, 0);

	g_oep = imagebase + share.old_oep;

#if defined (_WIN64)
	fun1();
#else
	_asm popad
	_asm jmp g_oep
#endif
}