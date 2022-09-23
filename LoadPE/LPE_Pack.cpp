#include "LPE_Pack.h"
#include "PEtools.h"

// 壳子导出的一个结构体
typedef struct SHARE
{
	long old_oep;	// 老OEP
	long new_oep;	// 要改变的OEP
	long tls_rva;	// tls表的rva
	long reloca_rva;// 重定位表的rva
	long import_rva;// 导入表
}_SHARE, * _PSHARE;

bool InPack(const TCHAR* infile, const TCHAR* shellfile, const TCHAR* outfile)
{
	bool ret = false;

	//	加载壳子到内存	dll到内存中不能更改;因为更改后不可卸载
	PVOID cur_load_dll = (PVOID)LoadLibrary(shellfile);
	if (cur_load_dll == nullptr)return false;

	//	获取壳子管理的一个结构体(导出了)
	_PSHARE Share = (_PSHARE)GetProcAddress((HMODULE)cur_load_dll, "share");

	//	定义pe对象,加载exe文件,加载成功用is_success判断
	PEtools pet_exe(infile);
	if (!pet_exe.is_success())return 0;

	//	定义结构体中 oep,relo,tls,import
	Share->old_oep = pet_exe.get_oep();
	Share->reloca_rva = pet_exe.get_relocate_rva();
	Share->tls_rva = pet_exe.get_tlsrva();
	Share->import_rva = pet_exe.get_import_rva();

	//	dll另外申请内存 保存
	char* dll_buff = (char*)PEtools(cur_load_dll).get_loadbuffer();	// 内存基址
	long dll_size = PEtools(cur_load_dll).get_imagesize();			// 大小
	char* data = new char[dll_size + 100];
	memcpy(data, dll_buff, dll_size);			// 用另外的空间装

	//	用可更改的内存 再初始化PE对象
	PEtools pet_dll(data);					// 非传入名字,而是直接传入内存地址
	if (!pet_dll.is_success())return 0;

	//	添加dll到新的节,节名称需要与之前的不同	属性0xE4000060
	ret = pet_exe.increase_section(".press", pet_dll.get_loadbuffer(), pet_dll.get_imagesize(), 0xE4000060);
	if (!ret) return false;

// --------------------------- 重定位表 处理 ---------------------------------

	// 得到exe中壳的重定位表rva = 壳节的开始位置+壳重定位表的位置
	long shell_start = pet_exe.get_rva_bysecname(".press");
	long shell_relo_rva = pet_dll.get_relocate_rva();
	if (shell_start == 0 || shell_relo_rva == 0)return false;
	long new_relo_rva = shell_start + shell_relo_rva;

	//	手动重定位,壳被填到新的区段中了,以前的全局变量等未修复
	//  重定位 -> 0x4010b9(原本的全局变量) + 壳区段起始
	long shell_start_foa = pet_exe.rva_to_foa(shell_start);
	PVOID temp = (PVOID)((long)pet_exe.get_pebuffer() + shell_start_foa);	// 临时内存下PE结构,新添加的节处开始
	PEtools temp_pet(temp);
	if (!temp_pet.is_success())return false;

	long cur_imagebase = pet_exe.get_imagebase() + shell_start;
	ret = temp_pet.repair_reloc((long)cur_load_dll, cur_imagebase);			// 修复
	if (!ret) return false;

	//	修复exe中壳区段的重定位表	重定位表表明一个要修复的地址是 virtualBase + offset
	//	virtualBase在原本壳中是0x1000之类的,但是现在壳到新的节中,需要virtualBase+新节起始
	ret = temp_pet.repair_relo_offset(shell_start);			// 传入新节起始
	if (!ret) return false;

	//	设置重定位表为 壳的重定位表
	pet_exe.set_relocate(new_relo_rva);

// --------------------------- 导入表 处理 ---------------------------------

	//	修复导入表偏移,壳的偏移->exe程序的偏移
	ret = temp_pet.repair_import_offset(shell_start);			// 传入新节起始
	if (!ret) return false;

	//	处理导入表问题,前面已经手动重定位了
	//	壳程序需要手动修复原有的导入表
	long shell_import_rva = pet_dll.get_import_rva();
	if (shell_import_rva == 0) return false;
	long new_import_rva = shell_start + shell_import_rva;

	pet_exe.set_import(new_import_rva);

// --------------------------- 入口、tls处理 ---------------------------------
	// 设置oep为 壳的oep
	long dll_oep = Share->new_oep - (long)cur_load_dll;
	dll_oep = dll_oep + shell_start;
	pet_exe.set_oep(dll_oep);

	//	设置tls为0,壳中有加载原有exe的tls流程
	pet_exe.set_tlsrva(0);

	//	保存
	ret = pet_exe.to_file(outfile);
	if (!ret) return false;

	//	卸载dll
	FreeLibrary((HMODULE)cur_load_dll);
	return true;
}