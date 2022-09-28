#include "LPE_Pack.h"
#include "PEtools.h"

// ���ӵ�����һ���ṹ��
typedef struct SHARE
{
	long old_oep;			// ��OEP
	long tls_rva;			// Ҫ�ı��OEP
	long reloca_rva;		// tls���rva
	long import_rva;		// �ض�λ���rva
	DWORD_PTR new_oep_va;	// �����
}_SHARE, * _PSHARE;


//	ѹ���㷨




//	�ӿ�
bool InPack(const TCHAR* infile, const TCHAR* shellfile, const TCHAR* outfile)
{
	bool ret = false;

	//	����pe����,����exe�ļ�,���سɹ���is_success�ж�
	PEtools pe_exe(infile);
	if (!pe_exe.is_success()) return false;

	//	ʹ���뻷�� �� Ŀ��PE�ļ�һ��
#if defined(_WIN64)
	if (pe_exe.is_32PE()) return false;
#else
	if (!pe_exe.is_32PE()) return false;
#endif

	//	���ؿ��ӵ��ڴ�	dll���ڴ��в��ܸ���;��Ϊ���ĺ󲻿�ж��
	PVOID cur_load_dll = (PVOID)LoadLibrary(shellfile);
	if (cur_load_dll == nullptr)return false;

	//	��ȡ���ӹ����һ���ṹ��(������)
	_PSHARE Share = (_PSHARE)GetProcAddress((HMODULE)cur_load_dll, "share");

	//	����pe����,����exe�ļ�,���سɹ���is_success�ж�
	PEtools pet_exe(infile);
	if (!pet_exe.is_success())return 0;

	//	����ṹ���� oep,relo,tls,import
	Share->old_oep = pe_exe.get_oep();
	Share->reloca_rva = pe_exe.get_relocate_rva();
	Share->tls_rva = pe_exe.get_tlsrva();
	Share->import_rva = pe_exe.get_import_rva();

	//	dll���������ڴ� ����
	char* dll_buff = (char*)PEtools(cur_load_dll).get_loadbuffer();	// �ڴ��ַ
	long dll_size = PEtools(cur_load_dll).get_imagesize();			// ��С
	char* data = new char[dll_size + 100];
	memcpy(data, dll_buff, dll_size);			// ������Ŀռ�װ

	//	�ÿɸ��ĵ��ڴ� �ٳ�ʼ��PE����
	PEtools pe_dll(data);						// �Ǵ�������,����ֱ�Ӵ����ڴ��ַ
	if (!pe_dll.is_success())return 0;

	//	���dll���µĽ�,��������Ҫ��֮ǰ�Ĳ�ͬ	����0xE4000060
	ret = pe_exe.increase_section(".press", pe_dll.get_loadbuffer(), pe_dll.get_imagesize(), 0xE4000060);
	if (!ret) return false;

// --------------------------- �ض�λ�� ���� ---------------------------------

	// �õ�exe�пǵ��ض�λ��rva = �ǽڵĿ�ʼλ��+���ض�λ���λ��
	long shell_start = pe_exe.get_rva_bysecname(".press");
	long shell_relo_rva = pe_dll.get_relocate_rva();
	if (shell_start == 0 || shell_relo_rva == 0)return false;
	long new_relo_rva = shell_start + shell_relo_rva;

	//	�ֶ��ض�λ,�Ǳ���µ���������,��ǰ��ȫ�ֱ�����δ�޸�
	//  �ض�λ -> 0x4010b9(ԭ����ȫ�ֱ���) + ��������ʼ
	long shell_start_foa = pe_exe.rva_to_foa(shell_start);
	PVOID temp = (PVOID)((DWORD_PTR)pe_exe.get_pebuffer() + shell_start_foa);	// ��ʱ�ڴ���PE�ṹ,����ӵĽڴ���ʼ
	PEtools temp_pet(temp);
	if (!temp_pet.is_success())return false;

	DWORD_PTR cur_imagebase = pe_exe.get_imagebase() + shell_start;
	ret = temp_pet.repair_reloc((DWORD_PTR)cur_load_dll, cur_imagebase);		// �޸�
	if (!ret) return false;

	//	�޸�exe�п����ε��ض�λ��	�ض�λ�����һ��Ҫ�޸��ĵ�ַ�� virtualBase + offset
	//	virtualBase��ԭ��������0x1000֮���,�������ڿǵ��µĽ���,��ҪvirtualBase+�½���ʼ
	ret = temp_pet.repair_relo_offset(shell_start);				// �����½���ʼ
	if (!ret) return false;

	//	�����ض�λ��Ϊ �ǵ��ض�λ��
	pe_exe.set_relocate(new_relo_rva);

// --------------------------- ����� ���� ---------------------------------

	//	�޸������ƫ��,�ǵ�ƫ��->exe�����ƫ��
	ret = temp_pet.repair_import_offset(shell_start);			// �����½���ʼ
	if (!ret) return false;

	//	�����������,ǰ���Ѿ��ֶ��ض�λ��
	//	�ǳ�����Ҫ�ֶ��޸�ԭ�еĵ����
	long shell_import_rva = pe_dll.get_import_rva();
	if (shell_import_rva == 0) return false;
	long new_import_rva = shell_start + shell_import_rva;

	pe_exe.set_import(new_import_rva);

// --------------------------- ��ڡ�tls���� ---------------------------------
	// ����oepΪ �ǵ�oep
	DWORD dll_oep_rva = Share->new_oep_va - (DWORD_PTR)cur_load_dll;
	dll_oep_rva = dll_oep_rva + shell_start;
	pe_exe.set_oep(dll_oep_rva);

	//	����tlsΪ0,�����м���ԭ��exe��tls����
	pe_exe.set_tlsrva(0);

	//	

	//	����
	ret = pe_exe.to_file(outfile);
	if (!ret) return false;

	//	ж��dll
	FreeLibrary((HMODULE)cur_load_dll);
	return true;
}