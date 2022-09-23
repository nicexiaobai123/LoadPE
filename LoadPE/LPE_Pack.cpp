#include "LPE_Pack.h"
#include "PEtools.h"

// ���ӵ�����һ���ṹ��
typedef struct SHARE
{
	long old_oep;	// ��OEP
	long new_oep;	// Ҫ�ı��OEP
	long tls_rva;	// tls���rva
	long reloca_rva;// �ض�λ���rva
	long import_rva;// �����
}_SHARE, * _PSHARE;

bool InPack(const TCHAR* infile, const TCHAR* shellfile, const TCHAR* outfile)
{
	bool ret = false;

	//	���ؿ��ӵ��ڴ�	dll���ڴ��в��ܸ���;��Ϊ���ĺ󲻿�ж��
	PVOID cur_load_dll = (PVOID)LoadLibrary(shellfile);
	if (cur_load_dll == nullptr)return false;

	//	��ȡ���ӹ����һ���ṹ��(������)
	_PSHARE Share = (_PSHARE)GetProcAddress((HMODULE)cur_load_dll, "share");

	//	����pe����,����exe�ļ�,���سɹ���is_success�ж�
	PEtools pet_exe(infile);
	if (!pet_exe.is_success())return 0;

	//	����ṹ���� oep,relo,tls,import
	Share->old_oep = pet_exe.get_oep();
	Share->reloca_rva = pet_exe.get_relocate_rva();
	Share->tls_rva = pet_exe.get_tlsrva();
	Share->import_rva = pet_exe.get_import_rva();

	//	dll���������ڴ� ����
	char* dll_buff = (char*)PEtools(cur_load_dll).get_loadbuffer();	// �ڴ��ַ
	long dll_size = PEtools(cur_load_dll).get_imagesize();			// ��С
	char* data = new char[dll_size + 100];
	memcpy(data, dll_buff, dll_size);			// ������Ŀռ�װ

	//	�ÿɸ��ĵ��ڴ� �ٳ�ʼ��PE����
	PEtools pet_dll(data);					// �Ǵ�������,����ֱ�Ӵ����ڴ��ַ
	if (!pet_dll.is_success())return 0;

	//	���dll���µĽ�,��������Ҫ��֮ǰ�Ĳ�ͬ	����0xE4000060
	ret = pet_exe.increase_section(".press", pet_dll.get_loadbuffer(), pet_dll.get_imagesize(), 0xE4000060);
	if (!ret) return false;

// --------------------------- �ض�λ�� ���� ---------------------------------

	// �õ�exe�пǵ��ض�λ��rva = �ǽڵĿ�ʼλ��+���ض�λ���λ��
	long shell_start = pet_exe.get_rva_bysecname(".press");
	long shell_relo_rva = pet_dll.get_relocate_rva();
	if (shell_start == 0 || shell_relo_rva == 0)return false;
	long new_relo_rva = shell_start + shell_relo_rva;

	//	�ֶ��ض�λ,�Ǳ���µ���������,��ǰ��ȫ�ֱ�����δ�޸�
	//  �ض�λ -> 0x4010b9(ԭ����ȫ�ֱ���) + ��������ʼ
	long shell_start_foa = pet_exe.rva_to_foa(shell_start);
	PVOID temp = (PVOID)((long)pet_exe.get_pebuffer() + shell_start_foa);	// ��ʱ�ڴ���PE�ṹ,����ӵĽڴ���ʼ
	PEtools temp_pet(temp);
	if (!temp_pet.is_success())return false;

	long cur_imagebase = pet_exe.get_imagebase() + shell_start;
	ret = temp_pet.repair_reloc((long)cur_load_dll, cur_imagebase);			// �޸�
	if (!ret) return false;

	//	�޸�exe�п����ε��ض�λ��	�ض�λ�����һ��Ҫ�޸��ĵ�ַ�� virtualBase + offset
	//	virtualBase��ԭ��������0x1000֮���,�������ڿǵ��µĽ���,��ҪvirtualBase+�½���ʼ
	ret = temp_pet.repair_relo_offset(shell_start);			// �����½���ʼ
	if (!ret) return false;

	//	�����ض�λ��Ϊ �ǵ��ض�λ��
	pet_exe.set_relocate(new_relo_rva);

// --------------------------- ����� ���� ---------------------------------

	//	�޸������ƫ��,�ǵ�ƫ��->exe�����ƫ��
	ret = temp_pet.repair_import_offset(shell_start);			// �����½���ʼ
	if (!ret) return false;

	//	�����������,ǰ���Ѿ��ֶ��ض�λ��
	//	�ǳ�����Ҫ�ֶ��޸�ԭ�еĵ����
	long shell_import_rva = pet_dll.get_import_rva();
	if (shell_import_rva == 0) return false;
	long new_import_rva = shell_start + shell_import_rva;

	pet_exe.set_import(new_import_rva);

// --------------------------- ��ڡ�tls���� ---------------------------------
	// ����oepΪ �ǵ�oep
	long dll_oep = Share->new_oep - (long)cur_load_dll;
	dll_oep = dll_oep + shell_start;
	pet_exe.set_oep(dll_oep);

	//	����tlsΪ0,�����м���ԭ��exe��tls����
	pet_exe.set_tlsrva(0);

	//	����
	ret = pet_exe.to_file(outfile);
	if (!ret) return false;

	//	ж��dll
	FreeLibrary((HMODULE)cur_load_dll);
	return true;
}