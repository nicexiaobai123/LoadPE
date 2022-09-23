#include "PEtools.h"

//
// ==================================== 功能方法  ====================================
//	这些方法是辅助功能方法
//  一些初始化、foa转rva、filebuffer转imagebuffer、 文件对齐、内存对齐、转存到文件
//  两种初始化方法: PETool(文件路径)，PETool(内存地址)
// ==================================================================================
//

// 申请空间读取文件数据
bool PEtools::init_filename_data(const string& file_name)
{
	// 打开文件
	HANDLE hfile{ 0 };
	hfile = CreateFileA(file_name.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hfile == INVALID_HANDLE_VALUE) { return false; }

	// 得到大小
	DWORD size{ 0 };
	size = GetFileSize(hfile, NULL);
	file_size = static_cast<DWORD>(size);
	pe_buff = new char[file_size] {0};
	if (pe_buff == nullptr)
	{
		CloseHandle(hfile);
		return false;
	}

	// 申请空间
	BOOL ret = false;
	int real_size{ 0 };
	ret = ReadFile(hfile, pe_buff, file_size, (PDWORD)&real_size, 0);
	if (!ret)
	{
		delete[] pe_buff;
		pe_buff = nullptr;
	}
	CloseHandle(hfile);
	return true;
}

// 初始化 PE数据
bool PEtools::init_pe_data(PVOID buffer)
{
	pdos_header = 0;
	pnt_header = 0;
	pfile_header = 0;
	poption_header = 0;
	pfirst_section_header = 0;
	if (buffer == nullptr)
	{
		return false;
	}
	pdos_header = (PIMAGE_DOS_HEADER)(buffer);
	if (pdos_header->e_magic != 0x5A4D)
	{
		return false;
	}
	pnt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)pdos_header + pdos_header->e_lfanew);
	if (pnt_header->Signature != 0x4550)
	{
		return false;
	}
	pfile_header = &pnt_header->FileHeader;
	poption_header = &pnt_header->OptionalHeader;
	pfirst_section_header = IMAGE_FIRST_SECTION(pnt_header);
	return true;
}

// 初始化PE数据,内存copy
bool PEtools::init_pe_data(const PEtools& pet)
{
	pdos_header = 0;
	pnt_header = 0;
	pfile_header = 0;
	poption_header = 0;
	pfirst_section_header = 0;
	if (pet.pe_buff == nullptr)
	{
		return false;
	}
	// 内存申请
	pe_buff = new char[pet.file_size]{ 0 };
	memcpy(pe_buff, pet.pe_buff, pet.file_size);

	// pe数据
	if (pe_buff == nullptr)
	{
		return false;
	}
	pdos_header = (PIMAGE_DOS_HEADER)(pe_buff);
	if (pdos_header->e_magic != 0x5A4D)
	{
		return false;
	}
	pnt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)pdos_header + pdos_header->e_lfanew);
	if (pnt_header->Signature != 0x4550)
	{
		return false;
	}
	pfile_header = &pnt_header->FileHeader;
	poption_header = &pnt_header->OptionalHeader;
	pfirst_section_header = IMAGE_FIRST_SECTION(pnt_header);
	return true;
}

// rva 转换成 foa
DWORD PEtools::rva_to_foa(DWORD rva)
{
	if (pe_buff == nullptr) { return 0; }
	PIMAGE_SECTION_HEADER psection = pfirst_section_header;
	DWORD foa = 0;
	for (size_t i = 0; i < pfile_header->NumberOfSections; i++)
	{
		if (psection->VirtualAddress <= rva &&
			rva < psection->VirtualAddress + psection->Misc.VirtualSize)
		{
			foa = rva - psection->VirtualAddress + psection->PointerToRawData;
			break;
		}
		psection++;
	}
	return foa;
}

// foa 转换成 rva
DWORD PEtools::foa_to_rva(DWORD foa)
{
	if (pe_buff == nullptr) { return 0; }
	PIMAGE_SECTION_HEADER psection = pfirst_section_header;
	DWORD rva = 0;
	for (size_t i = 0; i < pfile_header->NumberOfSections; i++)
	{
		if (psection->PointerToRawData <= foa &&
			foa <= psection->PointerToRawData + psection->SizeOfRawData)
		{
			rva = foa - psection->PointerToRawData + psection->VirtualAddress;
			break;
		}
		psection++;
	}
	return rva;
}

// 数字转为 文件对齐
DWORD PEtools::to_fileAlignment(DWORD number)
{
	DWORD ret_number{ 0 };
	if (pe_buff == nullptr) { return 0; }
	if (poption_header->FileAlignment == 0) { return 0; }
	if (number % poption_header->FileAlignment == 0)
	{
		ret_number = number;
	}
	else
	{
		ret_number = (number / poption_header->FileAlignment + 1) * poption_header->FileAlignment;
	}
	return ret_number;
}

// 数字转为 内存对齐
DWORD PEtools::to_sectionAlignment(DWORD number)
{
	DWORD ret_number{ 0 };
	if (pe_buff == nullptr) { return 0; }
	if (poption_header->SectionAlignment == 0) { return 0; }
	if (number % poption_header->SectionAlignment == 0)
	{
		ret_number = number;
	}
	else
	{
		ret_number = (number / poption_header->SectionAlignment + 1) * poption_header->SectionAlignment;
	}
	return ret_number;
	return 0;
}

// 得到节的rva，通过节名称
DWORD PEtools::get_rva_bysecname(const string& sec_name)
{
	if (pe_buff == nullptr) { return 0; }
	if (sec_name.empty() || sec_name.length() > 8) { return 0; }
	PIMAGE_SECTION_HEADER ptemp_section = pfirst_section_header;
	for (size_t i = 0; i < pfile_header->NumberOfSections; i++)
	{
		char* name = (char*)ptemp_section[i].Name;
		if (strcmp(name, sec_name.c_str()) == 0)
			return ptemp_section[i].VirtualAddress;
	}
	return 0;
}

// 通过rva得到节名
string PEtools::get_secname_byrva(DWORD rva)
{
	if (pe_buff == nullptr || rva == 0) return string("");
	PIMAGE_SECTION_HEADER ptemp_section = pfirst_section_header;
	for (size_t i = 0; i < pfile_header->NumberOfSections; i++)
	{
		DWORD sec_begin = ptemp_section[i].VirtualAddress;
		DWORD sec_end = ptemp_section[i].VirtualAddress + ptemp_section[i].Misc.VirtualSize;
		if (rva >= sec_begin && rva < sec_end)
		{
			return string((char*)ptemp_section[i].Name);
		}
	}
	return  string("");
}


// 将buffer 里面的数据保存到文件
bool PEtools::to_file(const string& file_name)
{
	HANDLE hfile = NULL;
	bool ret = false;
	hfile = CreateFileA(file_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hfile == NULL) { return false; }
	ret = WriteFile(hfile, pe_buff, file_size, NULL, 0);
	if (!ret)
	{
		CloseHandle(hfile);
		return false;
	}
	CloseHandle(hfile);
	return true;
}

//
// ================================== 会修改PE文件 ===================================
//	这些方法会修改原有的PE结构，
//  初始化PETool时有两种形式：PETool(文件路径)，PETool(内存地址)，这些方法都是PETool(文件路径)形式
//  其中有一个方法是to_imagebuffer，是重新申请扩大后的内存后再重新修改的pe_buff，并没有load_pe_buff
// 
// ==================================================================================
//

// 增加节
bool PEtools::increase_section(const string& sec_name, const PVOID sec_buffer, DWORD buff_size, DWORD character)
{
	// 判断值是否正确
	if (sec_name.empty() || sec_buffer == nullptr || buff_size == 0) { return false; }
	if (pe_buff == nullptr) { return false; }
	if (sec_name.length() > 8) { return false; }

	// 判断节表是否是否有空间放下  两个节头
	DWORD_PTR sec_number = pfile_header->NumberOfSections;
	DWORD_PTR section_lpos = ((DWORD_PTR)&pfirst_section_header[sec_number - 1]
		- (DWORD_PTR)pe_buff + IMAGE_SIZEOF_SECTION_HEADER);
	DWORD_PTR sizeof_headers = poption_header->SizeOfHeaders;
	if ((sizeof_headers - section_lpos) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		return false;
	}

	// 判断是否有节名称与传入的节名称相同
	PIMAGE_SECTION_HEADER pjudge_sec = pfirst_section_header;
	for (int i = 0; i < pfile_header->NumberOfSections; i++)
	{
		if (strcmp((char*)pjudge_sec[i].Name, sec_name.c_str()) == 0) {
			return false;
		}
	}

	// 要修正的 imagesize = 内存对齐( 原始imagesize + 大小 )
	PIMAGE_SECTION_HEADER plsection_temp = &pfirst_section_header[pfile_header->NumberOfSections - 1];
	DWORD real_imagesize = plsection_temp->VirtualAddress + plsection_temp->Misc.VirtualSize;
	real_imagesize = to_sectionAlignment(real_imagesize);				// 原来的对齐
	real_imagesize = to_sectionAlignment(real_imagesize + buff_size);	// 加上额外的再对齐

	// 重新初始化
	// file_size = 文件对齐 (file_size + 大小)
	// 文件大小是文件大小，内存大小是内存大小
	DWORD old_fileSize = file_size;
	file_size = to_fileAlignment(file_size + buff_size);
	char* temp_buff = new char[file_size] { 0 };
	if (temp_buff == nullptr)
	{
		file_size = old_fileSize;
		return false;
	}
	memcpy(temp_buff, pe_buff, old_fileSize);
	delete[] pe_buff;
	pe_buff = temp_buff;
	temp_buff = nullptr;
	init_flag = init_pe_data(pe_buff);
	if (!init_flag) { return false; }

	// 添加节 
	// 最后节的VirtualAddress是对齐后的
	PIMAGE_SECTION_HEADER plast_section = &pfirst_section_header[pfile_header->NumberOfSections - 1];
	PIMAGE_SECTION_HEADER pnew_section = &pfirst_section_header[pfile_header->NumberOfSections];
	DWORD lfile_pos = plast_section->PointerToRawData + plast_section->SizeOfRawData;

	memcpy(pnew_section, plast_section, IMAGE_SIZEOF_SECTION_HEADER);
	memcpy((char*)pnew_section->Name, sec_name.c_str(), sec_name.length() + 1);
	memcpy((char*)pe_buff + lfile_pos, sec_buffer, buff_size);
	pnew_section->Characteristics = character;
	pnew_section->VirtualAddress =
		to_sectionAlignment(plast_section->VirtualAddress + plast_section->Misc.VirtualSize);
	pnew_section->Misc.VirtualSize = buff_size;
	pnew_section->PointerToRawData = plast_section->PointerToRawData + plast_section->SizeOfRawData;
	pnew_section->SizeOfRawData = to_fileAlignment(buff_size);

	// 修改全局属性
	pfile_header->NumberOfSections += 1;
	poption_header->SizeOfImage = real_imagesize;

	return true;
}

//
// ==================================  手工修复  ===================================
// 手工修复只让其发生的一种情况
// 0、手工修复的时候，要加载的PE 和 当前编译环境一定是一样的，不用isPe32()查看目标PE是否是PE+
// 1、PE原本就被加载到内存中了，是拉伸状态；初始化PETool的时候用的是PETool(内存地址),这种情况用load_pe_buff
// 2、手工修复还有一点，它只会发生在修复程序与被修复PE同字长的情况下，因为64位程序不会loadlibary 32位dll，反之依然
// ===============================================================================
// 

// 修复重定位表
bool PEtools::repair_reloc(DWORD_PTR pre_imagebase, DWORD_PTR cur_imagebase, DWORD rva)
{
	if (load_pe_buff == nullptr) return false;
	DWORD relo_rva = rva != 0 ? rva : get_relocate_rva();
	if (relo_rva == 0) { return false; }

	PIMAGE_BASE_RELOCATION p_relocate = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)load_pe_buff + relo_rva);
	PIMAGE_BASE_RELOCATION ptemp_relp = p_relocate;
	while (ptemp_relp->VirtualAddress != 0)
	{
		for (size_t i = 0; i < (ptemp_relp->SizeOfBlock - 8) / 2; i++)
		{
			short* data = (short*)((DWORD_PTR)ptemp_relp + 8);
			// 高位为 3或者a0 就是可修复
			if ((data[i] & 0x3000) == 0x3000 || (data[i] & 0xa000) == 0xa000)
			{
				DWORD repair_rva = ptemp_relp->VirtualAddress + (data[i] & 0xFFF);
				PDWORD_PTR repair_pos = (PDWORD_PTR)((DWORD_PTR)load_pe_buff + repair_rva);
				// 内存属性
				DWORD old_protect = 0;
				VirtualProtect(repair_pos, sizeof(PDWORD_PTR), PAGE_EXECUTE_READWRITE, &old_protect);
				*repair_pos = *repair_pos - pre_imagebase + cur_imagebase;
				VirtualProtect(repair_pos, sizeof(PDWORD_PTR), old_protect, &old_protect);
			}
		}
		ptemp_relp = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)ptemp_relp + ptemp_relp->SizeOfBlock);
	}
	return true;
}

// 修复导入表
bool PEtools::repair_import(DWORD rva)
{
	if (load_pe_buff == nullptr)  return false;
	DWORD import_rva = rva != 0 ? rva : get_import_rva();
	if (import_rva == 0) return false;

	// 导入表 
	PIMAGE_IMPORT_DESCRIPTOR p_import = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)load_pe_buff + import_rva);
	PIMAGE_THUNK_DATA pThunk_First = nullptr;
	PIMAGE_THUNK_DATA pThunk_orgin = nullptr;

	while (p_import->Name != 0)
	{
		char* dllname = (char*)((DWORD_PTR)load_pe_buff + p_import->Name);
		HMODULE hmod = LoadLibraryA(dllname);
		if (hmod == NULL)return false;

		// IAT没修复之前FirstThunk == OriginalFirstThunk
		// OriginalFirstThunk可能被复制成0,所以用FirstThunk遍历修复
		pThunk_First = (PIMAGE_THUNK_DATA)((DWORD_PTR)load_pe_buff + p_import->FirstThunk);
		while (pThunk_First->u1.Ordinal != 0)
		{
			// 修复
			if (!IMAGE_SNAP_BY_ORDINAL(pThunk_First->u1.Ordinal))
			{
				PIMAGE_IMPORT_BY_NAME pby_name = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)load_pe_buff + pThunk_First->u1.Ordinal);
				char* func_name = pby_name->Name;
				// 内存属性
				DWORD old_protect = 0;
				VirtualProtect(pThunk_First, sizeof(PDWORD_PTR), PAGE_EXECUTE_READWRITE, &old_protect);
				*(PDWORD_PTR)pThunk_First = (DWORD_PTR)GetProcAddress(hmod, func_name);
				VirtualProtect(pThunk_First, sizeof(PDWORD_PTR), old_protect, &old_protect);
			}
			else
			{
				DWORD old_protect = 0;
				VirtualProtect(pThunk_First, sizeof(PDWORD_PTR), PAGE_EXECUTE_READWRITE, &old_protect);
				*(PDWORD_PTR)pThunk_First = (DWORD_PTR)GetProcAddress(hmod, (LPCSTR)(pThunk_First->u1.Ordinal & ~IMAGE_ORDINAL_FLAG));
				VirtualProtect(pThunk_First, sizeof(PDWORD_PTR), old_protect, &old_protect);
			}
			pThunk_First++;
		}
		p_import++;
	}
	return true;
}

// 手动加载TLS
bool PEtools::load_TLS(DWORD tls_rva, DWORD_PTR imagebase)
{
	if (load_pe_buff != nullptr) {
		if (tls_rva == 0) { return false; }
		PIMAGE_TLS_DIRECTORY tls_dir = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)load_pe_buff + tls_rva);
		PEtools::tls_callback* callback = (PEtools::tls_callback*)tls_dir->AddressOfCallBacks;
		//PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls_dir->AddressOfCallBacks;
		while (*callback)
		{
			(*callback)((PVOID)imagebase, DLL_PROCESS_ATTACH, NULL);
			callback++;
		}
		return true;
	}
	return false;
}

//
// ==================================  修复偏移  ==================================
//	修复偏移主要修复offset
//	当我PE的起始基址从0变化到如0x33000后，PE相应的表如重定位表、导入表当中的rva就不再正确
//  主要用于壳程序：当壳添加到新增节，起始位置就是新增节的起始，而不是0
// ===============================================================================
//

// 修复重定位表表项的rva
bool PEtools::repair_relo_offset(DWORD_PTR cur_start_pos, DWORD_PTR pre_start_pos, DWORD rva)
{
	if (load_pe_buff == nullptr)  return false;
	DWORD_PTR pre_pos = pre_start_pos != 0 ? pre_start_pos : 0;
	DWORD relo_rva = rva != 0 ? rva : get_relocate_rva();
	if (relo_rva == 0)  return false;

	PIMAGE_BASE_RELOCATION p_relocate = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)load_pe_buff + relo_rva);
	PIMAGE_BASE_RELOCATION ptemp_relp = p_relocate;
	while (ptemp_relp->VirtualAddress != 0)
	{
		// 修复 VirtualAddress
		ptemp_relp->VirtualAddress = ptemp_relp->VirtualAddress + cur_start_pos;
		ptemp_relp = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)ptemp_relp + ptemp_relp->SizeOfBlock);
	}
	return true;
}

// 修复导入表表项的rva
bool PEtools::repair_import_offset(DWORD_PTR cur_start_pos, DWORD_PTR pre_start_pos, DWORD rva)
{
	if (load_pe_buff == nullptr) return false;
	DWORD_PTR pre_pos = pre_start_pos != 0 ? pre_start_pos : 0;
	DWORD import_rva = rva != 0 ? rva : get_import_rva();
	if (import_rva == 0) return false;

	PIMAGE_IMPORT_DESCRIPTOR p_import = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)load_pe_buff + import_rva);
	while (p_import->Name != 0)
	{
		PDWORD_PTR pthunk_data = (PDWORD_PTR)((DWORD_PTR)load_pe_buff + p_import->OriginalFirstThunk);
		while (*pthunk_data != 0)
		{
			// 修复每个小offset
			if (!IMAGE_SNAP_BY_ORDINAL(*pthunk_data)) {
				*pthunk_data = *pthunk_data + cur_start_pos;
			}
			pthunk_data++;
		}
		p_import->FirstThunk = p_import->FirstThunk + cur_start_pos;
		p_import->Name = p_import->Name + cur_start_pos;
		p_import->OriginalFirstThunk = p_import->OriginalFirstThunk + cur_start_pos;

		p_import++;
	}
	return true;
}