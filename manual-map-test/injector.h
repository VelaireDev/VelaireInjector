#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <filesystem>

#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

typedef HMODULE(WINAPI* load_library_t)(LPCSTR);
typedef FARPROC(WINAPI* get_proc_address_t)(HMODULE, LPCSTR);
typedef BOOL(WINAPIV* rtl_add_function_table_t)(PRUNTIME_FUNCTION, DWORD, DWORD64);
typedef BOOL(WINAPI* dllmain_entrypoint)(PVOID, DWORD, LPVOID);

struct MAPPING_DATA {
	load_library_t load_library;
	get_proc_address_t get_proc_address;
	rtl_add_function_table_t rtl_add_function_table;
	BYTE* p_base;
	HINSTANCE module;
};

namespace Injector {
	DWORD get_process_id(const char* process_name);

	BYTE* get_dll_data(const char* dll_path);
	bool manual_map(HANDLE process_handle, const char* dll_path);
	void __stdcall shellcode(MAPPING_DATA* p_data);
}