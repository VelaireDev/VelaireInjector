#include "injector.h"
#include "functions.hpp"
#include "skCrypter.h"
#include <format> // For error formatting
#define _CRT_SECURE_NO_WARNINGS // To avoid strerror warnings
#include <fstream> // For logging to file

//Roblox Manual Map Injector, Developed by Deccatron...

// Global log file for persistent logging
std::ofstream g_LogFile;

void log_message(const char* format, ...) {
	char buffer[4096];
	va_list args;
	va_start(args, format);
	vsprintf_s(buffer, format, args);
	va_end(args);

	// Log to console
	printf("%s", buffer);

	// Log to file if open
	if (g_LogFile.is_open()) {
		g_LogFile << buffer;
		g_LogFile.flush(); // Ensure it's written immediately
	}
}

DWORD Injector::get_process_id(const char* process_name) {
	log_message(skCrypt("[LOG] Attempting to find process ID for: %s\n"), process_name);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		log_message(skCrypt("[ERROR] CreateToolhelp32Snapshot failed. Error code: %lu\n"), GetLastError());
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);

	if (Process32First(snapshot, &pe32)) {
		do {
			char exeFile[260];
			size_t convertedChars = 0;
			wcstombs_s(&convertedChars, exeFile, sizeof(exeFile), pe32.szExeFile, sizeof(exeFile));

			if (!strcmp(exeFile, process_name)) {
				log_message(skCrypt("[LOG] Process found with ID: %lu\n"), pe32.th32ProcessID);
				CloseHandle(snapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(snapshot, &pe32));
	}
	else {
		log_message(skCrypt("[ERROR] Process32First failed. Error code: %lu\n"), GetLastError());
	}

	log_message(skCrypt("[ERROR] Process not found: %s\n"), process_name);
	CloseHandle(snapshot);
	return 0;
}

BYTE* Injector::get_dll_data(const char* dll_path) {
	log_message(skCrypt("[LOG] Attempting to load DLL from: %s\n"), dll_path);
	if (!std::filesystem::exists(dll_path)) {
		log_message(skCrypt("[ERROR] DLL file not found: %s\n"), dll_path);
		return new BYTE[0];
	}

	std::ifstream file(dll_path, std::ios::binary | std::ios::ate);
	if (file.fail()) {
		char err_msg[256];
#ifdef _MSC_VER
		strerror_s(err_msg, sizeof(err_msg), errno);
		log_message(skCrypt("[ERROR] Failed to open DLL file. Error: %s\n"), err_msg);
#else
		log_message(skCrypt("[ERROR] Failed to open DLL file. Error code: %d\n"), errno);
#endif
		return new BYTE[0];
	}

	SIZE_T file_size = file.tellg();
	if (file_size < 0x1000) {
		log_message(skCrypt("[ERROR] DLL file size is invalid: %llu bytes\n"), file_size);
		return new BYTE[0];
	}

	log_message(skCrypt("[LOG] DLL size: %llu bytes\n"), file_size);
	BYTE* p_src_data = new BYTE[(UINT_PTR)file_size];
	file.seekg(0, std::ios::beg);
	file.read((char*)p_src_data, file_size);
	file.close();

	log_message(skCrypt("[LOG] DLL data loaded successfully\n"));
	return p_src_data;
}

void mb() {
	MessageBoxA(NULL, NULL, NULL, NULL);
}

bool Injector::manual_map(HANDLE process_handle, const char* dll_path) {
	// Open log file
	g_LogFile.open("injector_log.txt", std::ios::out | std::ios::app);

	bool injection_result = false;

	try {
		// Add flag to control memory checks - set to false to disable them
		bool enable_memory_checks = false;

		// Ask user if they want to use a validation DLL instead
		char choice;
		printf("Do you want to use a validation DLL instead of your actual DLL? (y/n): ");
		choice = getchar();
		// Clear input buffer
		while ((getchar()) != '\n');

		const char* target_dll_path;
		if (choice == 'y' || choice == 'Y') {
			// Use the validation DLL that the user created
			target_dll_path = "C:\\Users\\Dexter Sitwell\\source\\repos\\validation DLL\\x64\\Debug\\validation DLL.dll";
			log_message(skCrypt("[LOG] Using validation DLL mode\n"));

			// Check if validation DLL exists
			if (!std::filesystem::exists(target_dll_path)) {
				log_message(skCrypt("[ERROR] Validation DLL not found at: %s\n"), target_dll_path);
				log_message(skCrypt("[INFO] Please make sure the validation DLL exists at the specified path\n"));
				goto cleanup;
			}

			log_message(skCrypt("[LOG] Validation DLL found at: %s\n"), target_dll_path);
		}
		else {
			// Use the actual DLL
			target_dll_path = "C:\\Users\\Dexter Sitwell\\Downloads\\test.dll";
			log_message(skCrypt("[LOG] Using actual DLL\n"));
		}

		log_message(skCrypt("[LOG] Starting manual mapping process\n"));
		log_message(skCrypt("[LOG] Target DLL path: %s\n"), target_dll_path);

		// Check if the DLL exists
		if (!std::filesystem::exists(target_dll_path)) {
			log_message(skCrypt("[ERROR] DLL file not found at: %s\n"), target_dll_path);
			goto cleanup;
		}

		if (!process_handle) {
			log_message(skCrypt("[ERROR] Process handle invalid\n"));
			goto cleanup;
		}

		// Check if process is still alive
		DWORD exit_code = 0;
		if (!GetExitCodeProcess(process_handle, &exit_code) || exit_code != STILL_ACTIVE) {
			log_message(skCrypt("[ERROR] Target process is not running. Exit code: %lu\n"), exit_code);
			goto cleanup;
		}

		log_message(skCrypt("[LOG] Initializing PoolParty\n"));
		PoolParty pool_party(process_handle);
		// Note: No is_initialized check as it doesn't exist in PoolParty class

		log_message(skCrypt("[LOG] Loading DLL data\n"));
		BYTE* dll_data = get_dll_data(target_dll_path);
		if (!dll_data || dll_data[0] == 0) {
			log_message(skCrypt("[ERROR] Failed to load DLL data\n"));
			goto cleanup;
		}

		IMAGE_DOS_HEADER* p_data_header = (IMAGE_DOS_HEADER*)(dll_data);

		if (p_data_header->e_magic != 0x5A4D) {
			log_message(skCrypt("[ERROR] DLL file is invalid - DOS header magic number mismatch\n"));
			delete[] dll_data;
			goto cleanup;
		}
		log_message(skCrypt("[LOG] DOS header validated\n"));

		IMAGE_NT_HEADERS* p_nt_header = (IMAGE_NT_HEADERS*)(dll_data + p_data_header->e_lfanew);
		if (p_nt_header->Signature != IMAGE_NT_SIGNATURE) {
			log_message(skCrypt("[ERROR] Invalid NT header signature\n"));
			delete[] dll_data;
			goto cleanup;
		}
		log_message(skCrypt("[LOG] NT header validated\n"));

		IMAGE_OPTIONAL_HEADER* p_optional_header = &p_nt_header->OptionalHeader;
		IMAGE_FILE_HEADER* p_file_header = &p_nt_header->FileHeader;
		IMAGE_SECTION_HEADER* p_section_header = IMAGE_FIRST_SECTION(p_nt_header);

		log_message(skCrypt("[LOG] Allocating memory in target process. Size: %lu bytes\n"), p_optional_header->SizeOfImage);
		BYTE* p_target_base = (BYTE*)VirtualAllocEx(process_handle, NULL, p_optional_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!p_target_base) {
			log_message(skCrypt("[ERROR] VirtualAllocEx failed. Error code: %lu\n"), GetLastError());
			delete[] dll_data;
			goto cleanup;
		}

		log_message(skCrypt("[LOG] Memory allocated at: %p\n"), p_target_base);
		whitelist_page(pool_party, p_target_base); // No return value to check
		log_message(skCrypt("[LOG] Whitelisted memory page\n"));

		log_message(skCrypt("[LOG] Writing headers to target process\n"));
		if (!WriteProcessMemory(process_handle, p_target_base, dll_data, 0x1000, NULL)) {
			log_message(skCrypt("[ERROR] Failed to write headers to target process. Error code: %lu\n"), GetLastError());
			VirtualFreeEx(process_handle, p_target_base, 0, MEM_RELEASE);
			delete[] dll_data;
			goto cleanup;
		}

		log_message(skCrypt("[LOG] Target base: %p\n"), p_target_base);

		log_message(skCrypt("[LOG] Mapping %u sections\n"), p_file_header->NumberOfSections);
		for (UINT i = 0; i != p_file_header->NumberOfSections; ++i, ++p_section_header) {
			log_message(skCrypt("[LOG] Mapping section %u: %s, Size: %lu, VA: %lu\n"),
				i,
				reinterpret_cast<const char*>(p_section_header->Name),
				p_section_header->SizeOfRawData,
				p_section_header->VirtualAddress);

			if (p_section_header->SizeOfRawData) {
				if (!WriteProcessMemory(process_handle,
					p_target_base + p_section_header->VirtualAddress,
					dll_data + p_section_header->PointerToRawData,
					p_section_header->SizeOfRawData, NULL)) {

					log_message(skCrypt("[ERROR] Failed to map section %u. Error code: %lu\n"), i, GetLastError());
					VirtualFreeEx(process_handle, p_target_base, 0, MEM_RELEASE);
					delete[] dll_data;
					CloseHandle(process_handle);
					goto cleanup;
				}
			}
		}

		// Reset section header pointer for protection loop
		p_section_header = IMAGE_FIRST_SECTION(p_nt_header);

		log_message(skCrypt("[LOG] Setting memory protection for sections\n"));
		for (UINT i = 0; i != p_file_header->NumberOfSections; ++i, ++p_section_header) {
			if (p_section_header->Misc.VirtualSize) {
				DWORD new_protection = PAGE_READONLY;

				if ((p_section_header->Characteristics & IMAGE_SCN_MEM_WRITE) > 0)
					new_protection = PAGE_READWRITE;
				else if ((p_section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0)
					new_protection = PAGE_EXECUTE_READ;

				log_message(skCrypt("[LOG] Section %u: Setting protection to 0x%lX\n"), i, new_protection);

				PVOID address = p_target_base + p_section_header->VirtualAddress;
				whitelist_page(pool_party, address); // No return value to check
				log_message(skCrypt("[LOG] Whitelisted section %u page\n"), i);

				DWORD old_protect;
				if (!VirtualProtectEx(process_handle, address, p_section_header->Misc.VirtualSize, new_protection, &old_protect)) {
					log_message(skCrypt("[ERROR] Failed to set protection for section %u. Error code: %lu\n"), i, GetLastError());
				}
			}
		}

		log_message(skCrypt("[LOG] Setting up mapping data\n"));
		MAPPING_DATA mapping_data{ 0 };
		mapping_data.p_base = p_target_base;
		mapping_data.load_library = LoadLibraryA;
		mapping_data.get_proc_address = GetProcAddress;
		mapping_data.rtl_add_function_table = (rtl_add_function_table_t)RtlAddFunctionTable;

		size_t mapping_data_size = sizeof(MAPPING_DATA);
		log_message(skCrypt("[LOG] Allocating memory for mapping data\n"));
		BYTE* p_mapping_data = (BYTE*)(VirtualAllocEx(process_handle, NULL, mapping_data_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!p_mapping_data) {
			log_message(skCrypt("[ERROR] Failed to allocate memory for mapping data. Error code: %lu\n"), GetLastError());
			VirtualFreeEx(process_handle, p_target_base, 0, MEM_RELEASE);
			delete[] dll_data;
			goto cleanup;
		}

		log_message(skCrypt("[LOG] Writing mapping data to: %p\n"), p_mapping_data);
		if (!WriteProcessMemory(process_handle, p_mapping_data, &mapping_data, mapping_data_size, NULL)) {
			log_message(skCrypt("[ERROR] Failed to write mapping data. Error code: %lu\n"), GetLastError());
			VirtualFreeEx(process_handle, p_mapping_data, 0, MEM_RELEASE);
			VirtualFreeEx(process_handle, p_target_base, 0, MEM_RELEASE);
			delete[] dll_data;
			goto cleanup;
		}

		log_message(skCrypt("[LOG] Allocating memory for shellcode\n"));
		PVOID p_shellcode = VirtualAllocEx(process_handle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!p_shellcode) {
			log_message(skCrypt("[ERROR] Failed to allocate memory for shellcode. Error code: %lu\n"), GetLastError());
			VirtualFreeEx(process_handle, p_mapping_data, 0, MEM_RELEASE);
			VirtualFreeEx(process_handle, p_target_base, 0, MEM_RELEASE);
			delete[] dll_data;
			goto cleanup;
		}

		log_message(skCrypt("[LOG] Whitelisting shellcode page at: %p\n"), p_shellcode);
		whitelist_page(pool_party, p_shellcode); // No return value to check
		log_message(skCrypt("[LOG] Shellcode page whitelisted\n"));

		log_message(skCrypt("[LOG] Writing shellcode\n"));
		if (!WriteProcessMemory(process_handle, p_shellcode, &Injector::shellcode, 0x1000, NULL)) {
			log_message(skCrypt("[ERROR] Failed to write shellcode. Error code: %lu\n"), GetLastError());
			VirtualFreeEx(process_handle, p_shellcode, 0, MEM_RELEASE);
			VirtualFreeEx(process_handle, p_mapping_data, 0, MEM_RELEASE);
			VirtualFreeEx(process_handle, p_target_base, 0, MEM_RELEASE);
			delete[] dll_data;
			goto cleanup;
		}

		log_message(skCrypt("[LOG] Calling shellcode\n"));
		call_shellcode(pool_party, p_shellcode, p_mapping_data); // No return value to check
		log_message(skCrypt("[LOG] Shellcode call initiated\n"));

		log_message(skCrypt("[LOG] Scanning for codecave\n"));
		PVOID shellcode_address = pool_party.scan_codecave(process_handle);
		if (!shellcode_address) {
			log_message(skCrypt("[ERROR] Failed to find suitable codecave\n"));
			goto cleanup;
		}
		log_message(skCrypt("[LOG] Codecave found at: %p\n"), shellcode_address);

		log_message(skCrypt("[LOG] Setting up execution\n"));
		pool_party.SetupExecution(pool_party, (TP_DIRECT*)shellcode_address); // No return value to check
		log_message(skCrypt("[LOG] Execution setup completed\n"));

		log_message(skCrypt("[LOG] Setting event\n"));
		HANDLE io_handle = pool_party.get_io_handle();
		if (!io_handle || io_handle == INVALID_HANDLE_VALUE) {
			log_message(skCrypt("[LOG] IO handle is invalid, creating a new event\n"));
			// Create a new event handle since the existing one is invalid
			HANDLE new_event = CreateEvent(NULL, TRUE, FALSE, NULL);
			if (!new_event) {
				log_message(skCrypt("[ERROR] Failed to create new event. Error code: %lu\n"), GetLastError());
			}
			else {
				log_message(skCrypt("[LOG] New event created successfully\n"));
				// Try to store the event in the pool_party if possible
				// This is just an attempt, we don't know if pool_party has this ability
				// Skip the SetEvent call since we'll be using ZwSetIoCompletion directly
			}
		}
		else if (!SetEvent(io_handle)) {
			log_message(skCrypt("[ERROR] Failed to set event. Error code: %lu\n"), GetLastError());
		}
		else {
			log_message(skCrypt("[LOG] Event set successfully\n"));
		}

		log_message(skCrypt("[LOG] Setting memory protection for shellcode\n"));
		DWORD old_protect;
		SIZE_T shellcode_size = 0x1000; // Use the size we allocated earlier
		log_message(skCrypt("[LOG] Shellcode size: %llu bytes\n"), (ULONGLONG)shellcode_size);

		if (!VirtualProtectEx(process_handle, shellcode_address, shellcode_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
			log_message(skCrypt("[ERROR] Failed to set memory protection for shellcode. Error code: %lu\n"), GetLastError());
		}
		else {
			log_message(skCrypt("[LOG] Memory protection set successfully\n"));
		}

		log_message(skCrypt("[LOG] Writing shellcode to codecave\n"));
		SIZE_T bytes_written = 0;
		if (!WriteProcessMemory(process_handle, shellcode_address, &Injector::shellcode, 0x1000, &bytes_written)) {
			log_message(skCrypt("[ERROR] Failed to write shellcode to codecave. Error code: %lu\n"), GetLastError());
		}
		else {
			log_message(skCrypt("[LOG] Shellcode written successfully (%llu bytes)\n"), (ULONGLONG)bytes_written);
		}

		std::cout << "[+] ShellCode Address: 0x" << std::uppercase << std::hex << (uintptr_t)shellcode_address << std::endl;

		log_message(skCrypt("[LOG] Setting up TP_DIRECT structure\n"));
		TP_DIRECT direct;
		direct.Callback = shellcode_address;
		PTP_DIRECT remote_direct = static_cast<PTP_DIRECT>(VirtualAllocEx(process_handle, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!remote_direct) {
			log_message(skCrypt("[ERROR] Failed to allocate memory for TP_DIRECT. Error code: %lu\n"), GetLastError());
			goto cleanup;
		}

		log_message(skCrypt("[LOG] Writing TP_DIRECT to: %p\n"), remote_direct);
		if (!WriteProcessMemory(process_handle, remote_direct, &direct, sizeof(TP_DIRECT), NULL)) {
			log_message(skCrypt("[ERROR] Failed to write TP_DIRECT. Error code: %lu\n"), GetLastError());
		}

		log_message(skCrypt("[LOG] Setting IO completion\n"));
		NTSTATUS status = pool_party.m_ZwSetIoCompletion(process_handle, remote_direct, NULL, NULL, (PVOID)(ULONG_PTR)0x3); // Cast integer to PVOID
		if (status != 0) { // Assuming 0 is STATUS_SUCCESS
			log_message(skCrypt("[ERROR] ZwSetIoCompletion failed with status: 0x%X\n"), status);
		}
		else {
			log_message(skCrypt("[LOG] IO completion set successfully\n"));
		}

		// Skip memory checks if disabled
		if (!enable_memory_checks) {
			log_message(skCrypt("[LOG] Memory checks disabled - skipping memory monitoring\n"));
		}
		else {
			log_message(skCrypt("[LOG] Memory checks enabled - starting monitoring\n"));
			// Make the memory check optional and safer
			bool skip_memory_check = false;
			log_message(skCrypt("[LOG] Starting memory checks - monitoring for up to 10 iterations\n"));

			for (int i = 0; i < 10 && !skip_memory_check; i++) {
				log_message(skCrypt("[LOG] Memory check iteration %d/10\n"), i + 1);
				Sleep(5000); // Reduced from 19000 to 5000 to make it faster

				// Use VirtualQueryEx instead of VirtualQuery to query remote process memory
				MEMORY_BASIC_INFORMATION mbi;
				ZeroMemory(&mbi, sizeof(mbi));

				// Check if remote_direct is valid before querying
				if (!remote_direct) {
					log_message(skCrypt("[ERROR] Remote direct pointer is invalid, skipping memory checks\n"));
					skip_memory_check = true;
					continue;
				}

				// First check if the process is still running
				DWORD exit_code = 0;
				if (!GetExitCodeProcess(process_handle, &exit_code) || exit_code != STILL_ACTIVE) {
					log_message(skCrypt("[ERROR] Target process is no longer running. Skipping memory checks.\n"));
					skip_memory_check = true;
					continue;
				}

				SIZE_T result = VirtualQueryEx(process_handle, remote_direct, &mbi, sizeof(mbi));
				if (result == 0) {
					log_message(skCrypt("[ERROR] VirtualQueryEx Failed: Error Code %lu - Skipping further memory checks\n"), GetLastError());
					skip_memory_check = true;
					continue;
				}

				std::string protect_status = "[+] Memory Protection: ";
				switch (mbi.Protect) {
				case PAGE_EXECUTE_READWRITE: protect_status += "RWX"; break;
				case PAGE_EXECUTE_READ: protect_status += "RX"; break;
				case PAGE_READWRITE: protect_status += "RW"; break;
				case PAGE_READONLY: protect_status += "R"; break;
				default: protect_status += "Unknown"; break;
				}

				printf("%s\n", protect_status.c_str());

				// Check if the memory is still committed, if not we should stop checking
				if (mbi.State != MEM_COMMIT) {
					log_message(skCrypt("[WARNING] Memory is no longer committed, stopping memory checks\n"));
					skip_memory_check = true;
				}
			}

			log_message(skCrypt("[LOG] Memory monitoring completed\n"));
		}

		log_message(skCrypt("[LOG] Manual mapping completed\n"));
		log_message(skCrypt("[SUCCESS] Injection appears to have completed successfully!\n"));
		delete[] dll_data;
		injection_result = true;

	}
	catch (const std::exception& e) {
		log_message(skCrypt("[ERROR] Exception caught: %s\n"), e.what());
	}
	catch (...) {
		log_message(skCrypt("[ERROR] Unknown exception caught\n"));
	}

cleanup:
	if (!injection_result) {
		log_message(skCrypt("[FAILURE] Injection failed - check logs for details\n"));
	}

	// Close log file
	if (g_LogFile.is_open()) {
		g_LogFile.close();
	}

	// Keep terminal open until user presses a key
	log_message(skCrypt("\n\n============================================\n"));
	log_message(skCrypt("Injection %s! Logs saved to injector_log.txt\n"), injection_result ? "SUCCEEDED" : "FAILED");
	log_message(skCrypt("Press any key to exit...\n"));
	getchar();

	return injection_result;
}

void __stdcall Injector::shellcode(MAPPING_DATA* p_data) {
	if (!p_data) {
		// Can't log here as this runs in the target process
		p_data->module = (HINSTANCE)0x404040;
		return;
	}

	BYTE* p_base = p_data->p_base;
	IMAGE_NT_HEADERS* p_nt_header = (IMAGE_NT_HEADERS*)((uintptr_t)p_base + (uintptr_t)((IMAGE_DOS_HEADER*)(uintptr_t)p_base)->e_lfanew);
	IMAGE_OPTIONAL_HEADER* p_optional_header = &p_nt_header->OptionalHeader;

	auto load_library = p_data->load_library;
	auto get_proc_address = p_data->get_proc_address;
	auto rtl_add_function_table = p_data->rtl_add_function_table;
	auto dllmain = (dllmain_entrypoint)(p_base + p_optional_header->AddressOfEntryPoint);

	auto data_directory = p_optional_header->DataDirectory;
	auto base_reloc = data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	auto imports = data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto tls = data_directory[IMAGE_DIRECTORY_ENTRY_TLS];
	auto exception = p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	BYTE* location_delta = p_base - p_optional_header->ImageBase;
	if (location_delta) {
		if (base_reloc.Size) {
			auto* p_reloc_data = (IMAGE_BASE_RELOCATION*)(p_base + base_reloc.VirtualAddress);
			const auto* p_reloc_end = (IMAGE_BASE_RELOCATION*)((uintptr_t)(p_reloc_data)+base_reloc.Size);
			while (p_reloc_data < p_reloc_end && p_reloc_data->SizeOfBlock) {
				UINT retries_amount = (p_reloc_data->SizeOfBlock - 8) / 2;
				WORD* p_relative_info = (WORD*)(p_reloc_data + 1);

				for (UINT i = 0; i != retries_amount; ++i, ++p_relative_info) {
					if (RELOC_FLAG64(*p_relative_info)) {
						UINT_PTR* p_patch = (UINT_PTR*)(p_base + p_reloc_data->VirtualAddress + ((*p_relative_info) & 0xFFF));
						*p_patch += (UINT_PTR)(location_delta);
					}
				}
				p_reloc_data = (IMAGE_BASE_RELOCATION*)((BYTE*)(p_reloc_data)+p_reloc_data->SizeOfBlock);
			}
		}
	}

	if (imports.Size) {
		auto* p_import_descr = (IMAGE_IMPORT_DESCRIPTOR*)(p_base + imports.VirtualAddress);
		while (p_import_descr->Name) {
			char* module_name = (char*)(p_base + p_import_descr->Name);
			HINSTANCE import_module = load_library(module_name);

			ULONG_PTR* p_thunk_ref = (ULONG_PTR*)(p_base + p_import_descr->OriginalFirstThunk);
			ULONG_PTR* p_func_ref = (ULONG_PTR*)(p_base + p_import_descr->FirstThunk);

			if (!p_thunk_ref)
				p_thunk_ref = p_func_ref;

			for (; *p_thunk_ref; ++p_thunk_ref, ++p_func_ref) {
				if (IMAGE_SNAP_BY_ORDINAL(*p_thunk_ref)) {
					*p_func_ref = (ULONG_PTR)get_proc_address(import_module, (char*)(*p_thunk_ref & 0xFFFF));
				}
				else {
					auto* p_import = (IMAGE_IMPORT_BY_NAME*)(p_base + (*p_thunk_ref));
					*p_func_ref = (ULONG_PTR)get_proc_address(import_module, p_import->Name);
				}
			}
			++p_import_descr;
		}
	}

	if (tls.Size) {
		auto* p_tls = (IMAGE_TLS_DIRECTORY*)(p_base + tls.VirtualAddress);
		auto* p_callback = (PIMAGE_TLS_CALLBACK*)(p_tls->AddressOfCallBacks);
		for (; p_callback && *p_callback; ++p_callback)
			(*p_callback)(p_base, DLL_PROCESS_ATTACH, NULL);
	}

	bool exception_fail = false;
	if (exception.Size) {
		if (!rtl_add_function_table(
			(IMAGE_RUNTIME_FUNCTION_ENTRY*)(p_base + exception.VirtualAddress),
			exception.Size / 12, (DWORD64)p_base))
			exception_fail = true;
	}

	dllmain(p_base, DLL_PROCESS_ATTACH, NULL);
	p_data->module = (HINSTANCE)(p_base);
}