#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include "ntstructs.h"
#include <map>

typedef NTSTATUS(NTAPI* ntfunction_t)(...);

inline ntfunction_t NtQueryInformationProcess;
inline ntfunction_t NtQueryObject;
inline ntfunction_t ZwAssociateWaitCompletionPacket;

class PoolParty {
private:
	HANDLE process_handle;
	HANDLE io_handle;
	std::map<PVOID, PVOID> allocated_modules;
public:
	PoolParty(HANDLE process_handle);

	HANDLE get_io_handle();
	MODULEENTRY32 get_function_module(void(*function)());

	PVOID allocate(void(*function)());
	unsigned char* get_bytes(PVOID address, size_t size = 100);
	bool set_bytes(PVOID address, unsigned char* bytes, size_t size = 100);
	bool execute(PVOID address);
	PVOID scan_codecave(HANDLE process);
	bool m_ZwSetIoCompletion(HANDLE io_handle, PTP_DIRECT remote_direct, PVOID key, PVOID apc_context, PVOID apc_routine);
	void SetupExecution(PoolParty& pool_party, TP_DIRECT* m_ShellcodeAddress);

};