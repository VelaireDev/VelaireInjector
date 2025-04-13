#include "injector.h"
#include "poolparty.h"
#include "skCrypter.h"

#define TARGET_PROCESS skCrypt("RobloxPlayerBeta.exe")
#define DLL_PATH skCrypt("C:\\Users\\User\\Downloads\\ducks.dll")

int main() {
	HMODULE ntdll = GetModuleHandleA(skCrypt("ntdll.dll"));
	NtQueryInformationProcess = (ntfunction_t)GetProcAddress(ntdll, skCrypt("NtQueryInformationProcess"));
	NtQueryObject = (ntfunction_t)GetProcAddress(ntdll, skCrypt("NtQueryObject"));
	ZwAssociateWaitCompletionPacket = (ntfunction_t)GetProcAddress(ntdll, skCrypt("ZwAssociateWaitCompletionPacket"));

	DWORD process_id = Injector::get_process_id(TARGET_PROCESS.decrypt());
	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);

	if (Injector::manual_map(process_handle, DLL_PATH.decrypt()))
		printf(skCrypt("Mapped dll."));
	else
		printf(skCrypt("Failed to map dll."));

	return 0;
};