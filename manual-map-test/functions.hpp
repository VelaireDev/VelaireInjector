#pragma once

#include <Windows.h>
#include <stdio.h>
#include <fstream>
#include <string>
#include "poolparty.h"
#include "skCrypter.h"

#define SET_INSERT 0xDCA3C0
#define WHITELISTED_PAGES 0x2A5028
#define PAGE_ENCRYPTION_KEY 0x8BAE0AA10C9180A4 

typedef void(__stdcall* set_insert_t)(PVOID, PVOID, PVOID);
typedef void(__stdcall* shellcode_t)(BYTE*);

// Simple logging function to write to a file
void log_to_file(const char* message, ...) {
	char buffer[1024];
	va_list args;
	va_start(args, message);
	vsnprintf(buffer, sizeof(buffer), message, args);
	va_end(args);

	std::ofstream log_file("roblox_debug.log", std::ios::app);
	if (log_file.is_open()) {
		log_file << buffer << std::endl;
		log_file.close();
	}
}

void _whitelist_page_i() {
	uintptr_t hyperion_base = (uintptr_t)GetModuleHandleA("RobloxPlayerBeta.dll"); // dont encrypt or roblox will fucking crash

	// Log the base address
	char log_buf[256];
	sprintf_s(log_buf, "Hyperion Base: 0x%llX", hyperion_base);
	OutputDebugStringA(log_buf);

	if (!hyperion_base) {
		OutputDebugStringA("Failed to get RobloxPlayerBeta.dll handle");
		return;
	}

	set_insert_t set_insert = (set_insert_t)(hyperion_base + SET_INSERT);
	sprintf_s(log_buf, "Set Insert Func: 0x%llX", (uintptr_t)set_insert);
	OutputDebugStringA(log_buf);

	PVOID whitelisted_pages = (PVOID)(hyperion_base + WHITELISTED_PAGES);
	sprintf_s(log_buf, "Whitelisted Pages Address: 0x%llX", (uintptr_t)whitelisted_pages);
	OutputDebugStringA(log_buf);

	PVOID unused = nullptr;
	PVOID page = (PVOID)0xAABBCCDDEEFF;

	OutputDebugStringA("Calling set_insert...");
	set_insert(whitelisted_pages, &unused, &page);
	OutputDebugStringA("set_insert completed");

	while (1) {};
};

void _call_shellcode_i() {
	OutputDebugStringA("Entering _call_shellcode_i");

	shellcode_t shellcode = (shellcode_t)(0xAABBCCDDEEFF);
	OutputDebugStringA("About to call shellcode...");

	shellcode((BYTE*)0xFFEEDDCCBBAA);
	OutputDebugStringA("Shellcode execution completed");

	while (1) {};
};

uintptr_t encrypt_page(PVOID address) {
	uintptr_t result = ((((uintptr_t)address & 0xFFFFFFFFFFFFF000) >> 0xC) ^ PAGE_ENCRYPTION_KEY);
	char log_buf[256];
	sprintf_s(log_buf, "Encrypting page at 0x%llX, result: 0x%llX", (uintptr_t)address, result);
	OutputDebugStringA(log_buf);
	return result;
};

void whitelist_page(PoolParty pool_party, PVOID address) {
	log_to_file("Whitelisting page at address: 0x%llX", (uintptr_t)address);

	PVOID _whitelist_page_p = pool_party.allocate(_whitelist_page_i);
	log_to_file("Allocated whitelist function at: 0x%llX", (uintptr_t)_whitelist_page_p);

	if (!_whitelist_page_p) {
		log_to_file("ERROR: Failed to allocate memory for whitelist function");
		return;
	}

	unsigned char* function_bytes = pool_party.get_bytes(_whitelist_page_p);
	if (!function_bytes) {
		log_to_file("ERROR: Failed to get function bytes");
		return;
	}

	log_to_file("Got function bytes, preparing to modify at offset 34");
	uintptr_t encrypted_page = encrypt_page(address);
	*(uintptr_t*)(&function_bytes[34]) = encrypted_page;
	log_to_file("Set encrypted page value to: 0x%llX", encrypted_page);

	pool_party.set_bytes(_whitelist_page_p, function_bytes, 100);
	log_to_file("Set modified bytes back to function");

	log_to_file("Executing whitelist function...");
	pool_party.execute(_whitelist_page_p);
	log_to_file("Whitelist function executed");
};

void call_shellcode(PoolParty pool_party, PVOID address, PVOID mapping_data) {
	log_to_file("Calling shellcode at address: 0x%llX with mapping data: 0x%llX",
		(uintptr_t)address, (uintptr_t)mapping_data);

	PVOID _call_shellcode_p = pool_party.allocate(_call_shellcode_i);
	log_to_file("Allocated shellcode function at: 0x%llX", (uintptr_t)_call_shellcode_p);

	if (!_call_shellcode_p) {
		log_to_file("ERROR: Failed to allocate memory for shellcode function");
		return;
	}

	unsigned char* function_bytes = pool_party.get_bytes(_call_shellcode_p);
	if (!function_bytes) {
		log_to_file("ERROR: Failed to get function bytes");
		return;
	}

	log_to_file("Setting mapping data at offset 6");
	*(uintptr_t*)(&function_bytes[6]) = (uintptr_t)mapping_data;

	log_to_file("Setting address at offset 16");
	*(uintptr_t*)(&function_bytes[16]) = (uintptr_t)address;

	pool_party.set_bytes(_call_shellcode_p, function_bytes);
	log_to_file("Set modified bytes back to function");

	log_to_file("Executing shellcode function...");
	pool_party.execute(_call_shellcode_p);
	log_to_file("Shellcode function executed");
};