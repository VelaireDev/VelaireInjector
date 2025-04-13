#include <iostream>
#include <libloaderapi.h>

typedef void(__stdcall* print_t)(int, const char*);
typedef void(__stdcall* set_insert_t)(void*, void*, void*);

const uintptr_t SET_INSERT = 0x1669850;
const uintptr_t WHITELISTED_PAGES = 0x253430;
const uintptr_t PAGE_ENCRYPTION_KEY = 0x699350d3a7625727;

inline void whitelist_page_i() {
	uintptr_t hyperion_base = (uintptr_t)GetModuleHandleA("RobloxPlayerBeta.dll");
	set_insert_t set_insert = (set_insert_t)(hyperion_base + SET_INSERT);

	void* whitelisted_pages = (void*)(hyperion_base + WHITELISTED_PAGES);
	void* unused = nullptr;
	void* page = (void*)0x699350d3a7625727;

	set_insert(whitelisted_pages, &unused, &page);

	while (true) {};
};

inline uintptr_t encrypt_page(uintptr_t page_address) {
	return (((page_address & 0xFFFFFFFFFFFFF000) >> 0xC) ^ PAGE_ENCRYPTION_KEY);
};