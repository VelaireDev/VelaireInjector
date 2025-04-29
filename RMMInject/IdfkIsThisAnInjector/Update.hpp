#pragma once
#include "Windows.h"

namespace Offsets
{
	// no need to update these lol they dont rlly change
	constexpr uint16_t SCF_INSERTED_JMP = 0x04EB;
	constexpr uint32_t SCF_END_MARKER = 0xF4CC02EB;
	constexpr uintptr_t SCF_MARKER_STK = 0xDEADBEEFDEADC0DE;
	constexpr uint64_t kPageMask = 0xfffffffffffff000;
	constexpr uint8_t kPageShift = 0xc;

	// they get updated every update. I am probally going to make it pull from a public repo on VelaireDev when the dll is finished
    constexpr uint64_t kPageHash = 0x5f9213b9;
    constexpr uint64_t Offset_InsertSet = 0xB57060;
    constexpr uint64_t Offset_WhitelistedPages = 0x2A86A0;
}
