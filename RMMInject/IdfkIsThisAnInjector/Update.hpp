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

	// update these mf they change every update (usually)
    constexpr uint64_t kPageHash = 0x84B3A57D90E73527;
    constexpr uint64_t Offset_InsertSet = 0xC43D00;
    constexpr uint64_t Offset_WhitelistedPages = 0x29C758;
}
