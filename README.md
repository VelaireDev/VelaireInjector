
# RMMInject

**RMMInject** (Roblox Manual Map Injector) is a robust manual-mapping injection method for Roblox, developed to bypass the AMDXX64.dll patch. It provides a seamless and efficient way to inject DLLs into Roblox. **RMMInject** is open-source and written in C++.

---

**UPDATE!**

I have fixed all issues in the old RMMInject new injector should work as advertised!

---

### ⚠️ **Troubleshooting**

If Roblox crashes after injection, it's likely due to incorrect offsets for the following parameters:

- `SCF_INSERTED_JMP`
- `SCF_END_MARKER`
- `PAGE_ENCRYPTION_KEY`
- `SCF_MARKER_STK`
- `kPageMask`
- `kPageShift`
- `kPageHash`
- `InsertSet`
- `WhitelistedPages`
  
These offsets are subject to change with updates, so always ensure you have the correct values.

---

### 📜 **Current Offsets**

```cpp
//updated offsets for version-1e91b4133e334c9c!

namespace Offsets
{
    // No need to update these, they dont fucking change
    constexpr uint16_t SCF_INSERTED_JMP = 0x04EB;
    constexpr uint32_t SCF_END_MARKER = 0xF4CC02EB;
    constexpr uintptr_t SCF_MARKER_STK = 0xDEADBEEFDEADC0DE;
    constexpr uint64_t kPageMask = 0xfffffffffffff000;
    constexpr uint8_t kPageShift = 0xc;

    // These offsets change every update be warned!
    constexpr uint64_t kPageHash = 0x84B3A57D90E73527;
    constexpr uint64_t Offset_InsertSet = 0xC43D00;
    constexpr uint64_t Offset_WhitelistedPages = 0x29C758;
}
```

---

### 🔧 **Setup & Usage**

1. **Compile**: Build the project in your preferred IDE or use a tool like Visual Studi | **MAKE SURE BUILD IS SET TO Release x64**
3. **Ensure Correct Offsets**: If you encounter crashes, verify that the offsets are up to date.

---

### 📝 **Contributing**

Feel free to contribute by updating offsets or adding new features. Pull requests are welcome!

---
