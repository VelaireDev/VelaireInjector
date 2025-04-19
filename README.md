
# RMMInject

**RMMInject** (Roblox Manual Map Injector) is a robust manual-mapping injection method for Roblox, developed to bypass the AMDXX64.dll patch. It provides a seamless and efficient way to inject DLLs into Roblox. **RMMInject** is open-source and written in C++.

---

### ⚠️ **Troubleshooting**

If Roblox crashes after injection, it's likely due to incorrect offsets for the following parameters:

- `SET_INSERT`
- `WHITELISTED_PAGES`
- `PAGE_ENCRYPTION_KEY`
- `kPageHash`
- `kPageMask`
- `kPageShift`
- `RBXPRINT`

These offsets are subject to change with updates, so always ensure you have the correct values.

---

### 📜 **Current Offsets**

```cpp
//updated offsets for version-1e91b4133e334c9c!

constexpr uint64_t kPageHash = 0x84B3A57D90E73527; // Changed again due to update...
constexpr uint64_t kPageMask = 0xfffffffffffff000; // Same as before...
constexpr uint8_t  kPageShift = 0xc; // Same as before...

constexpr uint64_t Offset_InsertSet = 0xC43D00; // Changed again due to update...
constexpr uint64_t Offset_WhitelistedPages = 0x29C758; // Changed again due to update...
```

---

### 🔧 **Setup & Usage**

1. **Compile**: Build the project in your preferred IDE or use a tool like Visual Studio.
3. **Ensure Correct Offsets**: If you encounter crashes, verify that the offsets are up to date.

---

### 📝 **Contributing**

Feel free to contribute by updating offsets or adding new features. Pull requests are welcome!

---

_**CREDITS**_

Full credit goes to nbeater678 for creating the original foundation of this injection method. My version simply expands on it by adding enhanced logging to support further development and debugging. Be sure to thank him for this method — not me!

---
