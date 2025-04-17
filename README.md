
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
//Semi updated offsets for version-b83d92f2144a48e2!

constexpr uint64_t kPageHash = 0x8bae0aa10c9180a4; // Still looking for this offset (RMM may still work)
constexpr uint64_t kPageMask = 0xFFFFFFFFFFFFF000;
constexpr uint8_t  kPageShift = 0xC;

constexpr uint64_t Offset_InsertSet = 0xcea020; // Changed due to Roblox updating...
constexpr uint64_t Offset_WhitelistedPages = 0x2d3a48 ; // Changed due to Roblox updating...
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
