
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
constexpr uint64_t kPageHash = 0x8bae0aa10c9180a4; // This may change with updates
constexpr uint64_t kPageMask = 0xFFFFFFFFFFFFF000;
constexpr uint8_t  kPageShift = 0xC;

constexpr uint64_t Offset_InsertSet = 0xdca3c0; // This may change with updates
constexpr uint64_t Offset_WhitelistedPages = 0x2a5028; // This may change with updates
constexpr uint64_t Offset_RBXPRINT = 0x1631640; // This may change with updates
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

Full credit goes to nbeater678 for creating the original foundation of this injection method. My version sinmply expands on it by adding enhanced logging to support further development and debugging. Be sure to thank him for this method — not me!

---
