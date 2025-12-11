# 🛡️ Valkyrie  
**A modern, stealthy kernel-driver mapper for Windows x64.**

[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue?style=flat-square&logo=windows)](https://microsoft.com/windows)
[![C++](https://img.shields.io/badge/C%2B%2B-20-blue?style=flat-square&logo=c%2B%2B)](https://isocpp.org)
[![Kernel](https://img.shields.io/badge/Level-Kernel-red?style=flat-square)](https://docs.microsoft.com/windows-hardware)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Work%20in%20Progress-yellow?style=flat-square)](https://github.com/Parad0x141/Valkyrie)


## 📌 Description  
Valkyrie is a **stealthy, unsigned kernel-driver mapper** for Windows 10/11 x64.  
It abuses a vulnerable Intel driver (`iqvw64e.sys`) to load code into ring 0, then scrubs every trace left behind (PiDDBCache, CI Hash Table, etc.).  
It is a **clean, feature-rich rewrite** of the well-known [KDMapper](https://github.com/TheCruZ/kdmapper) by TheCruz, huge thanks to him for sharing his work.

---

## ⚠️ Warning  
**Educational & research use only.**  
Malicious or unauthorized use is **strictly forbidden**.  
The author **assumes no liability** for misuse.

---

## 🧪 Features  

### ✅ Map Unsigned Drivers  
Loads any `.sys` file **without a valid signature** into kernel space.  
No Service Control Manager, no trace in the registry.  
<!-- Screenshot: driver mapped in WinDbg -->

---

### 🔧 Runtime x64 Hook Generation  
No static shellcode.  
Valkyrie **generates polymorphic hooks** at runtime to call kernel functions.  
<!-- Screenshot: X64Assembler::PolymorphicHook in action -->

---
🧬 Syscall Gate Randomization (Coming soon)

No hard-coded gateway.
Valkyrie picks a random export from a curated list of safe, low-noise ntoskrnl routines, patches its prologue on-the-fly, and funnels execution through it.
<!-- Screenshot: CallKernelFunction with random chosen export -->
---

### 🧹 Forensics Wipe  
After mapping, Valkyrie **scrubs every trace** left behind :  
- **PiDDBCache** – unlinks driver entry from AVL table  
- **CI Hash Table** – removes hash bucket entry  
- **MmUnloadedDrivers** – zeroes UNICODE_STRING and buffer  
<!-- Screenshot: volatility / rekall showing empty tables -->

---

### 🧠 PE-Aware Mapping  
Handles :  
- **Relocations** (IMAGE_REL_BASED_DIR64)  
- **Imports** (kernel exports resolved at runtime)  
- **Security Cookies** (GS stack protection reinitialized)  
- **Section permissions** (RX, RW, RWX applied correctly)

---

### 🎯 One-Shot Mode  
Use `--freeMemory` or `-fm` to **map → call → unload → wipe** in a single pass.  
Perfect for **ephemeral payloads**, **no persistence**, **no memory leak**.  
<!-- Screenshot: console output with --freeMemory flag -->
---
### 🛡️ Patch-Guard Safe  
Valkyrie **never modifies kernel code or critical structures**.  
All hooks are **temporary**, **restored immediately**, and **never target Patch-Guard-protected regions**.  
No CR3, no IDT, no MSR, no KPP triggers.
---

## 🧰 Requirements  
- Windows 10/11 x64  
- Administrator privileges  
- Visual Studio (C++20)  
- Windows 10/11 SDK
- Vulnerable Driver Blocklist disabled
- `ntdll.lib`, `dbghelp.lib`

---

## 🛠️ Build  
```bash
git clone https://github.com/Parad0x141/Valkyrie.git
cd Valkyrie
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

## 🧪 Usage  

📁 Drag & Drop (fastest)
Drop any .sys file onto Valkyrie.exe & follow the prompt, it will map your driver and wipe every traces of the vulnerable driver.
By default the mapped driver stays persistent, the mapper uses all anti-forensics capabilities, and scrambles headers. See below to change mapper behavior.

---

### 🖥️ Command Line (full control)  
```bash
Valkyrie.exe [options] MyDriver.sys
| Option               | Short flag  | Description                                         |
| -------------------- | ----------- | --------------------------------------------        |
| `--help`             | `-h`        | Show help                                           |
| `--driverInfo`       | `-di`       | Display PE metadata before mapping                  |
| `--noStealth`        | `-nost`     | Skip PiDDB/CI/MmUnloadedDrivers cleanup             | 
| `--freeMemory`       | `-fm`       | One-shot mode: map → call entry point → free → exit |
| `--noHeaderScramble` | `-nosc`     | Keep original PE header (no junk overwrite)         |
| `--deepWipe`         | `-dw`       | Overwrite ex-driver memory with safe opcodes        |
```
---

## 📁 Project Layout  
-----------------------------------------------------------
|         File         |             Purpose              |
|----------------------|-----------------------------------
| `IntelLoader.cpp`    | Load vulnerable Intel driver     |
| `Helpers.cpp`        | Internal tools functions         |
| `PatternScanner.cpp` | Signature scanning engine        |
| `ValkyrieMapper.cpp` | Core mapping engine              |
| `StealthKit.cpp`     | Anti-forensics & trace removal   |
| `Resolver.cpp`       | Offsets resolver                 |
| `PEUtils.cpp`        | PE parsing & validation          |
| `PDBParser.cpp`      | Symbol resolution via PDB        |
| `X64Assembler.hpp`   | Runtime x64 shellcode generator  |
| `Main.cpp`           | Entry point                      |
-----------------------------------------------------------

## 🧠 Credits  
- **Cyril “Parad0x141” Bouvier** 
- **TheCruZ** – original idea ([KDMapper](https://github.com/TheCruZ/kdmapper))

---

## 📄 License  
[MIT](LICENSE) – free for lawful use.

---

## 🤝 Contributing  
Issues & PRs welcome.  
---

## 📬 Contact  
GitHub: [@Parad0x141](https://github.com/Parad0x141)

---

⭐ **Star the repo if you like it!**
