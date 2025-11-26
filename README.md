# 🛡️ Valkyrie  
**A modern, stealthy kernel-driver mapper for Windows x64.**

[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue?style=flat-square&logo=windows)](https://microsoft.com/windows)
[![C++](https://img.shields.io/badge/C%2B%2B-20-blue?style=flat-square&logo=c%2B%2B)](https://isocpp.org)
[![Kernel](https://img.shields.io/badge/Level-Kernel-red?style=flat-square)](https://docs.microsoft.com/windows-hardware)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Work%20in%20Progress-yellow?style=flat-square)](https://github.com/Parad0x141/Valkyrie)

---

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
- Map **unsigned** `.sys` drivers  
- Full trace cleanup:  
  – PiDDBCache  
  – CI Hash Table  
  – MmUnloadedDrivers  
- Handles relocations, imports, security cookies  
- Runtime x64 hook generation  
- Windows 10/11 x64 support (builds 1803 → 24H2)

---

## 🧰 Requirements  
- Windows 10/11 x64  
- Administrator privileges  
- Visual Studio 2022 (C++20)  
- Windows 10/11 SDK
- Vulnerable Driver Blocklist disabled (Will be auto-disabled by Valkyrie in the next update)
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
For now, the driver path is hardcoded for this early release, so drop the driver you want to map here:  
`C:\HelloWorld.sys`  

A simple Hello World driver is provided in the repo for you convenience.

Run `Valkyrie.exe` **as Administrator**.

---

## 📁 Project Layout  
| File | Purpose |
|---|---|
| `IntelLoader.cpp` | Load vulnerable Intel driver |
| `ValkyrieMapper.cpp` | Core mapping engine |
| `StealthKit.cpp` | Anti-forensics & trace removal |
| `PEUtils.cpp` | PE parsing & validation |
| `PDBParser.cpp` | Symbol resolution via PDB |
| `X64Assembler.hpp` | Runtime x64 shellcode generator |
| `Main.cpp` | Entry point |

## 🧠 Credits  
- **Cyril “Parad0x141” Bouvier** 
- **TheCruZ** – original idea ([KDMapper](https://github.com/TheCruZ/kdmapper))

---

## 📄 License  
[MIT](LICENSE) – free for lawful use.

---

## 🤝 Contributing  
Issues & PRs welcome.  
Please follow the [code of conduct](CODE_OF_CONDUCT.md).

---

## 📬 Contact  
GitHub: [@Parad0x141](https://github.com/Parad0x141)

---

⭐ **Star the repo if you like it!**
