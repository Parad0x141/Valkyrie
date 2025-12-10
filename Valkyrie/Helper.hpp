#pragma once

#include "Common.hpp"
#include "IntelDriver.hpp"
#include "PEUtils.hpp"
#include <chrono>



BOOL IsAdmin();
BOOL WriteDriverFile();
BOOL DeleteDriverFile();
BOOL ConfirmYesNo(const std::wstring& question);

PVOID GetNtdllFuncPtr(const char* functioName);
VOID EnumerateSyscalls();
VOID DumpBytes(const char* name, const uint8_t* bytes, size_t len);


uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
std::string FormatHex(uint64_t value);
std::string GetCurrentTimestamp();
std::string WStringToString(const std::wstring& w);
ULONG GetPETimeStamp(const std::wstring& path);
std::wstring ToHexW(uint64_t v);