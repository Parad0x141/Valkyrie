#pragma once

#include "Common.hpp"
#include "IntelDriver.hpp"
#include <chrono>



BOOL IsAdmin();
BOOL WriteDriver();
BOOL DeleteDriverFile();
VOID PrintSyscalls();

uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
std::string FormatHex(uint64_t value);
std::string GetCurrentTimestamp();
ULONG GetIntelTimeStamp();
ULONG GetPETimeStamp(const std::wstring& path);