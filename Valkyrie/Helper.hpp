#pragma once
#define NOMINMAX // Avoid min/max redef by Windows.h
#include <Windows.h>
#include <string>
#include <cstdint>




BOOL IsAdmin();
BOOL WriteDriverFile();
BOOL DeleteDriverFile();
BOOL ConfirmYesNo(const std::wstring& question);

PVOID GetNtdllFuncPtr(const char* functioName);
VOID EnumerateSyscalls();
VOID DumpBytes(const char* name, const uint8_t* bytes, size_t len);


std::string FormatHex(uint64_t value);
std::string GetCurrentTimestamp();
std::string WStringToString(const std::wstring& w);
ULONG GetPETimeStamp(const std::wstring& path);
std::wstring FormatHexWString(uint64_t v);