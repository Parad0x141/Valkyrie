#include "Helper.hpp"
#include <filesystem>

#include <format>
#include <ios>

#include "PEUtils.hpp"
#include "IntelDriver.hpp"
#include <iomanip>
#include <Windows.h>

BOOL IsAdmin()
{
    BOOL admin = FALSE;
    PSID administratorsGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &administratorsGroup))
    {
        CheckTokenMembership(nullptr, administratorsGroup, &admin);
        FreeSid(administratorsGroup);
    }

    return admin == TRUE;
}


BOOL WriteDriverFile()
{
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    std::wstring driverPath = std::wstring(tempPath) + L"iqvw64e.sys";

    HANDLE hFile = CreateFileW(
        driverPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cout << "Warning: failed to create vulnerable driver file!\n";
        return FALSE;
    }

    DWORD bytesWritten = 0;
    BOOL isWritten = WriteFile(
        hFile,
        intel_driver_resource::driver,
        sizeof(intel_driver_resource::driver),
        &bytesWritten,
        nullptr
    );

    CloseHandle(hFile);

    if (!isWritten || bytesWritten != sizeof(intel_driver_resource::driver))
    {
        std::cout << "Warning: failed to write driver bytes!\n";
        return FALSE;
    }

    LOG_SUCCESS("Driver written to : " << driverPath );

    return TRUE;
}

BOOL ConfirmYesNo(const std::wstring& question)
{
    std::wcout << question << L" (y/n) : " << std::flush;
    wchar_t ans = L'n';
    std::wcin >> ans;
    std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');

    return (ans == L'y' || ans == L'Y');
}

PVOID GetNtdllFuncPtr(const char* functioName)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        LOG_ERROR("Error, unable to get ntdll.dll handle");
        return nullptr;
    }

    PVOID functionPtr = GetProcAddress(ntdll, functioName);
    if (!functionPtr)
    {
        LOG_ERROR("Error, unable to get function pointer to function : " << functioName);
        CloseHandle(ntdll);
        return nullptr;
    }

    return functionPtr;
}


VOID EnumerateSyscalls()
{
    std::string path = "C:\\Windows\\System32\\ntoskrnl.exe";

    auto pe = PEUtils::ParsePE(path);
    if (!pe)
    {
        LOG_ERROR("Error, cannot parse PE");
        return;
    }

    LOG_SUCCESS_HEX("Image size : ", pe->imageSize);
    LOG_SUCCESS_HEX("Sections : ", pe->sections.size());
    LOG_SUCCESS_HEX("Imports : ", pe->imports.size());
    LOG_SUCCESS_HEX("Exports : ", pe->exports.size());


    std::cout << "\n=== SYSCALLS ===\n";
    for (const auto& exp : pe->exports)
    {
        if (exp.isSyscall())
            std::cout << exp.exportName << "\n";
    }

    return;

}

void DumpBytes(const char* name, const uint8_t* bytes, size_t len)
{
    std::wstringstream oss;
    oss << std::hex << std::setfill(L'0');
    for (size_t i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<int>(bytes[i]) << L' ';

    LOG_SUCCESS(std::wstring(name, name + strlen(name)) << L" : " << oss.str());
}


ULONG GetPETimeStamp(const std::wstring& path)
{
    auto raw = PEUtils::ReadFileByte(path);
    if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return 0;
    auto dos = (PIMAGE_DOS_HEADER)raw.data();
    auto nt = (PIMAGE_NT_HEADERS64)(raw.data() + dos->e_lfanew);
    return nt->FileHeader.TimeDateStamp;
}


BOOL DeleteDriverFile()
{
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring driverPath = std::wstring(tempPath) + L"iqvw64e.sys";

    if (DeleteFileW(driverPath.c_str()))
    {
        LOG_SUCCESS("Driver file deleted successfully.");
        return TRUE;
    }
    else
    {
        std::wcerr << L"[-] Failed to delete driver. Error: " << GetLastError() << L"\n";
        return FALSE;
    }
}


std::string FormatHex(uint64_t value)
{
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << value;
    return ss.str();
}


std::string GetCurrentTimestamp()
{
    auto now = std::chrono::system_clock::now();
    return std::format("{:%Y-%m-%d %H:%M:%S}", now);
}

std::string WStringToString(const std::wstring& w)
{
    return std::filesystem::path(w).string();
}

std::wstring FormatHexWString(uint64_t v) { return L"0x" + std::to_wstring(v); }
