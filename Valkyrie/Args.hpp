#pragma once

#include "Common.hpp"
#include <filesystem>

struct Args
{
    std::wstring driverPath;
    std::wstring DriverName() const;

    bool help = false;
    bool noStealth = false;
    bool noHeaderScramble = false;
    bool freeMemory = false;
    bool deepWipe = false;
};

std::wstring Args::DriverName() const
{
    if (driverPath.empty()) return L"";
    return std::filesystem::path(driverPath).filename().wstring();
}

Args ParseArgs(int argc, wchar_t* argv[]);


// Auto doc
static void PrintHelp()
{
    LOG_WARNING(L"Usage: Valkyrie.exe [options] <MyEvilDriver.sys>");
    LOG_WARNING(L"Options :");
    LOG_INFO(L"  -h  --help           Show this help");
    LOG_INFO(L"  -n  --noStealth      Do not erase Intel driver traces after mapping (Only delete driver file)");
    LOG_INFO(L"  -f  --freeMemory     Free memory after driver entry call (One-shot driver)");
    LOG_INFO(L"  -s  --scrambleHeader Scramble PE headers before mapping");
    LOG_INFO(L"  -d  --deepWipe       Write random safes opcodes in previously allocated driver memory");
}

Args ParseArgs(int argc, wchar_t* argv[])
{
    Args a;

    struct Flag { const wchar_t* longFlag; const wchar_t* shortFlag; bool* target; };
   
    static Flag flags[] = {
        { L"--help",               L"-h", &a.help},
        { L"--noStealth",          L"-nost", &a.noStealth},
        { L"--noHeaderScramble",   L"-nosc", &a.noHeaderScramble},
        { L"--freeMemory",         L"-f", &a.freeMemory},
        { L"--deepWipe",           L"-d", &a.deepWipe},
    };

    for (int i = 1; i < argc; ++i)
    {
        const std::wstring arg = argv[i];

        bool found = false;

        for (const auto& f : flags)
        {
            if (arg == f.longFlag || arg == f.shortFlag) { *f.target = true; found = true; break; }
        }
        if (found) continue;

        if (arg == L"/?" || arg == L"-?") { a.help = true; continue; }

        if (arg.starts_with(L"-"))
        {
            LOG_ERROR(L"Unknown flag : " << arg << L"  (see -h)");
            a.help = true; return a;
        }
        if (!a.driverPath.empty())
        {
            LOG_ERROR(L"Extra argument : " << arg);
            a.help = true; return a;
        }
        a.driverPath = arg;
    }

    if (a.driverPath.empty() && !a.help)
    {
        LOG_ERROR(L"No driver file provided");
        a.help = true;
    }


    if (!a.driverPath.empty())
    {
        if (!std::filesystem::exists(a.driverPath))
        {
            LOG_ERROR(L"File not found : " << a.driverPath);
            a.help = true;
        }
        else if (!a.driverPath.ends_with(L".sys"))
            LOG_WARNING(L"Extension not .sys, continue anyway");
    }

    return a;
}