#pragma once

#include "XorLog.hpp"
#include "Stringtable.hpp"
#include <filesystem>
#include <string>




struct Args
{
    std::wstring driverPath;
    std::wstring DriverName() const;

    bool help = false;
    bool showDriverInfo = false;
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
    bool test = false;

    XLOG_INFO(StringTable::ARGS_USAGE);
    XLOG_INFO(StringTable::ARGS_OPTIONS);
    JumpLine();

    XLOG_INFO(XorLog::DecodeSv(XorLog::Logger::HELLOWORLD));
    
    XLOG_INFO(StringTable::ARGS_HELP);
    XLOG_INFO(StringTable::ARGS_NO_STEALTH);
    XLOG_INFO(StringTable::ARGS_FREE_MEM);
    XLOG_INFO(StringTable::ARGS_NO_HEADER_SCRAMBLE);
    XLOG_INFO(StringTable::ARGS_DEEP_WIPE);
}

Args ParseArgs(int argc, wchar_t* argv[])
{
    Args a;

    struct Flag { const wchar_t* longFlag; const wchar_t* shortFlag; bool* target; };
   
    static Flag flags[] = {
        { L"--help",               L"-h",      &a.help},
        { L"--driverInfo",         L"-di",     &a.showDriverInfo},
        { L"--noStealth",          L"-nost",   &a.noStealth},
        { L"--noHeaderScramble",   L"-nosc",   &a.noHeaderScramble},
        { L"--freeMemory",         L"-fm",     &a.freeMemory},
        { L"--deepWipe",           L"-dw",     &a.deepWipe},
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
            XLOG_ERROR(StringTable::ARGS_UNKNOWN_FLAG), WStringToString(arg);
            a.help = true; return a;
        }
        if (!a.driverPath.empty())
        {
            XLOG_ERROR(StringTable::ARGS_EXTRA_ARG), WStringToString(arg);
            a.help = true; return a;
        }
        a.driverPath = arg;
    }

    if (a.driverPath.empty() && !a.help)
    {

        XLOG_ERROR(StringTable::ARGS_NO_DRIVER), WStringToString(a.driverPath);
        JumpLine();

        a.help = true;
    }


    return a;
}