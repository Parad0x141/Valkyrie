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

    XorLog::Logger::Info(StringTable::ARGS_USAGE);
    XorLog::Logger::Info(StringTable::ARGS_OPTIONS);
    JumpLine();

    XorLog::Logger::Debug(XorLog::Decrypt(XorLog::Logger::HELLOWORLD));
    
    XorLog::Logger::Info(StringTable::ARGS_HELP);
    XorLog::Logger::Info(StringTable::ARGS_NO_STEALTH);
    XorLog::Logger::Info(StringTable::ARGS_FREE_MEM);
    XorLog::Logger::Info(StringTable::ARGS_NO_HEADER_SCRAMBLE);
    XorLog::Logger::Info(StringTable::ARGS_DEEP_WIPE);
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
            // LOG_ERROR(L"Unknown flag : " << arg << L"  (see -h)");
            XorLog::Logger::Error(StringTable::ARGS_UNKNOWN_FLAG), WStringToString(arg);
            a.help = true; return a;
        }
        if (!a.driverPath.empty())
        {
           // LOG_ERROR(L"Extra argument : " << arg);
            XorLog::Logger::Error(StringTable::ARGS_EXTRA_ARG), WStringToString(arg);
            a.help = true; return a;
        }
        a.driverPath = arg;
    }

    if (a.driverPath.empty() && !a.help)
    {

        XorLog::Logger::Error(StringTable::ARGS_NO_DRIVER), WStringToString(a.driverPath);
        JumpLine();

        a.help = true;
    }


    return a;
}