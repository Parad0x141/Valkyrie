#pragma once

#pragma warning(disable : 4005) // macro redefinition

#define NOMINMAX // Avoid min/max redef by Windows.h


// Standard libs
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include <mutex>

#include <winternl.h>
#include <io.h>           
#include <fcntl.h>        
#include <memory>
#include <fstream>
#include <stdexcept>
#include <algorithm>


// Internal 
#include "ValkStatus.hpp"
#include "X64Assembler.hpp"
#include "Helper.hpp"
#include "IntelLoader.hpp"
#include "PEUtils.hpp"
#include "StealthKit.hpp"


// External
#include "../Valkyrie/External/RANG/rang.hpp"

inline std::mutex& GetValkyrieLogMutex() 
{
    static std::mutex logMutex;
    return logMutex;
}



#define LOG_SUCCESS(...) \
    do { \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex()); \
        std::cout << rang::fgB::green << "[Valkyrie] [+] " << rang::style::reset; \
        std::wcout << __VA_ARGS__ << L'\n' << std::flush; \
    } while(0)


#define LOG_ERROR(...) \
    do { \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex()); \
        std::cout << rang::fgB::red << "[Valkyrie] [-] " << rang::style::reset; \
        std::wcerr << __VA_ARGS__ << L'\n' << std::flush; \
    } while(0)

#define LOG_SUCCESS_HEX(fmt, val) \
    do { \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex()); \
        auto _saved_flags = std::cout.flags(); \
        std::cout << rang::fgB::green << "[Valkyrie] [+]  " << rang::style::reset \
                  << fmt << " 0x" << std::hex << val << '\n'; \
        std::cout.flush(); \
        std::cout.flags(_saved_flags); \
    } while(0)

#define LOG_ERROR_HEX(fmt, val) \
    do { \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex()); \
        auto _saved_flags = std::cout.flags(); \
        std::cout << rang::fgB::red << "[Valkyrie] [-] " << rang::style::reset \
                  << fmt << " 0x" << std::hex << val << '\n'; \
        std::cout.flush(); \
        std::cout.flags(_saved_flags); \
    } while(0)

#define LOG_ERROR_ANSI(fmt, ...) \
    do { \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex()); \
        std::cout << rang::fgB::red << "[-] " << rang::style::reset; \
        printf(fmt, __VA_ARGS__); \
        std::cout << '\n' << std::flush; \
    } while(0)

#if VERBOSE_DEBUG
#define LOG_DEBUG(...) \
    do { \
        if (Valkyrie::IsDebugEnabled()) { \
            std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex()); \
            std::cout << rang::fgB::cyan << "[Valkyrie] [DEBUG] " << rang::style::reset; \
            std::wcout << __VA_ARGS__ << L'\n' << std::flush; \
        } \
    } while(0)

#define LOG_DEBUG_HEX(fmt, val) \
    do { \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex()); \
        auto _saved_flags = std::cout.flags(); \
        std::cout << rang::fgB::cyan << "[DEBUG] " << rang::style::reset; \
        std::wcout << std::hex << fmt << L" 0x" << val << L'\n'; \
        std::wcout.flush(); \
        std::wcout.flags(_saved_flags); \
    } while(0)

#define LOG_DEBUG_ANSI(fmt, ...) \
    do { \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex()); \
        char _buf[512]; \
        snprintf(_buf, sizeof(_buf), fmt, __VA_ARGS__); \
        std::cout << rang::fgB::cyan << "[DEBUG] " << rang::style::reset \
                  << std::wstring(_buf, _buf + strlen(_buf)) << L'\n' << std::flush; \
    } while(0)

#else
#endif


#define LOG_OPERATION(op, result) \
    do { \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex()); \
        std::cout << rang::fgB::magenta << "[Valkyrie] [*]" << rang::fgB::yellow << rang::style::reset; \
        std::wcout << op << L" -> " << result << L'\n' << std::flush; \
    } while(0)