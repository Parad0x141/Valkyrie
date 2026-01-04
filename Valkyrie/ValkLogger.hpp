#include <iostream>
#include <mutex>
#include <array>



// Colored output
#include "../Valkyrie/External/RANG/rang.hpp"

static std::mutex& GetValkyrieLogMutex()
{
	static std::mutex m;
	return m;
}

static void JumpLine()
{
    std::wcout << "\n";
}



#define LOG_SUCCESS(...)                                             \
    do {                                                             \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex());    \
        std::cout << rang::fgB::green <<"[Valkyrie] [+] "<< rang::style::reset; \
        std::wcout << __VA_ARGS__ << L'\n' << std::flush;            \
    } while (0)

#define LOG_INFO(...)                                                                 \
    do {                                                                              \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex());                     \
        std::cout << rang::fgB::blue << "[Valkyrie] [i] "<< rang::style::reset;        \
        std::wcout << __VA_ARGS__ << L'\n' << std::flush;                             \
    } while (0)

#define LOG_INFO_HEX(fmt, val)                                                         \
    do {                                                                               \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex());                      \
        auto _saved_flags = std::cout.flags();                                         \
        std::cout << rang::fgB::blue << "[Valkyrie] [i] " << rang::style::reset         \
                  << fmt << " 0x" << std::hex << val << '\n';                          \
        std::cout.flush();                                                             \
        std::cout.flags(_saved_flags);                                                 \
    } while (0)

#define LOG_ERROR(...)                                                                 \
        do {                                                                           \
            std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex());                  \
            std::cout << rang::fgB::red << "[Valkyrie] [-] " << rang::style::reset;     \
            std::wcerr << __VA_ARGS__ << L'\n' << std::flush;                          \
        } while (0)


#define LOG_WARNING(...)                                                               \
        do {                                                                           \
            std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex());                  \
            std::cout << rang::fgB::yellow << "[Valkyrie] [!] " << rang::style::reset;  \
            std::wcout << __VA_ARGS__ << L'\n' << std::flush;                          \
        } while (0)

#define LOG_SUCCESS_HEX(fmt, val)                                                      \
        do {                                                                           \
            std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex());                  \
            auto _saved_flags = std::cout.flags();                                     \
            std::cout << rang::fgB::green << "[Valkyrie] [+] " << rang::style::reset    \
                      << fmt << " 0x" << std::hex << val << '\n';                      \
            std::cout.flush();                                                         \
            std::cout.flags(_saved_flags);                                             \
        } while (0)


#define LOG_ERROR_HEX(fmt, val)                                                        \
        do {                                                                           \
            std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex());                  \
            auto _saved_flags = std::cout.flags();                                     \
            std::cout << rang::fgB::red << "[Valkyrie] [-] " << rang::style::reset      \
                      << fmt << " 0x" << std::hex << val << '\n';                      \
            std::cout.flush();                                                         \
            std::cout.flags(_saved_flags);                                             \
        } while (0)

#define LOG_DEBUG(...)                                                                 \
      do {                                                                             \
        std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex());                      \
        std::cout << rang::fgB::magenta << "[Valkyrie] [D] " << rang::style::reset;     \
        std::wcout << __VA_ARGS__ << L'\n' << std::flush;                              \
      } while (0)

#define LOG_ERROR_ANSI(fmt, ...)                                                       \
        do {                                                                           \
            std::lock_guard<std::mutex> _lock(GetValkyrieLogMutex());                  \
            std::cout << rang::fgB::red << "[-]" << rang::style::reset;                \
            printf(fmt, __VA_ARGS__);                                                  \
            std::cout << '\n' << std::flush;                                           \
        } while (0)

