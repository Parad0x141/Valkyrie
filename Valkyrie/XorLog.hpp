#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <array>
#include <string_view>
#include <string>
#include <iostream>
#include <sstream>
#include <cstdint>
#include <mutex>

// Simple XOR/shift obfuscation to avoid plain strings in binaries.


// In Decrypt():
// Excludes the null terminator from the final std::string

// In DecryptView():
// Optimized: Same as Decrypt() but uses string_view & thread-local storage to avoid heap allocations





// Macro to create compile-time encrypted strings (constexpr)
// 
// GOOD: inline constexpr auto GOOD = XSTR("GOOD");
// BAD:  const auto bad = XSTR("BAD"); // Must be constexpr!

// Deduced type is always Encrypted<N>, not const char*

// Example: inline constexpr auto S = XSTR("test");
// Type of S is Encrypted<5> (includes the null terminator)
#define XSTR(s) (XorLog::Encode(s))


// Lazy man macros
#define XLOG_INFO(...)    XorLog::Logger::Info(__VA_ARGS__)
#define XLOG_SUCCESS(...) XorLog::Logger::Success(__VA_ARGS__)
#define XLOG_ERROR(...)   XorLog::Logger::Error(__VA_ARGS__)
#define XLOG_WARNING(...) XorLog::Logger::Warning(__VA_ARGS__)
#define XLOG_DEBUG(...)   XorLog::Logger::Debug(__VA_ARGS__)

namespace XorLog {

    inline std::mutex& GetMutex()
    {
        static std::mutex mutex;
        return mutex;
    }
   
    template<std::size_t N>
    struct Encrypted 
    {
        std::array<char, N> data{};
    };



    constexpr uint64_t CompileTimeSeed() noexcept 
    {
        uint64_t seed = (__TIME__[7] - '0') +
            (__TIME__[6] - '0') * 10 +
            (__TIME__[4] - '0') * 100 +
            (__TIME__[3] - '0') * 1000 +
            (__TIME__[1] - '0') * 10000 +
            (__TIME__[0] - '0') * 100000;



        seed ^= (__DATE__[4] - '0') * 1000000ULL;
        seed ^= (__DATE__[0] + __DATE__[1] + __DATE__[2]) * 10000000ULL;

        return seed;
    }

    template<std::size_t N, uint64_t Seed = CompileTimeSeed()>
    constexpr auto Encode(const char(&plain)[N]) noexcept {
        Encrypted<N> e{};

        for (std::size_t i = 0; i < N; ++i) 
        {
            uint8_t key1 = static_cast<uint8_t>((Seed >> (i % 8)) & 0xFF);

            uint8_t key2 = static_cast<uint8_t>((i * 0x9E3779B1) ^ 0xAA); // 0x9E3779B1 = Golden ratio prime 

            uint8_t key3 = static_cast<uint8_t>(~i ^ ((i << 3) | (i >> 5)));

            e.data[i] = plain[i] ^ key1 ^ key2 ^ key3;
        }

        return e;
    }

    template<std::size_t N, uint64_t Seed = CompileTimeSeed()>
    inline std::string Decode(const Encrypted<N>& e) 
    {
        std::array<char, N> buf = e.data;

        for (std::size_t i = 0; i < N; ++i)
        {
            // Same algo, reversed.
            uint8_t key1 = static_cast<uint8_t>((Seed >> (i % 8)) & 0xFF);
            uint8_t key2 = static_cast<uint8_t>((i * 0x9E3779B1) ^ 0xAA);
            uint8_t key3 = static_cast<uint8_t>(~i ^ ((i << 3) | (i >> 5)));

            buf[i] ^= key1 ^ key2 ^ key3;
        }

        // Without the null terminato
        return { buf.data(), (N > 0 ? N - 1 : 0) };
    }



    // Optimized
    template<std::size_t N>
    inline std::string_view DecodeSv(const Encrypted<N>& e)
    {
        thread_local std::array<char, N> buf;   
        buf = e.data;                           

        constexpr uint64_t Seed = CompileTimeSeed();
        for (std::size_t i = 0; i < N; ++i)
        {
            uint8_t key1 = static_cast<uint8_t>((Seed >> (i % 8)) & 0xFF);
            uint8_t key2 = static_cast<uint8_t>((i * 0x9E3779B1) ^ 0xAA);
            uint8_t key3 = static_cast<uint8_t>(~i ^ ((i << 3) | (i >> 5)));

            buf[i] ^= key1 ^ key2 ^ key3;
        }

        return { buf.data(), (N > 0 ? N - 1 : 0) };
    }
    
    inline void EnableANSI()
    {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == INVALID_HANDLE_VALUE) return;

        DWORD dwMode = 0;
        if (!GetConsoleMode(hOut, &dwMode)) return;

        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }


    // ANSI color codes
    enum Color 
    {
        Green = 32,
        Red = 31,
        Blue = 34,
        Yellow = 33,
        Cyan = 36,
        Magenta = 35
    };

    inline void SetColor(Color c)
    {
        std::cout << "\033[" << c << "m";
    }

    inline void ResetColor() 
    {
        std::cout << "\033[0m";
    }

  

    class Logger 
    {
        // compile-time prefix & tags
        static constexpr auto PREFIX = Encode("[Valkyrie] ");

        static constexpr auto TAG_INFO = Encode("[i] ");
        static constexpr auto TAG_SUCC = Encode("[+] ");
        static constexpr auto TAG_WARN = Encode("[!] ");
        static constexpr auto TAG_ERR = Encode("[-] ");
        static constexpr auto TAG_DBG = Encode("[*] ");



    public:
        template<typename... Args>
        static void Success(Args&&... args)
        {
            std::lock_guard<std::mutex> lock(GetMutex());

            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Green);
            std::cout << DecodeSv(PREFIX) << DecodeSv(TAG_SUCC);
            ResetColor();
            std::cout << oss.str() << '\n';

        }

        template<std::size_t N, typename... Args>
        static void Success(const Encrypted<N>& encrypted, Args&&... args)
        {
            std::lock_guard<std::mutex> lock(GetMutex());

            std::ostringstream oss;
            oss << DecodeSv(encrypted);
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Green);
            std::cout << DecodeSv(PREFIX) << DecodeSv(TAG_SUCC);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<typename... Args>
        static void Info(Args&&... args)
        {
            std::lock_guard<std::mutex> lock(GetMutex());


            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Blue);
            std::cout << DecodeSv(PREFIX) << DecodeSv(TAG_INFO);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<std::size_t N, typename... Args>
        static void Info(const Encrypted<N>& encrypted, Args&&... args)
        {
            std::lock_guard<std::mutex> lock(GetMutex());


            std::ostringstream oss;
            oss << DecodeSv(encrypted);
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Blue);
            std::cout << DecodeSv(PREFIX) << DecodeSv(TAG_INFO);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<typename... Args>
        static void Warning(Args&&... args)
        {
            std::lock_guard<std::mutex> lock(GetMutex());


            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Yellow);
            std::cout << DecodeSv(PREFIX) << DecodeSv(TAG_WARN);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<std::size_t N, typename... Args>
        static void Warning(const Encrypted<N>& encrypted, Args&&... args)
        {

            std::lock_guard<std::mutex> lock(GetMutex());

            std::ostringstream oss;
            oss << DecodeSv(encrypted);
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Yellow);
            std::cout << DecodeSv(PREFIX) << DecodeSv(TAG_WARN);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<typename... Args>
        static void Error(Args&&... args)
        {

            std::lock_guard<std::mutex> lock(GetMutex());

            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Red);
            std::cout << DecodeSv(PREFIX) << DecodeSv(TAG_ERR);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<std::size_t N, typename... Args>
        static void Error(const Encrypted<N>& encrypted, Args&&... args)
        {
            std::lock_guard<std::mutex> lock(GetMutex());


            std::ostringstream oss;
            oss << DecodeSv(encrypted);
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Red);
            std::cout << DecodeSv(PREFIX) << DecodeSv(TAG_ERR);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<typename... Args>
        static void Debug(Args&&... args)
        {
            std::lock_guard<std::mutex> lock(GetMutex());


            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Magenta);
            std::cout << DecodeSv(PREFIX) << DecodeSv(TAG_DBG);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<std::size_t N, typename... Args>
        static void Debug(const Encrypted<N>& encrypted, Args&&... args)
        {
            std::lock_guard<std::mutex> lock(GetMutex());


            std::ostringstream oss;
            oss << DecodeSv(encrypted);
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Magenta);
            std::cout << DecodeSv(PREFIX) << DecodeSv(TAG_DBG);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        static constexpr auto HELLOWORLD = Encode("Hello XorLog !");

    };

} 




