#pragma once
#include <array>
#include <string>
#include <iostream>
#include <sstream>

namespace XorLog {

   
    template<std::size_t N>
    struct Encrypted 
    {
        std::array<char, N> data{};
        constexpr Encrypted() = default;
    };

    template<std::size_t N>
    constexpr auto Encrypt(const char(&plain)[N]) noexcept {
        Encrypted<N> e{};
        for (std::size_t i = 0; i < N; ++i)
            e.data[i] = plain[i] ^ static_cast<char>(i + 1);
        return e;
    }

    template<std::size_t N>
    inline std::string Decrypt(const Encrypted<N>& e) {
        std::array<char, N> buf = e.data;
        for (std::size_t i = 0; i < N; ++i)
            buf[i] ^= static_cast<char>(i + 1);
        return { buf.data(), N - 1 };
    }


#define XSTR(s) XorLog::Decrypt(XorLog::Encrypt(s))


    enum Color {
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
        static constexpr auto PREFIX = Encrypt("[Valkyrie] ");
        static constexpr auto TAG_SUCC = Encrypt("[+] ");
        static constexpr auto TAG_WARN = Encrypt("[!] ");
        static constexpr auto TAG_ERR = Encrypt("[-] ");
        static constexpr auto TAG_DBG = Encrypt("[*] ");

    public:
        template<typename... Args>
        static void Success(Args&&... args)
        {
            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Green);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_SUCC) << oss.str() << '\n';
            ResetColor();
        }

        template<typename... Args>
        static void Warning(Args&&... args)
        {
            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Yellow);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_WARN) << oss.str() << '\n';
            ResetColor();
        }

        template<typename... Args>
        static void Error(Args&&... args) 
        {
            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Red);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_ERR) << oss.str() << '\n';
            ResetColor();
        }

        template<typename... Args>
        static void Debug(Args&&... args) 
        {
            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Magenta);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_DBG) << oss.str() << '\n';
            ResetColor();
        }
    };

} // namespace XorLog

