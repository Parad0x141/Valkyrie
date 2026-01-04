#pragma once
#include <array>
#include <string>
#include <iostream>
#include <sstream>
#include <cstdint>


// Compile time XOR, 0 overhead runtime.


namespace XorLog {

   
    template<std::size_t N>
    struct Encrypted 
    {
        std::array<char, N> data{};
    };


    // This should be nice enough
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
    constexpr auto Encrypt(const char(&plain)[N]) noexcept {
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
    inline std::string Decrypt(const Encrypted<N>& e) {
        std::array<char, N> buf = e.data;

        for (std::size_t i = 0; i < N; ++i)
        {
            // Same algo, reversed.
            uint8_t key1 = static_cast<uint8_t>((Seed >> (i % 8)) & 0xFF);
            uint8_t key2 = static_cast<uint8_t>((i * 0x9E3779B1) ^ 0xAA);
            uint8_t key3 = static_cast<uint8_t>(~i ^ ((i << 3) | (i >> 5)));

            buf[i] ^= key1 ^ key2 ^ key3;
        }

        return { buf.data(), N - 1 };
    }



    // ANSI color codes
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

  
#define XSTR(s) (XorLog::Encrypt(s))

    class Logger 
    {
        // compile-time prefix & tags
        static constexpr auto PREFIX = Encrypt("[Valkyrie] ");

        static constexpr auto TAG_INFO = Encrypt("[i] ");
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
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_SUCC);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<std::size_t N, typename... Args>
        static void Success(const Encrypted<N>& encrypted, Args&&... args)
        {
            std::ostringstream oss;
            oss << Decrypt(encrypted);
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Green);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_SUCC);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<typename... Args>
        static void Info(Args&&... args)
        {
            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Blue);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_INFO);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<std::size_t N, typename... Args>
        static void Info(const Encrypted<N>& encrypted, Args&&... args)
        {
            std::ostringstream oss;
            oss << Decrypt(encrypted);
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Blue);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_INFO);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<typename... Args>
        static void Warning(Args&&... args)
        {
            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Yellow);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_WARN);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<std::size_t N, typename... Args>
        static void Warning(const Encrypted<N>& encrypted, Args&&... args)
        {
            std::ostringstream oss;
            oss << Decrypt(encrypted);
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Yellow);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_WARN);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<typename... Args>
        static void Error(Args&&... args)
        {
            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Red);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_ERR);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<std::size_t N, typename... Args>
        static void Error(const Encrypted<N>& encrypted, Args&&... args)
        {
            std::ostringstream oss;
            oss << Decrypt(encrypted);
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Red);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_ERR);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<typename... Args>
        static void Debug(Args&&... args)
        {
            std::ostringstream oss;
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Magenta);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_DBG);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        template<std::size_t N, typename... Args>
        static void Debug(const Encrypted<N>& encrypted, Args&&... args)
        {
            std::ostringstream oss;
            oss << Decrypt(encrypted);
            ((oss << std::forward<Args>(args)), ...);
            SetColor(Color::Magenta);
            std::cout << Decrypt(PREFIX) << Decrypt(TAG_DBG);
            ResetColor();
            std::cout << oss.str() << '\n';
        }

        static constexpr auto HELLOWORLD = Encrypt("Hello XorLog !");

    };

} 



