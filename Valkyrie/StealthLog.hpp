#pragma once

#include <array>
#include <mutex>
#include <iostream>
#include <sstream>
#include <string>

#include "../Valkyrie/External/RANG/rang.hpp"



inline void JumpLine()
{
    std::cout << "\n" << std::flush;
}

// Multi layers compile time encryption
template <std::size_t N>
struct EncryptedString
{
    std::array<char, N> data{};
    unsigned char keys[3] = { 0, 0, 0 };
    unsigned char shuffle = 0;
};

template <std::size_t N>
constexpr auto EncryptString(const char(&s)[N]) noexcept {
    EncryptedString<N> es{};

    // Generate keys based on string content and length
    es.keys[0] = static_cast<unsigned char>(N ^ 0x9E);
    es.keys[1] = static_cast<unsigned char>((N * 0x37) & 0xFF);
    es.keys[2] = static_cast<unsigned char>((N + 0x55) ^ 0xAA);

    // Shuffle pattern
    es.shuffle = static_cast<unsigned char>((N * 0x11) % 7);

    // Multi layer XOR encryption
    for (std::size_t i = 0; i < N; ++i)
    {
        unsigned char c = static_cast<unsigned char>(s[i]);

        // Layer 1: XOR with key + position
        c ^= es.keys[0] + static_cast<unsigned char>(i);

        // Layer 2: XOR with rotated second key
        unsigned char key2 = (es.keys[1] << (i % 3)) | (es.keys[1] >> (8 - (i % 3)));
        c ^= key2;

        // Layer 3: Add/subtract third key
        if (i % 2 == 0)
            c += es.keys[2];
        else
            c -= es.keys[2];

        // Layer 4: Bit rotation
        c = (c >> 2) | (c << 6);

        es.data[i] = static_cast<char>(c);
    }

    // Simple shuffle to break patterns
    if (es.shuffle > 0 && N > 1)
    {
        for (std::size_t i = 0; i < N - 1; i += 2)
            std::swap(es.data[i], es.data[(i + es.shuffle) % N]);
    }

    return es;
}

template <std::size_t N>
inline void DecryptString(const EncryptedString<N>& es, char* out)
{
    // Unshuffle first
    std::array<char, N> temp = es.data;
    if (es.shuffle > 0 && N > 1)
    {
        for (std::size_t i = 0; i < N - 1; i += 2)
            std::swap(temp[i], temp[(i + es.shuffle) % N]);
    }

    // Decrypt in reverse order
    for (std::size_t i = 0; i < N; ++i)
    {
        unsigned char c = static_cast<unsigned char>(temp[i]);

        // Reverse layer 4: Bit rotation
        c = (c << 2) | (c >> 6);

        // Reverse layer 3: Add/subtract
        if (i % 2 == 0)
            c -= es.keys[2];
        else
            c += es.keys[2];

        // Reverse layer 2: XOR with rotated second key
        unsigned char key2 = (es.keys[1] << (i % 3)) | (es.keys[1] >> (8 - (i % 3)));
        c ^= key2;

        // Reverse layer 1: XOR with key + position
        c ^= es.keys[0] + static_cast<unsigned char>(i);

        out[i] = static_cast<char>(c);
    }

    out[N - 1] = '\0';
}


template <std::size_t N>
inline std::string DecryptToString(const EncryptedString<N>& es) 
{
    char buffer[N];
    DecryptString(es, buffer);

    return std::string(buffer);
}

// Macros helpers
#define ENCRYPT(str) EncryptString(str)
#define DECRYPT(encrypted) DecryptToString(encrypted)


class StealthLog
{
    inline static std::mutex mtx_;

    // Encrypted string pool
    static constexpr auto enc_prefix = EncryptString("[Valkyrie] ");
    static constexpr auto enc_success = EncryptString("[+] ");
    static constexpr auto enc_info = EncryptString("[i] ");
    static constexpr auto enc_warn = EncryptString("[!] ");
    static constexpr auto enc_error = EncryptString("[-] ");

public:
    enum class Color { Green, Blue, Yellow, Red, Cyan, Magenta };

private:
    static auto colorCode(Color c)
    {
        switch (c)
        {
        case Color::Green:  return rang::fgB::green;
        case Color::Blue:   return rang::fgB::blue;
        case Color::Yellow: return rang::fgB::yellow;
        case Color::Red:    return rang::fgB::red;
        case Color::Cyan:   return rang::fgB::cyan;
        case Color::Magenta:return rang::fgB::magenta;
        }
    }

    // Decrypt and print with type
    template <typename... Args>
    static void print(Color c, const EncryptedString<5>& type_prefix_enc, Args&&... args) {
        std::lock_guard<std::mutex> lg(mtx_);

        // Decrypt prefixes
        char prefix[32];
        char type_prefix[16];

        DecryptString(enc_prefix, prefix);
        DecryptString(type_prefix_enc, type_prefix);

        // Build message
        std::ostringstream oss;
        (oss << ... << std::forward<Args>(args));

        // Output
        std::cout << colorCode(c)
            << prefix
            << type_prefix
            << rang::style::reset
            << oss.str()
            << '\n'
            << std::flush;
    }

public:
    template <typename... Args>
    static void succ(Args&&... args) 
    {
        print(Color::Green, enc_success, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void info(Args&&... args) 
    {
        print(Color::Blue, enc_info, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void warn(Args&&... args)
    {
        print(Color::Yellow, enc_warn, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void error(Args&&... args)
    {
        print(Color::Red, enc_error, std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void debug(Args&&... args)
    {
#ifdef _DEBUG
        print(Color::Magenta, enc_info, std::forward<Args>(args)...);
#endif
    }

    template <typename... Args>
    static void custom(Color c, const char* custom_prefix, Args&&... args) {
        std::lock_guard<std::mutex> lg(mtx_);

        // Encrypt custom prefix at compile time if it's a string literal
        char decrypted_prefix[32];
        DecryptString(enc_prefix, decrypted_prefix);

        std::cout << colorCode(c)
            << decrypted_prefix
            << "["
            << custom_prefix
            << "] "
            << rang::style::reset;

        std::ostringstream oss;
        (oss << ... << std::forward<Args>(args));
        std::cout << oss.str() << '\n' << std::flush;
    }
};