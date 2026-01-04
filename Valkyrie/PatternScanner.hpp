// PatternScanner.hpp 
#pragma once
#define NOMINMAX // Avoid min/max redef by Windows.h

#include <Windows.h>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include "IntelLoader.hpp"
#include <map>
#include <vector>



class PatternScanner
{
public:
    struct Stats
    {
        size_t bytesScanned = 0;
        size_t comparisons = 0;
        size_t cacheHits = 0;
        double scanTimeMs = 0.0;

        void Reset() { *this = Stats{}; }
    };

    // Can easily be converted for another project.
    explicit PatternScanner(IntelLoader& loader) : m_loader(loader) {}

    

    /// <summary>
    /// Cherche un pattern dans une section d'un module kernel
    /// </summary>
    /// <param name="moduleBase">Base address du module (ex: ntoskrnl)</param>
    /// <param name="sectionName">Nom de la section (".text", "PAGE", ".data")</param>
    /// <param name="pattern">Bytes à chercher</param>
    /// <param name="mask">Masque ("x" = exact, "?" = wildcard)</param>
    /// <param name="useCache">Utiliser le cache (défaut: true)</param>
    /// <param name="enableSIMD">Utiliser SIMD (défaut: true si pattern >= 16 bytes)</param>
    uintptr_t FindPattern(
        uintptr_t moduleBase,
        const char* sectionName,
        const BYTE* pattern,
        const char* mask,
        bool useCache = true,
        bool enableSIMD = true
    );

    /// <summary>
	/// String pattern, ex: "48 8B ?? ?? ?? 48 85 C0 74 0A"
    /// </summary>
    uintptr_t FindPatternStr(
        uintptr_t moduleBase,
        const char* sectionName,
        const char* patternStr,
        bool useCache = true,
        bool enableSIMD = true
    );

    /// <summary>
	/// Search multiple patterns and return the first found
    /// </summary>
    uintptr_t FindPatternMulti(
        uintptr_t moduleBase,
        const char* sectionName,
        const std::vector<std::pair<std::string, std::string>>& patterns, // {pattern, mask}
        bool useCache = true,
        bool enableSIMD = true
    );

    uintptr_t FindPatternRaw(uintptr_t moduleBase,
        const char* sectionName,
        const BYTE* pattern,
        const char* mask,
        bool useCache = true);

    uintptr_t FindPatternRange(uintptr_t start, size_t len, const BYTE* pat, const char* mask);
  

    Stats GetStats() const;
    void ClearCache();
    void ClearStats();

private:
    IntelLoader& m_loader;

    // Cache
    struct CacheEntry { uintptr_t addr; uint64_t ts; };
    mutable std::map<std::string, CacheEntry> m_cache;
    mutable uint64_t m_cacheTS = 0;
    mutable std::mutex m_cacheMutex;

    // Stats
    mutable Stats m_stats;
    mutable std::mutex m_statsMutex;


    // PE validation
    bool ValidateDOS(uintptr_t base, IMAGE_DOS_HEADER& out) const;
    bool ValidateNT(uintptr_t base, DWORD lfanew, IMAGE_NT_HEADERS64& out) const;
    bool GetSection(uintptr_t base, const IMAGE_NT_HEADERS64& nt,
        const char* name, IMAGE_SECTION_HEADER& out) const;

    // Scanners
    uintptr_t ScanChunked(uintptr_t start, size_t size,
        const BYTE* pat, const char* mask, size_t mLen) const;
    uintptr_t ScanNaive(const BYTE* buf, size_t sz,
        const BYTE* pat, const char* mask, size_t mLen) const;
    uintptr_t ScanBMH(const BYTE* buf, size_t sz,
        const BYTE* pat, const char* mask, size_t mLen) const;
    uintptr_t ScanSIMD(const BYTE* buf, size_t sz,
        const BYTE* pat, const char* mask, size_t mLen) const;

    bool Match(const BYTE* buf, const BYTE* pat, const char* mask, size_t mLen) const;

    // Cache
    std::string CacheKey(uintptr_t mod, const char* sec,
        const BYTE* pat, const char* mask) const;
    bool TryCache(const std::string& key, uintptr_t& out) const;
    void AddCache(const std::string& key, uintptr_t addr) const;

    // Helper for accepting pattern as a string
    static std::pair<std::vector<BYTE>, std::string> ParsePatternStr(const char* str);
};