#include "PatternScanner.hpp"

// TODO : Change workflow to use all scanners and make sure to not miss/misread patterns.

uintptr_t PatternScanner::FindPattern(
    uintptr_t moduleBase,
    const char* sectionName,
    const BYTE* pattern,
    const char* mask,
    bool useCache,
    bool enableSIMD)
{
    auto t0 = std::chrono::high_resolution_clock::now();
    ClearStats();

    size_t maskLen = strlen(mask);
    if (!moduleBase || !sectionName || !pattern || !mask || maskLen == 0)
    {
        LOG_ERROR("Invalid args");
        return 0;
    }

    // Cache check
    std::string key;
    if (useCache)
    {
        key = CacheKey(moduleBase, sectionName, pattern, mask);
        uintptr_t cached;
        if (TryCache(key, cached)) return cached;
    }

    // PE validation
    IMAGE_DOS_HEADER dos;
    if (!ValidateDOS(moduleBase, dos)) return 0;

    IMAGE_NT_HEADERS64 nt;
    if (!ValidateNT(moduleBase, dos.e_lfanew, nt)) return 0;

    IMAGE_SECTION_HEADER sec;
    if (!GetSection(moduleBase, nt, sectionName, sec)) return 0;

    uintptr_t secStart = moduleBase + sec.VirtualAddress;
    size_t secSize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;

    if (secSize < maskLen) return 0;

    // Scan
    uintptr_t hit = 0;
    if (false)
    {
        hit = ScanChunked(secStart, secSize, pattern, mask, maskLen);
    }
    else
    {
        std::unique_ptr<BYTE[]> buf(new (std::nothrow) BYTE[secSize]);
        if (!buf || !m_loader.ReadMemory(secStart, buf.get(), secSize)) 
        {
            return 0;
        }


        if (enableSIMD && maskLen >= 16)
            hit = ScanSIMD(buf.get(), secSize, pattern, mask, maskLen);
        else if (maskLen >= 4)
            hit = ScanBMH(buf.get(), secSize, pattern, mask, maskLen);
        else
            hit = ScanNaive(buf.get(), secSize, pattern, mask, maskLen);

        if (hit != 0) hit += secStart;
    }

    // Cache result
    if (useCache && hit) AddCache(key, hit);

    // Stats
    auto t1 = std::chrono::high_resolution_clock::now();
    std::lock_guard<std::mutex> lk(m_statsMutex);
    m_stats.bytesScanned = secSize;
    m_stats.scanTimeMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    return hit;
}

uintptr_t PatternScanner::FindPatternStr(
    uintptr_t moduleBase,
    const char* sectionName,
    const char* patternStr,
    bool useCache,
    bool enableSIMD)
{
    auto [pattern, mask] = ParsePatternStr(patternStr);
    return FindPattern(moduleBase, sectionName, pattern.data(), mask.c_str(),
        useCache, enableSIMD);
}

uintptr_t PatternScanner::FindPatternMulti(
    uintptr_t moduleBase,
    const char* sectionName,
    const std::vector<std::pair<std::string, std::string>>& patterns,
    bool useCache,
    bool enableSIMD)
{
    for (const auto& [patStr, mask] : patterns)
    {
        auto [patBytes, _] = ParsePatternStr(patStr.c_str());

        uintptr_t result = FindPattern(moduleBase, sectionName,
            patBytes.data(), mask.c_str(),
            useCache, true);
        if (result) {
            LOG_SUCCESS_HEX("Pattern match found at", result);
            return result;
        }
    }

    LOG_ERROR("No pattern matched");
    return 0;
}


// "Dumb" scanner to fix chunks edge issue and such.
uintptr_t PatternScanner::FindPatternRaw(uintptr_t moduleBase, const char* sectionName, const BYTE* pattern, const char* mask, bool useCache)
{
    size_t maskLen = strlen(mask);
    if (!moduleBase || !sectionName || !pattern || !mask || maskLen == 0)
        return 0;

    // Cache
    std::string key;
    if (useCache)
    {
        key = CacheKey(moduleBase, sectionName, pattern, mask);
        uintptr_t cached;
        if (TryCache(key, cached)) return cached;
    }

    // Get section
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_SECTION_HEADER sec;

    if (!ValidateDOS(moduleBase, dos) ||
        !ValidateNT(moduleBase, dos.e_lfanew, nt) ||
        !GetSection(moduleBase, nt, sectionName, sec))
        return 0;

    uintptr_t secStart = moduleBase + sec.VirtualAddress;
    size_t secSize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;

    if (secSize < maskLen) return 0;

    std::unique_ptr<BYTE[]> buf(new (std::nothrow) BYTE[secSize]);
    if (!buf || !m_loader.ReadMemory(secStart, buf.get(), secSize))
        return 0;

    
    uintptr_t hit = ScanNaive(buf.get(), secSize, pattern, mask, maskLen);
    if (hit != 0) hit += secStart;

    if (useCache && hit) AddCache(key, hit);

    return hit;
}

uintptr_t PatternScanner::FindPatternRange(uintptr_t start, size_t len, const BYTE* pat, const char* mask)
{
    std::unique_ptr<BYTE[]> buf(new (std::nothrow) BYTE[len]);
    if (!buf || !m_loader.ReadMemory(start, buf.get(), len)) return 0;

    uintptr_t off = ScanNaive(buf.get(), len, pat, mask, strlen(mask));
    return off ? start + off : 0;
}

bool PatternScanner::ValidateDOS(uintptr_t base, IMAGE_DOS_HEADER& out) const 
{
    if (!m_loader.ReadMemory(base, &out, sizeof(out))) return false;
    if (out.e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (out.e_lfanew == 0 || out.e_lfanew > 0x1000) return false;
    return true;
}

bool PatternScanner::ValidateNT(uintptr_t base, DWORD lfanew, IMAGE_NT_HEADERS64& out) const 
{
    if (!m_loader.ReadMemory(base + lfanew, &out, sizeof(out))) return false;
    if (out.Signature != IMAGE_NT_SIGNATURE) return false;
    if (out.FileHeader.NumberOfSections == 0 || out.FileHeader.NumberOfSections > 96) return false;
    return true;
}

bool PatternScanner::GetSection(uintptr_t base, const IMAGE_NT_HEADERS64& nt,
    const char* name, IMAGE_SECTION_HEADER& out) const

{
    PIMAGE_SECTION_HEADER sec = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        base + (reinterpret_cast<uintptr_t>(IMAGE_FIRST_SECTION(&nt)) - reinterpret_cast<uintptr_t>(&nt)));

    for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i, ++sec)
    {
        IMAGE_SECTION_HEADER localSec;
        if (!m_loader.ReadMemory(reinterpret_cast<uintptr_t>(sec), &localSec, sizeof(localSec)))
            continue;

        char secName[9] = {};
        memcpy(secName, localSec.Name, 8);

        if (_stricmp(secName, name) == 0)
        {
            out = localSec;
            return true;
        }
    }
    LOG_ERROR_ANSI("Section '%s' not found", name);
    return false;
}


uintptr_t PatternScanner::ScanChunked(uintptr_t start, size_t size,
    const BYTE* pat, const char* mask, size_t mLen) const
{
    constexpr size_t CHUNK = 4 * 1024 * 1024;
    std::unique_ptr<BYTE[]> buf(new (std::nothrow) BYTE[CHUNK + mLen]);
    if (!buf) return 0;

    for (size_t pos = 0; pos < size; pos += CHUNK - mLen + 1) 
    {
        size_t read = std::min(CHUNK + mLen, size - pos);
        if (!m_loader.ReadMemory(start + pos, buf.get(), read)) continue;

        uintptr_t hit = ScanBMH(buf.get(), read, pat, mask, mLen);
        if (hit) return start + pos + hit;
    }
    return 0;
}

uintptr_t PatternScanner::ScanNaive(const BYTE* buf, size_t sz,
    const BYTE* pat, const char* mask, size_t mLen) const 
{
    for (size_t i = 0; i + mLen <= sz; ++i)
        if (Match(buf + i, pat, mask, mLen)) return i;
    return 0;
}

uintptr_t PatternScanner::ScanBMH(const BYTE* buf, size_t sz,
    const BYTE* pat, const char* mask, size_t mLen) const 
{
    size_t skip[256];
    for (auto& s : skip) s = mLen;
    for (size_t i = 0; i < mLen - 1; ++i)
        if (mask[i] == 'x') skip[pat[i]] = mLen - 1 - i;

    for (size_t i = 0; i + mLen <= sz;) {
        if (Match(buf + i, pat, mask, mLen)) return i;
        i += skip[buf[i + mLen - 1]];
        std::lock_guard<std::mutex> lk(m_statsMutex);
        ++m_stats.comparisons;
    }
    return 0;
}

uintptr_t PatternScanner::ScanSIMD(const BYTE* buf, size_t sz,
    const BYTE* pat, const char* mask, size_t mLen) const
{
    size_t first = 0;
    while (first < mLen && mask[first] != 'x') ++first;
    if (first == mLen) return ScanNaive(buf, sz, pat, mask, mLen);

    __m128i need = _mm_set1_epi8(pat[first]);

    for (size_t i = 0; i + mLen <= sz; i += 16)
    {
        __m128i v = _mm_loadu_si128((const __m128i*)(buf + i + first));
        __m128i m = _mm_cmpeq_epi8(v, need);
        int hits = _mm_movemask_epi8(m);

        while (hits) {
            unsigned long pos;
            _BitScanForward(&pos, (unsigned long)hits);
            if (Match(buf + i + pos, pat, mask, mLen)) return i + pos;
            hits &= hits - 1;
        }
    }
    return 0;
}

bool PatternScanner::Match(const BYTE* buf, const BYTE* pat, const char* mask, size_t mLen) const {
    for (size_t i = 0; i < mLen; ++i)
        if (mask[i] == 'x' && buf[i] != pat[i]) return false;
    return true;
}


std::string PatternScanner::CacheKey(uintptr_t mod, const char* sec,
    const BYTE* pat, const char* mask) const 
{
    std::string k;
    char tmp[64];
    sprintf_s(tmp, "%llX:%s:", (unsigned long long)mod, sec);
    k += tmp;
    for (size_t i = 0; mask[i]; ++i)
        k += (mask[i] == 'x') ? "XX" : "??";
    return k;
}

bool PatternScanner::TryCache(const std::string& key, uintptr_t& out) const
{
    std::lock_guard<std::mutex> lk(m_cacheMutex);
    auto it = m_cache.find(key);
    if (it == m_cache.end()) return false;

    it->second.ts = ++m_cacheTS;
    out = it->second.addr;

    std::lock_guard<std::mutex> sl(m_statsMutex);
    ++m_stats.cacheHits;
    return true;
}

void PatternScanner::AddCache(const std::string& key, uintptr_t addr) const
{
    std::lock_guard<std::mutex> lk(m_cacheMutex);
    if (m_cache.size() >= 256)
    {
        auto old = std::min_element(m_cache.begin(), m_cache.end(),
            [](auto& a, auto& b) { return a.second.ts < b.second.ts; });
        if (old != m_cache.end()) m_cache.erase(old);
    }
    m_cache[key] = { addr, ++m_cacheTS };
}


std::pair<std::vector<BYTE>, std::string> PatternScanner::ParsePatternStr(const char* str)
{
    std::vector<BYTE> pattern;
    std::string mask;

    std::istringstream iss(str);
    std::string token;

    while (iss >> token)
    {
        if (token == "??" || token == "?") 
        {
            pattern.push_back(0);
            mask += '?';
        }
        else {
            pattern.push_back((BYTE)std::stoul(token, nullptr, 16));
            mask += 'x';
        }
    }

    return { pattern, mask };
}


PatternScanner::Stats PatternScanner::GetStats() const 
{
    std::lock_guard<std::mutex> lk(m_statsMutex);
    return m_stats;
}

void PatternScanner::ClearCache() 
{
    std::lock_guard<std::mutex> lk(m_cacheMutex);
    m_cache.clear();
    m_cacheTS = 0;
}

void PatternScanner::ClearStats()
{
    std::lock_guard<std::mutex> lk(m_statsMutex);
    m_stats.Reset();
}