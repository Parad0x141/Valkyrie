#pragma once
#include "PatternScanner.hpp"
#include "SigTable.hpp"

class SigResolver
{
public:
    explicit SigResolver(IntelLoader& loader) : m_loader(loader) {}

    // Return **ABSOLUTE** address if foudn , std::nullopt otherwise
    std::optional<uintptr_t> resolve(const SigTable::SigEntry& entry) const
    {
        uintptr_t base = m_loader.GetNtoskrnlBaseAddress();
        if (!base) return std::nullopt;

        uintptr_t hit = PatternScanner(m_loader).FindPattern(
            base,
            entry.section,
            reinterpret_cast<const BYTE*>(entry.bytes),
            entry.mask,
            true, 
            true);  // SIMD if available

        

        return hit ? std::make_optional(hit) : std::nullopt;
    }


private:
    IntelLoader& m_loader;
};