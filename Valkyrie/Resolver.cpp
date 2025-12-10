#include "Resolver.hpp"


using namespace SigTable::Signatures;



ValkStatus Resolver::ResolveAll()
{
    return ValkStatus();
}

ValkStatus Resolver::ResolveExported()
{
    if (!m_loader.IsValid())
    {
        system("cls");
        LOG_ERROR("Critical failure, invalid loader object. Aborting");
        return ValkStatus::ERR_RESOLVE_FAILED;
    }

    const uint64_t kernelBase = m_loader.GetNtoskrnlBaseAddress();

    LOG_INFO("Resolving exported functions addresses...");

    auto resolve = [&](const char* name, UINT64& out) -> ValkStatus
        {
            out = m_loader.GetKernelModuleExport(kernelBase, name);
            if (!out)
            {
                LOG_ERROR("Failed to resolve " << name);
                return ValkStatus::ERR_RESOLVER_ADDRESS_NOT_FOUND;
            }

            

            LOG_SUCCESS_HEX(name, out);
            return ValkStatus::OK;
        };

    if (auto st = resolve("ExFreePool", m_offsets.ExFreePool); !ValkSucceeded(st)) return st; 
    if (auto st = resolve("ExAcquireResourceExclusiveLite", m_offsets.ExAcquireResourceExclusiveLite); !ValkSucceeded(st)) return st; 
    if (auto st = resolve("ExReleaseResourceLite", m_offsets.ExReleaseResourceLite); !ValkSucceeded(st)) return st;
    if (auto st = resolve("RtlDeleteElementGenericTableAvl", m_offsets.RtlDeleteElementGenericTableAvl); !ValkSucceeded(st)) return st; 
    if (auto st = resolve("RtlLookupElementGenericTableAvl", m_offsets.RtlLookupElementGenericTableAvl); !ValkSucceeded(st)) return st;
    if (auto st = resolve("RtlEnumerateGenericTableWithoutSplayingAvl", m_offsets.RtlEnumerateGenericTableWithoutSplayingAvl); !ValkSucceeded(st)) return st;

    LOG_SUCCESS("All exported functions resolved successfully");
    return ValkStatus::OK;
}

ValkStatus Resolver::ResolvePatterns()
{
    if (!m_loader.IsValid())
    {
        system("cls");
        LOG_ERROR("Critical failure, invalid loader object, aborting.");
        return ValkStatus::ERR_RESOLVE_FAILED;
    }

    PatternScanner scanner(m_loader);
    UINT64 kernelBase = m_loader.GetNtoskrnlBaseAddress();
    uintptr_t hit{};
    

    /*             MmAllocateIndependentPagesEx            */
    
    hit = scanner.FindPattern(kernelBase,
        MmAllocateIndependentPagesEx.section,
        reinterpret_cast<const BYTE*>(MmAllocateIndependentPagesEx.bytes),
        MmAllocateIndependentPagesEx.mask,
        true,
        false);

    if (!hit)
    {
        
        LOG_ERROR("Scanner failed to find MmAllocateIndependentPagesEx signature.");
        return ValkStatus::ERR_PATTERN_NOT_FOUND;
    }


    hit += 8;

    hit = (uintptr_t)m_loader.ResolveRelativeAddress((PVOID)hit, 1, 5);
    m_offsets.MmAllocateIndependentPagesEx = hit;


    hit = 0;


    /*                  MmFreeIndependentPages                    */

    hit = scanner.FindPattern(kernelBase,
        MmFreeIndependentPages.section,
        reinterpret_cast<const BYTE*>(MmFreeIndependentPages.bytes),
        MmFreeIndependentPages.mask,
        true,
        false);

    if (!hit)
    {
        LOG_ERROR("Scanner failed to find MmFreeIndependentPages signature.");
        return ValkStatus::ERR_PATTERN_NOT_FOUND;
    }


    hit += 8;

    hit = (uintptr_t)m_loader.ResolveRelativeAddress((PVOID)hit, 1, 5);
    m_offsets.MmFreeIndependentPages = hit;

    hit = 0;



    /*                    MmSetPageProtection                 */

    hit = scanner.FindPatternRaw(kernelBase,
        MmSetPageProtection0.section,
        reinterpret_cast<const BYTE*>(MmSetPageProtection0.bytes),
        MmSetPageProtection0.mask);

    if (!hit)
    {
        // fallback 
        hit = scanner.FindPattern(kernelBase,
            MmSetPageProtection1.section,
            reinterpret_cast<const BYTE*>(MmSetPageProtection1.bytes),
            MmSetPageProtection1.mask,
            true,
            false);

        if (hit) 
            hit += 13;
    }
    else
    {
        hit += 10;
    }

    if (!hit)
    {
        LOG_ERROR("Scanner failed to find MmSetPageProtection Signature.");
        return ValkStatus::ERR_PATTERN_NOT_FOUND;
    }

    hit = (uintptr_t)m_loader.ResolveRelativeAddress((PVOID)hit, 1, 5);
    m_offsets.MmSetPageProtection = hit;

    hit = 0;


    /*                       PiDDBLock                       */


    hit = scanner.FindPatternRaw(kernelBase,
        PiDDBLock0.section,
        reinterpret_cast<const BYTE*>(PiDDBLock0.bytes),
        PiDDBLock0.mask,
        true);

    if (hit) hit += 28;                 
    else
    {
        
        hit = scanner.FindPatternRaw(kernelBase,
            PiDDBLock1.section,
            reinterpret_cast<const BYTE*>(PiDDBLock1.bytes),
            PiDDBLock1.mask,
            true);

        if (hit) hit += 16;
        else
        {
            
            hit = scanner.FindPatternRaw(kernelBase,
                PiDDBLock2.section,
                reinterpret_cast<const BYTE*>(PiDDBLock2.bytes),
                PiDDBLock2.mask,
                true);

            if (hit) hit += 19;
        }
    }

    if (!hit)
    {
        LOG_ERROR("Scanner failed to find PIDDBLock signature.");
        return ValkStatus::ERR_PATTERN_NOT_FOUND;
    }

    m_offsets.PiDDBLock = (UINT64)m_loader.ResolveRelativeAddress((PVOID)hit, 3, 7);
    hit = 0;



    /*                   PiDDBCacheTable                        */

    hit = scanner.FindPattern(kernelBase,
        PiDDBCacheTable0.section,
        reinterpret_cast<const BYTE*>(PiDDBCacheTable0.bytes),
        PiDDBCacheTable0.mask,
        true,
        false);

    if (!hit)
    {
        hit = scanner.FindPattern(kernelBase,
            PiDBBCacheTable1.section,
            reinterpret_cast<const BYTE*>(PiDBBCacheTable1.bytes),
            PiDBBCacheTable1.mask,
            true,
            false);

        if (hit)
            hit += 2;
        

    }
    if (!hit)
    {
        LOG_ERROR("Scanner failed to find PiDBBCacheTable signature.");
        return ValkStatus::ERR_PATTERN_NOT_FOUND;
    }

    PRTL_AVL_TABLE table = (PRTL_AVL_TABLE)m_loader.ResolveRelativeAddress((PVOID)hit, 6, 10);
    m_offsets.PiDDBCacheTable = (UINT64)table;

    hit = 0;


    /*                        ci.dll                         */
    uintptr_t ciBaseAddress = PEUtils::GetModuleBaseAddress("ci.dll");
    if (!ciBaseAddress)
    {
        LOG_ERROR("ci.dll not found");
        return ValkStatus::ERR_MODULE_NOT_FOUND;
    }

    // BucketList first so we can locate the lock
    uintptr_t bucketHit = scanner.FindPattern(ciBaseAddress,
        CiBucketList0.section,
        reinterpret_cast<const BYTE*>(CiBucketList0.bytes),
        CiBucketList0.mask,
        true, false);

    if (!bucketHit)
    {
        LOG_ERROR("Scanner failed to find CiBucketList signature.");
        return ValkStatus::ERR_PATTERN_NOT_FOUND;
    }

    m_offsets.CiBucketList = (UINT64)m_loader.ResolveRelativeAddress((PVOID)bucketHit, 3, 7);

    // Now we can backward scan for the lock
    uintptr_t searchStart = (bucketHit > 0x1000) ? bucketHit - 0x1000 : ciBaseAddress;
    size_t searchLen = bucketHit - searchStart;

    uintptr_t lockHit = scanner.FindPatternRange(searchStart,
        searchLen,
        reinterpret_cast<const BYTE*>(CiBucketLock0.bytes),
        CiBucketLock0.mask);

    if (!lockHit)
    {
        LOG_ERROR("Scanner failed to find CiBucketLock signature.");
        return ValkStatus::ERR_PATTERN_NOT_FOUND;
    }

    m_offsets.CiBucketLock = (UINT64)m_loader.ResolveRelativeAddress((PVOID)lockHit, 3, 7);

    return ValkStatus::OK;

}


