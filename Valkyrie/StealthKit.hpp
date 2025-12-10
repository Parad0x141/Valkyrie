#pragma once
#include "Common.hpp"
#include "IntelLoader.hpp"

class StealthKit
{
public:
    explicit StealthKit(IntelLoader& loader, const KernelOffsets& offsets) :  m_loader(loader),
        m_NtTraceEventOriginalBytes(0),
        m_offsets(offsets) { }
   

    /* File + registry */
    BOOLEAN DeleteDriverFile(const std::wstring& serviceName);
    BOOLEAN DeleteRegistryKeys(const std::wstring& serviceName);
  

    // Painless ETW self patching. Obviously not full spectrum, except ntEtwWrite kernel ETW is untouched.
    
    /* ETW Patching */
    ValkStatus PatchETW();
    BOOLEAN PatchNtTraceEvent();
   


    /* Kernel tricks */
    BOOLEAN ClearMmUnloadedDrivers();
    ValkStatus CleanPiDDBCache(const std::wstring& driverName, ULONG timestamp);
    ValkStatus ClearCIHashTable();

    

    /* Cleaning */
    BOOLEAN RewriteKernelCode(uint64_t base, uint32_t size);

    //Helpers
    VOID EnumeratePiDDBCache();
    VOID DebugEtwHooks();

    // :D.
    VOID KernelPanic();

private:

    IntelLoader& m_loader;
    const KernelOffsets& m_offsets;
    uint8_t m_NtTraceEventOriginalBytes[16];
  
};