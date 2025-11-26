#pragma once
#include "Common.hpp"

static const UCHAR ThreatIntGuid[16] =
{ 0x45,0x7D,0xFC,0x8C,0xE1,0x2B,0xD6,0x41,0xAB,0x38,0x86,0xA3,0x17,0xB6,0xFA,0xBB };



// TODO ! Clean PiDBBCacheTable -> Done.
// TODO ! Check if we can hook or patch NtEtwEventWrite. -> Better to mute it via ETW event registration.
// TODO ! Randomize pool tag?
// Advanced callbacks hookign ? Something like if(Known EDR/AC/AV)... {end operations early} might be cool and more sneaky.


class StealthKit
{
public:
    explicit StealthKit(IntelLoader& loader) :  m_loader(loader) {}
   

    /* File + registry */
    BOOLEAN DeleteDriverFiles(const std::wstring& serviceName);
    BOOLEAN EraseServiceKey(const std::wstring& serviceName);



    /* Kernel tricks */

    ValkStatus CleanPiDDBCache(const std::wstring& driverName, ULONG timeDateStamp);
    ValkStatus ClearCIHashTable();

    /* Cleaning */
    BOOLEAN WipeKernelImage(uint64_t base, uint32_t size);

    //Helpers
    void EnumeratePiDDBCache();


private:
    IntelLoader& m_loader;

    
};