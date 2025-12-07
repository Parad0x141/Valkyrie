#pragma once
#include "Common.hpp"
#include "IntelLoader.hpp"

class StealthKit
{
public:
    explicit StealthKit(IntelLoader& loader) :  m_loader(loader) {}
   

    /* File + registry */
    BOOLEAN DeleteDriverFiles(const std::wstring& serviceName);
    BOOLEAN EraseServiceKey(const std::wstring& serviceName);
  




    /* Kernel tricks */
    BOOLEAN ClearMmUnloadedDrivers();
    ValkStatus CleanPiDDBCache(const std::wstring& driverName, ULONG timestamp);
    ValkStatus ClearCIHashTable();
    

    /* Cleaning */
    BOOLEAN RewriteKernelCode(uint64_t base, uint32_t size);

    //Helpers
    void EnumeratePiDDBCache();

private:
    IntelLoader& m_loader;

    
};