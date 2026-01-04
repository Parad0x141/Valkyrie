#include "EnvProbe.hpp"


BOOL EnvProbe::IsHypervisorCPUID() const
{
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);

    // Check bit 31 (hypervisor present)
    if (!((cpuInfo[2] >> 31) & 1))
        return FALSE;

    // If present, check vendor string (CPUID leaf 0x40000000)
    __cpuid(cpuInfo, 0x40000000);

    // VMware = "VMwareVMware"
    // VirtualBox = "VBoxVBoxVBox"
    // Hyper-V = "Microsoft Hv"
    // KVM = "KVMKVMKVM"

    char vendor[13] = { 0 };
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);

    const char* blacklist[] = { "VMwareVMware", "VBoxVBoxVBox", "KVMKVMKVM", "Microsoft Hv" };
    for (const auto& v : blacklist)
        if (strcmp(vendor, v) == 0) return TRUE;

    return FALSE; // Hypervisor present but not recognized (safer to allow)
}

BOOL EnvProbe::IsBlacklistedMAC() const
{
    ULONG bufLen = 0;

    DWORD result = GetAdaptersInfo(nullptr, &bufLen);
    if (result != ERROR_BUFFER_OVERFLOW || bufLen == 0)
        return FALSE;

    PIP_ADAPTER_INFO info = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufLen);
    if (!info)
        return FALSE;

    BOOL found = FALSE;

    struct VendorMAC 
    {
        BYTE oui[3];
        const char* name;
    };

    const VendorMAC VM_MACS[] = {
        {{0x08, 0x00, 0x27}, "VirtualBox"},
        {{0x00, 0x05, 0x69}, "VMware"},
        {{0x00, 0x0C, 0x29}, "VMware"},
        {{0x00, 0x50, 0x56}, "VMware ESXi"},
        {{0x00, 0x1C, 0x42}, "Parallels"},
        {{0x00, 0x15, 0x5D}, "Hyper-V"},
        {{0x00, 0x16, 0x3E}, "Xen"},
        {{0x52, 0x54, 0x00}, "KVM/QEMU"},
        {{0x00, 0x1C, 0x14}, "VMware"},
        {{0x00, 0x1B, 0x21}, "VirtualPC"},
        {{0x00, 0x0F, 0x4B}, "Virtual Iron"},
        {{0x00, 0x21, 0xF6}, "Virtual MAC"},
        {{0x00, 0x24, 0x81}, "Oracle VM"},
        {{0x0A, 0x00, 0x27}, "VirtualBox (new)"},
    };

    result = GetAdaptersInfo(info, &bufLen);
    if (result == NO_ERROR)
    {
        for (PIP_ADAPTER_INFO p = info; p; p = p->Next)
        {
            // Bad if not at least 3 bytes, skip
            if (p->AddressLength < 3)
                continue;

            const BYTE* m = p->Address;

            for (const auto& vendor : VM_MACS)
            {
                if (memcmp(m, vendor.oui, 3) == 0)
                {
                    found = TRUE;
                    break;
                }
            }

            if (found)
                break;
        }
    }

    HeapFree(GetProcessHeap(), 0, info);
    return found;
}


BOOL EnvProbe::IsBlacklistedManufacturer() const
{
    char manufacturer[256] = { 0 };
    char model[256] = { 0 };
    DWORD sz = sizeof(manufacturer);

 
    if (RegGetValueA(HKEY_LOCAL_MACHINE,
        R"_(SYSTEM\CurrentControlSet\Control\SystemInformation)_",
        "SystemManufacturer", RRF_RT_REG_SZ, nullptr, manufacturer, &sz) != ERROR_SUCCESS)
        return FALSE;
    


    sz = sizeof(model);
    RegGetValueA(HKEY_LOCAL_MACHINE,
        R"_(SYSTEM\CurrentControlSet\Control\SystemInformation)_",
        "SystemProductName", RRF_RT_REG_SZ, nullptr, model, &sz);

    const char* vmVendors[] = { "VMware", "innotek", "QEMU", "Xen" };
    for (const auto& vendor : vmVendors)
    {
        if (strstr(manufacturer, vendor))
            return TRUE;
    }

    const char* vmModels[] = {
        "VirtualBox",
        "VMware Virtual Platform",
        "Virtual Machine",
        "KVM",
        "Standard PC"  // QEMU default
    };

    for (const auto& vmModel : vmModels)
    {
        if (strstr(model, vmModel))
            return TRUE;
    }

    // Microsoft Corporation + "Virtual Machine" = HyperV
    if (strstr(manufacturer, "Microsoft Corporation") && strstr(model, "Virtual Machine"))
        return TRUE;

    return FALSE;
}

BOOL EnvProbe::IsDebuggerProcess() const
{
    const wchar_t* debuggers[] = {
        L"x64dbg.exe", L"x32dbg.exe",
        L"ollydbg.exe",
        L"windbg.exe", L"kd.exe",
        L"idaq64.exe", L"idaq.exe", L"ida64.exe", L"ida.exe",
        L"processhacker.exe", L"procexp.exe", L"procexp64.exe",
        L"procmon.exe", L"procmon64.exe",
        L"tcpview.exe", L"autoruns.exe", L"autorunsc.exe",
        L"wireshark.exe", L"fiddler.exe",
        L"filemon.exe", L"regmon.exe",
        L"importrec.exe", L"lordpe.exe",
        L"dumpcap.exe",
        L"hookexplorer.exe", L"ollyice.exe",
        L"pestudio.exe", L"de4dot.exe",
        L"ilspy.exe", L"dnspy.exe",
        L"scylla_x64.exe", L"scylla_x86.exe",
    };



    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return FALSE;

    PROCESSENTRY32W pe = { sizeof(pe) };
    BOOL found = FALSE;

    if (Process32FirstW(snapshot, &pe))
    {
        do {
            for (const auto& dbg : debuggers)
            {
                if (_wcsicmp(pe.szExeFile, dbg) == 0)
                {
                    found = TRUE;
                    goto cleanup;
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }

cleanup:
    CloseHandle(snapshot);
    return found;
}

BOOL EnvProbe::IsSandBoxed() const
{
    const char* sandboxDlls[] = {
        "SbieDll.dll",      // Sandboxie
        "api_log.dll",      // SunBelt Sandbox
        "dir_watch.dll",    // Sandboxie
        "dbghelp.dll",      // Potentiel debugger attachment
        "pstorec.dll",      // Protected Storage
    };

    for (const auto& dll : sandboxDlls)
        if (GetModuleHandleA(dll)) return TRUE;

    return FALSE;
}

BOOL EnvProbe::IsDebuggerPresentPEB() const
{

    return *(uint8_t*)(__readgsqword(0x60) + 0x2) != 0;

}

BOOL EnvProbe::IsDebuggerPresentTiming() const
{
   
    auto t1 = __rdtsc();
    volatile int x = 0;
    for (int i = 0; i < 100; ++i) x++;
    auto t2 = __rdtsc();

    if ((t2 - t1) > 5000) // high threshold, trying to avoid false p
        return TRUE;

    // 2. GetTickCount64 vs QueryPerformanceCounter discrepancy
    UINT64 tick1 = GetTickCount64();
    LARGE_INTEGER qpc1;
    QueryPerformanceCounter(&qpc1);

    Sleep(10); // 10ms sleep

    UINT64 tick2 = GetTickCount64();
    LARGE_INTEGER qpc2;
    QueryPerformanceCounter(&qpc2);

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);

    UINT64 tickDelta = tick2 - tick1;
    UINT64 qpcDelta = ((qpc2.QuadPart - qpc1.QuadPart) * 1000) / freq.QuadPart;

    // If difference > 50ms for a 10ms sleep -> debugger stepping
    if (llabs((long long)(tickDelta - qpcDelta)) > 50)
        return TRUE;

    return FALSE;
}
BOOL EnvProbe::IsFreshInstall() const
{
    DWORD installDate = 0; // Unix timestamp
    DWORD sz = sizeof(installDate);

    if (RegGetValueA(HKEY_LOCAL_MACHINE,
        R"_(SOFTWARE\Microsoft\Windows NT\CurrentVersion)_",
        "InstallDate", RRF_RT_REG_DWORD, nullptr, &installDate, &sz) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    time_t now = time(nullptr);

    UINT64 secondsSinceInstall = now - installDate;
    UINT64 daysSinceInstall = secondsSinceInstall / (24 * 3600);

    // Fresh installs (< 7 days) are suspicious
    return daysSinceInstall < 7;
}

BOOL EnvProbe::HasSuspiciousDiskSize() const
{
    ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;

    if (!GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes, &totalFreeBytes))
        return FALSE;

    UINT64 totalGB = totalBytes.QuadPart / (1024ULL * 1024 * 1024);

    return totalGB < 80;
}

BOOL EnvProbe::IsLowEndMachine() const
{
    SYSTEM_INFO si; GetSystemInfo(&si);

    if (si.dwNumberOfProcessors < 2)
        return TRUE;

    MEMORYSTATUSEX ms = { sizeof(ms) };

    return GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys < 4ULL * 1024 * 1024 * 1024;
}

BOOL EnvProbe::HasNoUSBDevices() const
{
    // Real machines usually have USB devices (mouse, keyboard, etc.)
    // VMs often have none or only virtual USB controllers

    HDEVINFO deviceInfo = SetupDiGetClassDevsA(
        nullptr,  // All device classes
        "USB",    // Enumerator (USB devices only)
        nullptr,
        DIGCF_PRESENT | DIGCF_ALLCLASSES
    );

    if (deviceInfo == INVALID_HANDLE_VALUE)
        return FALSE;

    SP_DEVINFO_DATA deviceData = { sizeof(SP_DEVINFO_DATA) };
    DWORD deviceCount = 0;

    for (DWORD i = 0; SetupDiEnumDeviceInfo(deviceInfo, i, &deviceData); i++)
    {
        // Check if it's a real USB device (not just USB controller)
        char deviceID[256] = { 0 };
        if (SetupDiGetDeviceInstanceIdA(deviceInfo, &deviceData, deviceID, sizeof(deviceID), nullptr))
        {
            // Skip USB Root Hubs and Host Controllers (present even in VMs)
            if (strstr(deviceID, "ROOT_HUB") || strstr(deviceID, "USB\\ROOT"))
                continue;

            deviceCount++;
        }
    }

    SetupDiDestroyDeviceInfoList(deviceInfo);

    // Less than 2 USB devices (excluding hubs) is suspicious
    return deviceCount < 2;
}

EnvProbe::Result EnvProbe::Analyze() const
{
    Result probeResults;

    if (IsDebuggerPresentPEB())
    {
        probeResults.Score = 100;
        probeResults.Flags.push_back("Debugger attached (PEB)");

        return probeResults; // abort
    }

    
    if (IsHypervisorCPUID())
    {
        probeResults.Score += 40;
        probeResults.Flags.push_back("Hypervisor CPUID detected");
    }

    if (IsBlacklistedManufacturer())
    {
        probeResults.Score += 35;
        probeResults.Flags.push_back("VM manufacturer detected");
    }

    
    if (IsBlacklistedMAC())
    {
        probeResults.Score += 25;
        probeResults.Flags.push_back("VM MAC address detected");
    }

    if (IsSandBoxed())
    {
        probeResults.Score += 30;
        probeResults.Flags.push_back("Sandbox DLL detected");
    }

    if (IsDebuggerProcess())
    {
        probeResults.Score += 25;
        probeResults.Flags.push_back("Debugger process detected");
    }

    // Low confidence because of potentil false P
    if (IsDebuggerPresentTiming())
    {
        probeResults.Score += 10;
        probeResults.Flags.push_back("Timing anomaly detected");
    }

    if (IsFreshInstall())
    {
        probeResults.Score += 15;
        probeResults.Flags.push_back("Fresh install detected");
    }

    if (IsLowEndMachine())
    {
        probeResults.Score += 20;
        probeResults.Flags.push_back("Low-end hardware detected");
    }

    if (HasSuspiciousDiskSize())
    {
        probeResults.Score += 15;
        probeResults.Flags.push_back("Small disk size detected");
    }

    if (HasNoUSBDevices())
    {
        probeResults.Score += 10;
        probeResults.Flags.push_back("No USB devices found");
    }

    return probeResults;
}