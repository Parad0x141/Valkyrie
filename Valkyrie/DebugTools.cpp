#include "DebugTools.hpp"



namespace DebugTools
{

    static const wchar_t* ServiceStateToString(DWORD s)
    {
        switch (s)
        {
        case SERVICE_STOPPED:          return L"STOPPED";
        case SERVICE_START_PENDING:    return L"START_PENDING";
        case SERVICE_STOP_PENDING:     return L"STOP_PENDING";
        case SERVICE_RUNNING:          return L"RUNNING";
        case SERVICE_CONTINUE_PENDING: return L"CONTINUE_PENDING";
        case SERVICE_PAUSE_PENDING:    return L"PAUSE_PENDING";
        case SERVICE_PAUSED:           return L"PAUSED";
        default:                       return L"UNKNOWN";
        }
    }

    static void WriteStr(const std::wstring& s)
    {
        DWORD dummy = 0;
        WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), s.c_str(), (DWORD)s.size(), &dummy, nullptr);
    }

    void ListWinServices()
    {
        
        SetConsoleOutputCP(1200); // UTF-16
        
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCM)
            return;

        DWORD bytesNeeded = 0, svcsReturned = 0, resume = 0;
        EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &svcsReturned, &resume, nullptr);

        if (GetLastError() != ERROR_MORE_DATA || !bytesNeeded)
        {
            CloseServiceHandle(hSCM);
            return;
        }

        std::vector<BYTE> buffer(bytesNeeded);
        auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

        if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL, buffer.data(), bytesNeeded, &bytesNeeded,
            &svcsReturned, &resume, nullptr))
        {
            CloseServiceHandle(hSCM);
            return;
        }

        WriteStr(L"[+] Found " + std::to_wstring(svcsReturned) + L" services\n");
        WriteStr(L"========================================\n");

        for (DWORD i = 0; i < svcsReturned; ++i)
        {
            std::wstring line = L"[" + std::to_wstring(i + 1) + L"] " +
                services[i].lpServiceName + L"  (" +
                (services[i].lpDisplayName ? services[i].lpDisplayName : L"") +
                L")  - " + ServiceStateToString(services[i].ServiceStatusProcess.dwCurrentState) + L'\n';
            WriteStr(line);
        }
        WriteStr(L"========================================\n");
        CloseServiceHandle(hSCM);
    }

    VOID ListKernelModuleExports(IntelLoader& loader)
    {
        UINT64 ntoskrnlBaseAddress = loader.GetNtoskrnlBaseAddress();

        if (!ntoskrnlBaseAddress)
        {
            std::cout << "[-] Invalid module base\n";
            return;
        }

        IMAGE_DOS_HEADER dos_header = { 0 };
        IMAGE_NT_HEADERS64 nt_headers = { 0 };

        if (!loader.ReadMemory(ntoskrnlBaseAddress, &dos_header, sizeof(dos_header)) ||
            dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        {
            std::cout << "[-] Invalid DOS header\n";
            return;
        }

        if (!loader.ReadMemory(ntoskrnlBaseAddress + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE) {
            std::cout << "[-] Invalid NT headers\n";
            return;
        }

        const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (!export_base || !export_base_size) {
            std::cout << "[-] No exports found\n";
            return;
        }

        const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

        if (!loader.ReadMemory(ntoskrnlBaseAddress + export_base, export_data, export_base_size)) {
            std::cout << "[-] Failed to read export directory\n";
            VirtualFree(export_data, 0, MEM_RELEASE);
            return;
        }

        const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;
        const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
        const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
        const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

        std::cout << "\n[+] Listing " << export_data->NumberOfNames << " exports from module at 0x"
            << std::hex << ntoskrnlBaseAddress << std::dec << "\n";
        std::cout << "========================================\n";

        for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
            const std::string function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));
            const auto function_ordinal = ordinal_table[i];
            const auto function_rva = function_table[function_ordinal];
            const auto function_address = ntoskrnlBaseAddress + function_rva;

            // Check if it's a forwarder
            bool is_forwarded = (function_address >= ntoskrnlBaseAddress + export_base &&
                function_address <= ntoskrnlBaseAddress + export_base + export_base_size);

            if (is_forwarded)
            {
                char forward_str[256] = { 0 };
                if (loader.ReadMemory(function_address, forward_str, sizeof(forward_str))) {
                    std::cout << std::setw(40) << std::left << function_name
                        << " -> " << forward_str << " (forwarded)\n";
                }
            }
            else
            {
                std::cout << std::setw(40) << std::left << function_name
                    << " @ 0x" << std::hex << function_address << std::dec << "\n";
            }
        }

        std::cout << "========================================\n";
        VirtualFree(export_data, 0, MEM_RELEASE);
    }

    void TestKernelMemAPI(IntelLoader& loader)
    {
        constexpr uint32_t MAGIC = 0xDEAD1337;

        std::wcout << L"[+] Test MmAllocateIndependentPagesEx(0x1000)\n";
        uint64_t base = loader.MmAllocateIndependentPagesEx(MAGIC);
        if (!base) { std::wcout << L"[-] alloc failed\n"; return; }
        std::wcout << L"[+] allocated at 0x" << std::hex << base << std::dec << L'\n';

        std::wcout << L"[+] Test MmSetPageProtection(RWX)\n";
        BOOLEAN ok = loader.MmSetPageProtection(base, MAGIC, PAGE_EXECUTE_READWRITE);
        std::wcout << (ok ? L"[+] protect OK\n" : L"[-] protect failed\n");

        
        uint8_t pattern = 0xCC;
        if (loader.WriteMemory(base, &pattern, sizeof(pattern)))
            std::wcout << L"[+] write byte OK\n";
        else
            std::wcout << L"[-] write failed\n";

        std::wcout << L"[+] Test MmFreeIndependentPages\n";
        BOOLEAN free = loader.MmFreeIndependentPages(base, MAGIC);
        std::wcout << (free ? L"[+] free OK\n" : L"[-] free failed\n");
    }

    VOID TestBestCandidates(IntelLoader& loader) 
    {
        const char* candidates[] = {""};

        uint64_t kernelBase = loader.GetNtoskrnlBaseAddress();

        printf("Checking sysgate candidates...\n");
        for (int i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) 
        {
            uint64_t kernelAddrNt = loader.GetKernelModuleExport(kernelBase, candidates[i]);
            std::string zwName = "Zw" + std::string(candidates[i] + 2);
            uint64_t kernelAddrZw = loader.GetKernelModuleExport(kernelBase, zwName.c_str());

            printf("%-25s: Nt=0x%p, Zw=0x%p\n",
                candidates[i], (void*)kernelAddrNt, (void*)kernelAddrZw);
        }
    }


    VOID AnalyzePrologues(IntelLoader& loader)
    {
        const char* candidates[] = {""};

        printf("=== functions prologue ===\n");

        for (int i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) 
        {
            uint64_t addr = loader.GetKernelModuleExport(loader.GetNtoskrnlBaseAddress(), candidates[i]);
            printf("\n%s (0x%p):\n", candidates[i], (void*)addr);

            if (addr) {
                BYTE prologue[16];
                if (loader.ReadMemory(addr, prologue, sizeof(prologue)))
                {
                    printf("  Prologue: ");
                    for (int j = 0; j < 12; j++)
                    {
                        printf("%02X ", prologue[j]);
                    }
                    printf("\n");

                    if (prologue[0] == 0x48 && prologue[1] == 0x8B && prologue[2] == 0xC4) 
                    {
                        printf("STANDARD (mov rax, rsp)\n");
                    }
                    else if (prologue[0] == 0x40 && prologue[1] == 0x53)
                    {
                        printf("STANDARD (push rbx)\n");
                    }
                    else if (prologue[0] == 0x48 && prologue[1] == 0x83 && prologue[2] == 0xEC)
                    {
                        printf("STANDARD (sub rsp, xx)\n");
                    }
                    else 
                    {
                        printf("NON-STANDARD\n");
                    }

                    
                    printf("Minimal size: %d/12 bytes\n", 12);
                }
                else 
                {
                    printf("Unable to read function prologue\n");
                }
            }
            else
            
            {
                printf("Address not found!\n");
            }
        }
    }

}