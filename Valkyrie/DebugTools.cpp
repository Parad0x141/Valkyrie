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