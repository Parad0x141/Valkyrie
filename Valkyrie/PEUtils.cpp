#include "PEUtils.hpp"

namespace PEUtils
{
    typedef struct _vRTL_PROCESS_MODULE_INFORMATION
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];

    } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

    typedef struct _vRTL_PROCESS_MODULES
    {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];

    }   RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


    uint64_t GetModuleBaseAddress(const char* moduleName)
    {
        ULONG bufferSize = 0;

        // Get required buffer size
        NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &bufferSize); // 11 = SystemModuleInformation

        if (bufferSize == 0) {
            std::cout << "[-] Failed to get buffer size for kernel modules\n";
            return 0;
        }

        auto buffer = std::make_unique<BYTE[]>(bufferSize);
        PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)buffer.get();

        NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, modules, bufferSize, &bufferSize);
        if (!NT_SUCCESS(status)) {
            std::cout << "[-] NtQuerySystemInformation failed: 0x" << std::hex << status << "\n";
            return 0;
        }

        for (ULONG i = 0; i < modules->NumberOfModules; i++) {
            auto module = &modules->Modules[i];
            char* fileName = (char*)module->FullPathName + module->OffsetToFileName;

            if (_stricmp(fileName, moduleName) == 0) {
                std::cout << "[+] Found " << moduleName << " at 0x" << std::hex << (uint64_t)module->ImageBase << std::dec << "\n";
                return (uint64_t)module->ImageBase;
            }
        }

        std::cout << "[-] Module " << moduleName << " not found\n";
        return 0;
    }

    std::vector<BYTE> ReadFileByte(const std::wstring& filePath)
    {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file)
            return {};

        const auto size = file.tellg();
        if (size == 0 || size == std::streampos(-1))
            return {};

        file.seekg(0, std::ios::beg);

        std::vector<BYTE> buffer(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
            return {};

        return buffer;
    }


    DWORD RvaToFileOffset(PIMAGE_NT_HEADERS64 ntHeaders, DWORD rva)
    {
        auto section = IMAGE_FIRST_SECTION(ntHeaders);

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        {
            if (rva >= section[i].VirtualAddress &&
                rva < section[i].VirtualAddress + section[i].Misc.VirtualSize)
            {
                return rva - section[i].VirtualAddress + section[i].PointerToRawData;
            }
        }

        return rva;
    }


    /// <summary>
    /// X64 PE Parser.
    /// </summary>
    /// <param name="PEPath"></param>
    /// <returns> A PEImage struct unique pointer.</returns>
    std::unique_ptr<PEImage> ParsePE(const std::string& PEPath)
    {
        auto peImage = std::make_unique<PEImage>();

        std::ifstream file(PEPath, std::ios::binary | std::ios::ate);
        if (!file.is_open())
        {
            std::wcout << L"[-] Failed to open file\n";
            return nullptr;
        }

        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        peImage->rawData.resize(fileSize);
        if (!file.read(reinterpret_cast<char*>(peImage->rawData.data()), fileSize))
        {
            std::wcout << L"[-] Failed to read file\n";
            return nullptr;
        }

        if (fileSize < sizeof(IMAGE_DOS_HEADER))
        {
            std::wcout << L"[-] File too small for DOS header\n";
            return nullptr;
        }

        peImage->dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peImage->rawData.data());
        if (peImage->dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            std::wcout << L"[-] Invalid DOS signature\n";
            return nullptr;
        }

        if (peImage->dosHeader->e_lfanew >= fileSize ||
            peImage->dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize)
        {
            std::wcout << L"[-] Invalid e_lfanew offset\n";
            return nullptr;
        }

        peImage->ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            peImage->rawData.data() + peImage->dosHeader->e_lfanew);

        if (peImage->ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            std::wcout << L"[-] Invalid NT signature\n";
            return nullptr;
        }
        if (peImage->ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            std::wcout << L"[-] PE is not x64\n";
            return nullptr;
        }

        peImage->imageSize = peImage->ntHeaders->OptionalHeader.SizeOfImage;

        auto sectionHeader = IMAGE_FIRST_SECTION(peImage->ntHeaders);
        WORD numSections = peImage->ntHeaders->FileHeader.NumberOfSections;

        if (reinterpret_cast<uint8_t*>(sectionHeader) +
            numSections * sizeof(IMAGE_SECTION_HEADER) >
            peImage->rawData.data() + fileSize)
        {
            std::wcout << L"[-] Invalid section headers\n";
            return nullptr;
        }

        peImage->sections.assign(sectionHeader, sectionHeader + numSections);
        LOG_SUCCESS("Found " << numSections << " sections:");
        for (const auto& sec : peImage->sections)
        {
            char name[9] = { 0 };
            memcpy(name, sec.Name, 8);
            LOG_SUCCESS("    " << std::wstring(name, name + strnlen(name, 8))
                << " - VirtualSize: 0x" << std::hex << sec.Misc.VirtualSize
                << ", RawSize: 0x" << sec.SizeOfRawData << std::dec);
        }

        auto& relocDir = peImage->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size)
        {
            DWORD relocOffset = RvaToFileOffset(peImage->ntHeaders, relocDir.VirtualAddress);
            if (relocOffset + relocDir.Size <= fileSize)
            {
                peImage->relocationData.assign(
                    peImage->rawData.begin() + relocOffset,
                    peImage->rawData.begin() + relocOffset + relocDir.Size);
                std::wcout << L"[+] Relocation data: " << relocDir.Size << L" bytes\n";
            }
            else
            {
                std::wcout << L"[!] Warning: Invalid relocation directory\n";
            }
        }
        else
        {
            std::wcout << L"[!] Warning: No relocations (PE may not be relocatable)\n";
        }

        auto& importDir = peImage->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!importDir.Size || !importDir.VirtualAddress)
        {
            std::wcout << L"[!] No imports found\n";
        }
        else
        {
            DWORD importOffset = RvaToFileOffset(peImage->ntHeaders, importDir.VirtualAddress);
            if (importOffset >= fileSize)
            {
                std::wcout << L"[!] Invalid import directory RVA\n";
            }
            else
            {
                auto* importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                    peImage->rawData.data() + importOffset);

                while (importDesc->Name)
                {
                    DWORD nameOffset = RvaToFileOffset(peImage->ntHeaders, importDesc->Name);
                    if (nameOffset >= fileSize) break;

                    PEImage::Import import;
import.moduleName = reinterpret_cast<const char*>(
                    peImage->rawData.data() + nameOffset);

                    DWORD thunkRva = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk
                        : importDesc->FirstThunk;
                    DWORD thunkOffset = RvaToFileOffset(peImage->ntHeaders, thunkRva);
                    if (thunkOffset >= fileSize) { ++importDesc; continue; }

                    auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(
                        peImage->rawData.data() + thunkOffset);

                    while (thunk->u1.AddressOfData)
                    {
                        if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                        {
import.ordinals.push_back(IMAGE_ORDINAL(thunk->u1.Ordinal));
import.functions.push_back("");
                        }
                        else
                        {
                            DWORD nameRva = static_cast<DWORD>(thunk->u1.AddressOfData);
                            DWORD funcNameOffset = RvaToFileOffset(peImage->ntHeaders, nameRva);
                            if (funcNameOffset + sizeof(IMAGE_IMPORT_BY_NAME) > fileSize) break;

                            auto* byName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                                peImage->rawData.data() + funcNameOffset);
import.functions.push_back(byName->Name);
import.ordinals.push_back(0);
                        }
                        ++thunk;
                    }

                    peImage->imports.push_back(std::move(import));
                    ++importDesc;
                }

                std::wcout << L"[+] Found " << peImage->imports.size() << L" imported modules:\n";
                for (const auto& imp : peImage->imports)
                {
                    std::wstring wMod(imp.moduleName.begin(), imp.moduleName.end());
                    std::wcout << L"    " << wMod << L"  (" << imp.functions.size() << L" functions)\n";
                    for (size_t i = 0; i < imp.functions.size(); ++i)
                    {
                        if (imp.ordinals[i])
                        {
                            std::wcout << L"        Ordinal " << imp.ordinals[i] << L'\n';
                        }
                        else
                        {
                            std::wstring wfn(imp.functions[i].begin(), imp.functions[i].end());
                            std::wcout << L"        " << wfn << L'\n';
                        }
                    }
                }
                std::wcout << std::flush;
            }
        }


        auto& exportDir = peImage->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.Size && exportDir.VirtualAddress)
        {
            DWORD exportOffset = RvaToFileOffset(peImage->ntHeaders, exportDir.VirtualAddress);
            if (exportOffset + sizeof(IMAGE_EXPORT_DIRECTORY) <= fileSize)
            {
                auto* exportData = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(peImage->rawData.data() + exportOffset);

                const auto nameRVAs = (uint32_t*)(peImage->rawData.data() + RvaToFileOffset(peImage->ntHeaders, exportData->AddressOfNames));
                const auto ordinals = (uint16_t*)(peImage->rawData.data() + RvaToFileOffset(peImage->ntHeaders, exportData->AddressOfNameOrdinals));
                const auto funcRVAs = (uint32_t*)(peImage->rawData.data() + RvaToFileOffset(peImage->ntHeaders, exportData->AddressOfFunctions));

                for (uint32_t i = 0; i < exportData->NumberOfNames; ++i)
                {
                    PEImage::Export ex;
                    ex.exportName = (const char*)(peImage->rawData.data() + RvaToFileOffset(peImage->ntHeaders, nameRVAs[i]));
                    ex.ordinal = ordinals[i];
                    ex.rva = funcRVAs[ex.ordinal];

                   
                    if (ex.rva >= exportDir.VirtualAddress && ex.rva < exportDir.VirtualAddress + exportDir.Size)
                    {
                        ex.isForwarded = true;

                        DWORD forwardOffset = RvaToFileOffset(peImage->ntHeaders, ex.rva);

                        if (forwardOffset < fileSize)
                            ex.forwardName = (const char*)(peImage->rawData.data() + forwardOffset);
                    }

                    peImage->exports.push_back(std::move(ex));
                }
                std::wcout << L"[+] Exports: " << peImage->exports.size() << L" named functions\n";

            }
        }

        auto& tlsDir = peImage->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir.Size) std::wcout << L"[!] Driver has TLS callbacks, TLS callbacks are NOT supported.\n";

        auto& excDir = peImage->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir.Size) std::wcout << L"[+] Exception directory: " << excDir.Size << L" bytes\n";

        LOG_SUCCESS_HEX("PE parsing done  - ImageSize: ", peImage->imageSize);

        return peImage;
    }

    

    BOOL ValidateDriverPE(const PEImage& PEImage)
    {
        std::wcout << L"Validating driver PE...\n";

        // Must be a x64 driver
        if (PEImage.ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            std::wcout << L"[-] FAILED ! Not a 64-bit PE file\n";
            return FALSE;
        }

        // Subsystem check if != NATIVE, not a driver
        if (PEImage.ntHeaders->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE)
        {
            std::wcout << L"[-]FAILED ! Not a native driver\n";
            return FALSE;
        }


        // Does it have an entry point ?
        if (PEImage.ntHeaders->OptionalHeader.AddressOfEntryPoint == 0) 
        {
            LOG_SUCCESS("[-] FAILED ! No DriverEntry");
            return FALSE;
        }

        // Image size
        if (PEImage.ntHeaders->OptionalHeader.SizeOfImage < 0x1000)
        {
           LOG_SUCCESS("[-] FAILED ! Image size too small");
            return FALSE;
        }

        // Sections check
        struct SectionCheck
        {
            const char* name;
            bool required;
        } sections[] =
        
        {
            { ".text", true },
            { ".data", false }
        };

        for (const auto& check : sections)
        {
            bool found = false;
            for (const auto& sec : PEImage.sections) 
            {
                
                char secName[9] = { 0 };
                strncpy_s(secName, sizeof(secName), (const char*)sec.Name, 8);

                if (strncmp(secName, check.name, strlen(check.name)) == 0) {
                    found = true;
                    break;
                }
            }

            if (check.required && !found) 
            {
                LOG_ERROR("Missing required section: " << check.name);
                return FALSE;
            }
        }

        LOG_SUCCESS("Driver PE validation passed");
        return TRUE;
    }


    std::vector<uint8_t> ReadFile(const std::wstring& filePath)
    {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);

        if (!file.is_open())
        {
            std::cout << "[-] Error, failed to read file.";
            return {};
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(size);
        if (!file.read((char*)buffer.data(), size))
        {
            std::wcout << L"[-] Error, failed to read file\n";
        }

        std::wcout << L"[+] Read " << size << L"bytes from" << filePath << L"\n";

        return buffer;
    }
}

