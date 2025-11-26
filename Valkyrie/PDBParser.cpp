#include "PDBParser.hpp"


bool PDBParser::Init()
{


    SymSetOptions(
        SYMOPT_UNDNAME |
        SYMOPT_LOAD_LINES |
        SYMOPT_DEBUG |
        SYMOPT_LOAD_ANYTHING |    
        SYMOPT_INCLUDE_32BIT_MODULES |
        SYMOPT_ALLOW_ABSOLUTE_SYMBOLS
    );

    const char* symbolPath = "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols";
    m_isInit = SymInitialize(GetCurrentProcess(), symbolPath, FALSE);

    if (!m_isInit)
    {
        std::cerr << "[-] SymInitialize failed (Error: " << GetLastError() << ")" << std::endl;
        return false;
    }

    std::cout << "[+] SymInitialize OK" << std::endl;
    return true;
}

bool PDBParser::LoadModule(const std::string& moduleName, uint64_t baseAddress)
{
    if (!m_isInit)
    {
        std::cerr << "[-] PDBParser not initialized!" << std::endl;
        return false;
    }


    std::string fullPath;

    // Might alredy have a path to it
    if (moduleName.find("\\") != std::string::npos || moduleName.find("/") != std::string::npos)
    {
        fullPath = moduleName;
    }
    else
    {
        // Fallback, trying to build /system32/ path
        char sysPath[MAX_PATH];
        GetSystemDirectoryA(sysPath, MAX_PATH);
        fullPath = std::string(sysPath) + "\\" + moduleName;
    }

    std::cout << "[DEBUG] Loading: " << fullPath << std::endl;
    std::cout << "[DEBUG] Base: 0x" << std::hex << baseAddress << std::dec << std::endl;


    DWORD fileAttrib = GetFileAttributesA(fullPath.c_str());
    if (fileAttrib == INVALID_FILE_ATTRIBUTES)
    {
        std::cerr << "[-] File not found: " << fullPath << std::endl;
        return false;
    }


    DWORD64 moduleBase = SymLoadModuleEx(
        GetCurrentProcess(),
        NULL,
        fullPath.c_str(),
        NULL,
        baseAddress,
        0,  // Size 0 = autodetect
        NULL,
        0
    );

    if (moduleBase == 0)
    {
        DWORD error = GetLastError();

        if (error == ERROR_SUCCESS)
        {
            std::cout << "[+] Module already loaded, retrieving base..." << std::endl;
            moduleBase = SymGetModuleBase64(GetCurrentProcess(), baseAddress);
        }

        if (moduleBase == 0) {
            std::cerr << "[-] Failed to load symbols (Error: " << error << ")" << std::endl;
            return false;
        }
    }

    m_moduleBaseAddresses[moduleName] = moduleBase;
    std::cout << "[+] Loaded symbols for " << moduleName
        << " (base: 0x" << std::hex << baseAddress << std::dec << ")" << std::endl;

    IMAGEHLP_MODULE64 modInfo = {};
    modInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

    if (SymGetModuleInfo64(GetCurrentProcess(), moduleBase, &modInfo))
    {
        std::cout << "[DEBUG] Symbol type: ";
        switch (modInfo.SymType) {
        case SymNone:
            std::cout << "None (NO SYMBOLS!)" << std::endl;
            return false;
        case SymExport:
            std::cout << "Export only" << std::endl;
            break;
        case SymPdb:
            std::cout << "PDB" << std::endl;
            break;
        case SymDeferred:
            std::cout << "Deferred - forcing load..." << std::endl;
            SymRefreshModuleList(GetCurrentProcess());
            break;
        default:
            std::cout << "Type " << modInfo.SymType << std::endl;
            break;
        }

        if (modInfo.LoadedPdbName[0])
            std::cout << "[+] PDB loaded: " << modInfo.LoadedPdbName << std::endl;    
    }
    else
    {
        std::cerr << "[-] SymGetModuleInfo64 failed" << std::endl;
        return false;
    }

    return true;
}

std::vector<SymbolData> PDBParser::ParseAllSymbols(const std::string& moduleFilter)
{
    std::vector<SymbolData> symbols;

    if (!m_isInit) 
    {
        std::cerr << "[-] PDBParser not initialized!" << std::endl;
        return symbols;
    }

    std::cout << "[DEBUG] Modules in map: " << m_moduleBaseAddresses.size() << std::endl;

    for (const auto& [moduleName, moduleBase] : m_moduleBaseAddresses)
    {

        if (moduleFilter != "*" && moduleName != moduleFilter) 
        {
            continue;
        }

        std::cout << "[DEBUG] Enumerating: " << moduleName
            << " @ 0x" << std::hex << moduleBase << std::dec << std::endl;



        EnumContext ctx = { &symbols, 0 };

        BOOL result = SymEnumSymbols(
            GetCurrentProcess(),
            moduleBase,
            "*",  // We want everything
            [](PSYMBOL_INFO si, ULONG size, PVOID context) -> BOOL {
                auto* ctx = static_cast<EnumContext*>(context);

                SymbolData data;
                data.name = si->Name;
                data.address = si->Address;
                data.moduleBase = si->ModBase;
                data.size = si->Size;
                data.type = (si->Flags & SYMFLAG_FUNCTION) ? "Function" : "Data";

                // Unmangle
                char undecorated[MAX_SYM_NAME] = { 0 };
                if (UnDecorateSymbolName(si->Name, undecorated, MAX_SYM_NAME, UNDNAME_NAME_ONLY)) {
                    data.undecoratedName = undecorated;
                }
                else
                {
                    data.undecoratedName = si->Name;
                }

                ctx->symbols->push_back(data);
                ctx->count++;

                return TRUE;
            },
            &ctx
        );

        if (!result)
        {
            DWORD error = GetLastError();
            std::cerr << "[-] SymEnumSymbols failed (Error: " << error << ")" << std::endl;
        }
        else {
            std::cout << "[+] Enumerated " << ctx.count << " symbols from " << moduleName << std::endl;
        }
    }

    return symbols;
}

json PDBParser::ExportToJson(const std::vector<SymbolData>& symbols)
{
    json j;

    j["metadata"]["export_date"] = GetCurrentTimestamp();
    j["metadata"]["symbol_server"] = "https://msdl.microsoft.com/download/symbols";
    j["metadata"]["version"] = "1.0";
    j["metadata"]["symbol_count"] = symbols.size();

    std::map<std::string, json> modules;

    for (const auto& symbol : symbols)
    {
        std::string moduleName = GetModuleNameByBase(symbol.moduleBase);

        if (modules.find(moduleName) == modules.end()) {
            modules[moduleName] = json::object();
            modules[moduleName]["base_address"] = FormatHex(symbol.moduleBase);
            modules[moduleName]["symbols"] = json::object();
        }

        json symbolJson;
        symbolJson["address"] = FormatHex(symbol.address);
        symbolJson["size"] = symbol.size;
        symbolJson["type"] = symbol.type;
        symbolJson["undecorated_name"] = symbol.undecoratedName;

        modules[moduleName]["symbols"][symbol.name] = symbolJson;
    }

    j["modules"] = modules;
    return j;
}



// Helpers
std::string PDBParser::GetModuleNameByBase(uint64_t baseAddress)
{
    for (const auto& [name, base] : m_moduleBaseAddresses)
    {
        if (base == baseAddress)
        {
            return name;
        }
    }
    return "Unknown";
}



PDBParser::~PDBParser()
{
    if (m_isInit)
    {
        SymCleanup(GetCurrentProcess());
    }
}