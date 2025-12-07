#pragma once
#include "Common.hpp"
#include "IntelLoader.hpp"



class PEImage {
public:
    uint64_t imageSize;

    std::vector<uint8_t> rawData;

    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS64 ntHeaders;

    std::vector<IMAGE_SECTION_HEADER> sections;
    std::vector<uint8_t> relocationData;

    struct Export
    {
        std::string exportName = "";
        uint32_t rva = 0;
        uint16_t ordinal = 0;
        bool isForwarded = 0;
        std::string forwardName = "";

        bool isSyscall() const
        {
            return !exportName.empty() &&
                (exportName.rfind("Nt", 0) == 0 ||
                    exportName.rfind("Zw", 0) == 0);
        }

    };

    struct Import
    {
        std::string moduleName = "";
        std::vector<std::string> functions;
        std::vector<uint16_t> ordinals;
    };

    std::vector<Import> imports;
    std::vector<Export> exports;

  

  

    PEImage() : dosHeader(nullptr), ntHeaders(nullptr), imageSize(0) {}

};

namespace PEUtils
{
    std::unique_ptr<PEImage> ParsePE(const std::string& driverPath);
    BOOL ValidateDriverPE(const PEImage& PEImage);

    DWORD RvaToFileOffset(PIMAGE_NT_HEADERS64 ntHeaders, DWORD rva);
    uint64_t GetModuleBaseAddress(const char* moduleName);
    std::vector<BYTE> ReadFileByte(const std::wstring& filePath);
    std::vector<uint8_t> ReadFile(const std::wstring& filePath);
    VOID ShowPEDetails(const PEImage& pe, std::wstring driverName);
}