#pragma once
#include "Common.hpp"
#include "Helpers.hpp"
#include <dbghelp.h>

#include "../Valkyrie/External/Json/json.hpp"

#pragma comment(lib, "dbghelp.lib") // Needed to parse symbols


using json = nlohmann::json;



 typedef struct SymbolData
{
	std::string name;
	std::string moduleName;
	std::string type;
	std::string undecoratedName;
	uint64_t address;
	uint64_t moduleBase;
	ULONG size;
} SymbolData, *PSymbolData ;

 // Only used to count 
 struct EnumContext
 {
	 std::vector<SymbolData>* symbols;
	 size_t count;
 };


class PDBParser
{
private:

	std::wstring m_SymbolPath;
	bool m_isInit = false;
	std::map<std::string, uint64_t> m_moduleBaseAddresses;
	std::string GetModuleNameByBase(uint64_t baseAddress);

public:

	bool Init();
	bool LoadModule(const std::string& moduleName, uint64_t baseAddress);
	std::vector<SymbolData> ParseAllSymbols(const std::string& moduleFilter = "*");
	json ExportToJson(const std::vector<SymbolData>& symbols);


	// Not impl yet
	bool SaveToFile(const std::string& filename, const std::vector<SymbolData>& symbols);

	~PDBParser();
};