#include "PEUtils.hpp"
#include <vector>
#include <fstream>

namespace PEUtils
{

	uint64_t GetModuleBaseAddress(const char* moduleName)
	{
		ULONG bufferSize = 0;

		// Get required buffer size
		NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &bufferSize); // 11 = SystemModuleInformation

		if (bufferSize == 0)
		{
			LOG_ERROR("Failed to get module buffer size .");
			return 0;
		}

		auto buffer = std::make_unique<BYTE[]>(bufferSize);
		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)buffer.get();

		NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, modules, bufferSize, &bufferSize);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR_HEX("NtQuerySystemInformation failed with error code ", status);
			return 0;
		}

		for (ULONG i = 0; i < modules->NumberOfModules; i++)
		{
			auto module = &modules->Modules[i];
			char* fileName = (char*)module->FullPathName + module->OffsetToFileName;

			if (_stricmp(fileName, moduleName) == 0)
			{
				return (uint64_t)module->ImageBase;
			}
		}

		LOG_ERROR("Module not found : " << std::wstring(moduleName, moduleName + strlen(moduleName)));
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
			LOG_ERROR("Failed to open file");
			return nullptr;
		}

		size_t fileSize = file.tellg();
		file.seekg(0, std::ios::beg);

		peImage->rawData.resize(fileSize);
		if (!file.read(reinterpret_cast<char*>(peImage->rawData.data()), fileSize))
		{
			LOG_ERROR("Failed to read file.");
			return nullptr;
		}

		if (fileSize < sizeof(IMAGE_DOS_HEADER))
		{
			LOG_ERROR("File too small for DOS headers.");
			return nullptr;
		}

		peImage->dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peImage->rawData.data());
		if (peImage->dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			LOG_ERROR("Invalid DOS signature.");
			return nullptr;
		}

		if (peImage->dosHeader->e_lfanew >= fileSize ||
			peImage->dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize)
		{
			LOG_ERROR("Invalid e_lfanew offset.");
			return nullptr;
		}

		peImage->ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(
			peImage->rawData.data() + peImage->dosHeader->e_lfanew);

		if (peImage->ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			LOG_ERROR("Invalid NT signature.");
			return nullptr;
		}
		if (peImage->ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		{
			LOG_ERROR("PE is not X64. Valkyrie only support X64 drivers.");
			return nullptr;
		}

		peImage->imageSize = peImage->ntHeaders->OptionalHeader.SizeOfImage;

		auto sectionHeader = IMAGE_FIRST_SECTION(peImage->ntHeaders);
		WORD numSections = peImage->ntHeaders->FileHeader.NumberOfSections;

		if (reinterpret_cast<uint8_t*>(sectionHeader) +
			numSections * sizeof(IMAGE_SECTION_HEADER) >
			peImage->rawData.data() + fileSize)
		{
			LOG_ERROR("Invalid section header.");
			return nullptr;
		}

		peImage->sections.assign(sectionHeader, sectionHeader + numSections);
		
		for (const auto& sec : peImage->sections)
		{
			char name[9] = { 0 };
			memcpy(name, sec.Name, 8);
			
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
				
			}
			else
			{
				LOG_ERROR("Invalid relocation data directory.");
				return nullptr;
			}
		}
		else
		{
			LOG_ERROR("No relocation data found. Aborting.");
			return nullptr;
		}

		auto& importDir = peImage->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!importDir.Size || !importDir.VirtualAddress)
		{
			// Should fail, a driver not importing anything is odd.
			LOG_ERROR("No imports found in PE.");
			return nullptr;
		}
		else
		{
			DWORD importOffset = RvaToFileOffset(peImage->ntHeaders, importDir.VirtualAddress);
			if (importOffset >= fileSize)
			{
				LOG_ERROR("Invalid import directory.");
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
			}
		}

		auto& tlsDir = peImage->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (tlsDir.Size) LOG_WARNING("Driver has TLS callback, this is NOT supported by Valkyrie !");

		auto& excDir = peImage->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excDir.Size) std::wcout << L"[+] Exception directory: " << excDir.Size << L" bytes\n";

		LOG_SUCCESS_HEX("PE parsing done. ImageSize: ", peImage->imageSize);

		return peImage;
	}

	



	BOOL ValidateDriverPE(const PEImage& PEImage)
	{
		LOG_INFO("Validating PE...");

		// Must be a x64 PE
		if (PEImage.ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			LOG_ERROR("Validation failed. File is not a X64 PE.");
			return FALSE;
		}

		// Subsystem check if != NATIVE, not a driver
		if (PEImage.ntHeaders->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE)
		{
			LOG_ERROR("Validation failed. File is not a X64 driver.");
			return FALSE;
		}


		// Does it have an entry point ?
		if (PEImage.ntHeaders->OptionalHeader.AddressOfEntryPoint == 0)
		{
			LOG_ERROR("Validation failed. No driver entry point found.");
			return FALSE;
		}

		// Image size
		if (PEImage.ntHeaders->OptionalHeader.SizeOfImage < 0x1000)
		{
			LOG_ERROR("Validation failed. File size is too small.");
			return FALSE;
		}

		// Sections check
		struct SectionCheck
		{
			const char* name;
			bool required;
		}

		sections[] =
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

		LOG_SUCCESS("Driver PE validation passed, loader ready to map !");
		return TRUE;
	}


	std::vector<uint8_t> ReadFile(const std::wstring& filePath)
	{
		std::ifstream file(filePath, std::ios::binary | std::ios::ate);

		if (!file.is_open())
		{
			LOG_ERROR("Failed to read file.");
			return {};
		}

		std::streamsize size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::vector<uint8_t> buffer(size);
		if (!file.read((char*)buffer.data(), size))
		{
			LOG_ERROR("Failed to read file.");
		}

		LOG_SUCCESS("Read " << size << L" bytes from " << filePath);

		return buffer;
	}

	void PEUtils::ShowPEDetails(const PEImage& pe, std::wstring driverName)
	{
		system("cls");
		if (!pe.ntHeaders) return;
		
		std::wcout << L" D R I V E R   S U M M A R Y\n"
			L"=============================\n";
		std::wcout << "\n";

		LOG_SUCCESS("Driver : " << driverName);
		std::wcout << "\n";

		LOG_SUCCESS(L"[ Meta-data ]");
		std::wcout << "\n";

		LOG_INFO_HEX("Image size      ",pe.imageSize);
		LOG_INFO_HEX("Entry-point RVA ",(pe.ntHeaders->OptionalHeader.AddressOfEntryPoint));
		LOG_INFO_HEX("Image base      ",(pe.ntHeaders->OptionalHeader.ImageBase));
		LOG_INFO_HEX("Checksum        ",(pe.ntHeaders->OptionalHeader.CheckSum));
		LOG_INFO_HEX("Subsystem       ",(pe.ntHeaders->OptionalHeader.Subsystem));
		LOG_INFO_HEX("DLL chars       ",(pe.ntHeaders->OptionalHeader.DllCharacteristics));
		std::wcout << "\n";

		/* -----  SECTIONS  ----- */
		LOG_SUCCESS(L"[ Sections : " + std::to_wstring(pe.sections.size()) + L" ]");
		std::wcout << "\n";

		for (const auto& sec : pe.sections)
		{
			wchar_t name[9] = { 0 };
			for (int k = 0; k < 8; ++k) name[k] = static_cast<wchar_t>(sec.Name[k]);

			std::wstring line = L"  +- [" + std::wstring(name, 8) + L"]  "
				L"RVA : " + ToHexW(sec.VirtualAddress) + L"  "
				L"Size : " + ToHexW(sec.SizeOfRawData) + L"  "
				L"Flags : " + ToHexW(sec.Characteristics);
			LOG_INFO(line);

		}
		std::wcout << "\n";

		/* -----  IMPORTS  ----- */
		LOG_SUCCESS(L"[ Imports : " + std::to_wstring(pe.imports.size()) + L" ]");
		std::wcout << "\n";

		if (pe.imports.empty())
		{
			LOG_INFO(L"  (none)");
		}
		else
		{
			for (const auto& imp : pe.imports)
			{
				std::wstring wmod(imp.moduleName.begin(), imp.moduleName.end());
				LOG_SUCCESS(L"  + " + wmod + L"  (" + std::to_wstring(imp.functions.size()) + L" funcs)");
				for (size_t i = 0; i < imp.functions.size() && i < 5; ++i)
				{
					std::wstring wfn(imp.functions[i].begin(), imp.functions[i].end());
					LOG_INFO(L"      |- " + wfn);
				}
				if (imp.functions.size() > 5)
					LOG_INFO(L"      ... (" + std::to_wstring(imp.functions.size() - 5) + L" more)");
			}
			std::wcout << "\n";
		}

		LOG_SUCCESS(L"[ Exports : " + std::to_wstring(pe.exports.size()) + L" ]");
		std::wcout << "\n";

		if (pe.exports.empty())
		{
			LOG_WARNING(L"No exports found ! Skipping...");
			std::wcout << "\n";
		}
		else
		{
			size_t syscallCount = std::count_if(pe.exports.begin(), pe.exports.end(),
				[](const auto& e) { return e.isSyscall(); });
			LOG_INFO(L"  Syscall stubs : " + std::to_wstring(syscallCount));
			for (size_t i = 0; i < pe.exports.size() && i < 8; ++i)
			{
				std::wstring wname(pe.exports[i].exportName.begin(), pe.exports[i].exportName.end());
				LOG_INFO(L"      |- " + wname + L" (ord " + std::to_wstring(pe.exports[i].ordinal) + L")");
			}
			if (pe.exports.size() > 8)
				LOG_INFO(L"      ... (" + std::to_wstring(pe.exports.size() - 8) + L" more)");
		}

		LOG_SUCCESS(L"[ Relocations ]");
		std::wcout << "\n";

		LOG_INFO(L"  Size : " + std::to_wstring(pe.relocationData.size()) + L" bytes");
		std::wcout << "\n";

		LOG_SUCCESS(L"[ Security ]");
		std::wcout << "\n";

		auto& cfg = pe.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
		if (cfg.Size)
		{
			LOG_INFO(L"  Load-config present  (GS enabled)");
			std::wcout << "\n";
		}
		else
		{
			LOG_WARNING(L"No load-config  (no GS)");
			std::wcout << "\n";
		}

		LOG_INFO("Press ENTER to continue...");
		std::wcin.get();
		
			
	}
}

