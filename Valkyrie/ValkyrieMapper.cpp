#include "ValkyrieMapper.hpp"
#include "StealthKit.hpp"

PIMAGE_NT_HEADERS64 ValkyrieMapper::GetNtHeadersValk(void* image_base) 
{
	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<ULONG64>(image_base) + dos_header->e_lfanew);

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	return nt_headers;
}

void ValkyrieMapper::ImageRebase(vec_relocs relocs, const ULONG64 delta) 
{
	for (const auto& current_reloc : relocs)
	{
		for (auto i = 0u; i < current_reloc.count; ++i) 
		{
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<ULONG64*>(current_reloc.address + offset) += delta;
		}
	}
}

vec_relocs ValkyrieMapper::GetRelocs(void* image_base)
{
	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeadersValk(image_base);

	if (!nt_headers)
		return {};

	vec_relocs relocs;
	DWORD reloc_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	if (!reloc_va)
		return {};

	auto current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<ULONG64>(image_base) + reloc_va);
	const auto reloc_end = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<ULONG64>(current_base_relocation) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	while (current_base_relocation < reloc_end && current_base_relocation->SizeOfBlock) {
		RelocInfo reloc_info;

		reloc_info.address = reinterpret_cast<ULONG64>(image_base) + current_base_relocation->VirtualAddress;
		reloc_info.item = reinterpret_cast<USHORT*>(reinterpret_cast<ULONG64>(current_base_relocation) + sizeof(IMAGE_BASE_RELOCATION));
		reloc_info.count = (current_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);

		relocs.push_back(reloc_info);

		current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<ULONG64>(current_base_relocation) + current_base_relocation->SizeOfBlock);
	}

	return relocs;
}



vec_imports ValkyrieMapper::GetImports(void* image_base)
{
	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeadersValk(image_base);

	if (!nt_headers)
		return {};

	DWORD import_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (!import_va)
		return {};

	vec_imports imports;

	auto current_import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<ULONG64>(image_base) + import_va);

	while (current_import_descriptor->FirstThunk) 
	{
		ImportInfo import_info;

		import_info.module_name = std::string(reinterpret_cast<char*>(reinterpret_cast<ULONG64>(image_base) + current_import_descriptor->Name));

		auto current_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<ULONG64>(image_base) + current_import_descriptor->FirstThunk);
		auto current_originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<ULONG64>(image_base) + current_import_descriptor->OriginalFirstThunk);

		while (current_originalFirstThunk->u1.Function) 
		{
			ImportFunctionInfo import_function_data;

			auto thunk_data = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<ULONG64>(image_base) + current_originalFirstThunk->u1.AddressOfData);

			import_function_data.name = thunk_data->Name;
			import_function_data.address = &current_first_thunk->u1.Function;

			import_info.function_datas.push_back(import_function_data);

			++current_originalFirstThunk;
			++current_first_thunk;
		}

		imports.push_back(import_info);
		++current_import_descriptor;
	}

	return imports;
}

bool ValkyrieMapper::ResolveImports(const vec_imports imports)
{
	for (const auto& mod : imports)
	{
		ULONG64 modBase = PEUtils::GetModuleBaseAddress(mod.module_name.c_str());
		if (!modBase)
		{
			LOG_ERROR(L"Dependency not found : " << std::wstring(mod.module_name.begin(), mod.module_name.end()));
			return false;
		}

		for (auto& fn : mod.function_datas)
		{
			ULONG64 addr = m_loader.GetKernelModuleExport(modBase, fn.name);
			if (!addr && modBase != m_loader.GetNtoskrnlBaseAddress())
				addr = m_loader.GetKernelModuleExport(m_loader.GetNtoskrnlBaseAddress(), fn.name);

			if (!addr)
			{
				LOG_ERROR(L"Unresolved import : " << std::wstring(fn.name.begin(), fn.name.end())
					<< L" (" << std::wstring(mod.module_name.begin(), mod.module_name.end()) << L")");
			}

			*fn.address = addr;
		}
	}
	return true;

}



ULONG64 ValkyrieMapper::MapDriver(PEImage& drvImage, ULONG64 arg1, ULONG64 arg2, BOOL freeMemAfterUse, BOOL noHeaderScramble,
    AllocationMode mode, BOOL PassAllocationAddressAsFirstParam,NTSTATUS* exitCode)
{
    void* localBase = VirtualAlloc(nullptr, drvImage.imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!localBase)
    {
        LOG_ERROR("VirtualAlloc failed");
        return 0;
    }

    // PE headers
    memcpy(localBase, drvImage.rawData.data(), drvImage.ntHeaders->OptionalHeader.SizeOfHeaders);

  
    // Allocating kernel pages
    ULONG32 allocSize = (drvImage.imageSize + 0xFFF) & ~0xFFF; // Aligned 0x1000
    ULONG64 kernelBase = m_loader.MmAllocateIndependentPagesEx(allocSize);
    if (!kernelBase)
    {
        LOG_ERROR("Kernel allocation failed"); 
        VirtualFree(localBase, 0, MEM_RELEASE);
        return 0;
    }

    LOG_SUCCESS_HEX("Kernel base : ", kernelBase);

	// sections
	for (const auto& sec : drvImage.sections)
	{
		if (sec.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) continue;
		if (sec.SizeOfRawData == 0) continue;

		void* dst = (BYTE*)localBase + sec.VirtualAddress;
		const void* src = drvImage.rawData.data() + sec.PointerToRawData;
		memcpy(dst, src, sec.SizeOfRawData);
	}

	ImageRebase(GetRelocs(localBase), kernelBase - drvImage.ntHeaders->OptionalHeader.ImageBase);
	if (!FixSecurityCookie(localBase, kernelBase))
	{
		LOG_ERROR("Failed to fix security cookie.");
	}
	else if(!ResolveImports(GetImports(localBase)))
	{
		LOG_ERROR("Failed to resolve one or more imports.");
	}


	// Page to RW
	LOG_SUCCESS("MmSetPageProtection(0x" << std::hex << kernelBase
		<< L", 0x" << std::hex << allocSize << L", RW)");
	if (!m_loader.MmSetPageProtection(kernelBase, allocSize, PAGE_READWRITE))
	{
		LOG_ERROR("MmSetPageProtection RW failed.");
	}


	// Write to prevously allocated page
	std::wcout << L"[DEBUG] WriteMemory(0x" << std::hex << kernelBase
		<< L", 0x" << reinterpret_cast<ULONG64>(localBase)
		<< L", 0x" << allocSize << L")\n";
	if (!m_loader.WriteMemory(kernelBase, localBase, allocSize))
	{
		LOG_ERROR("WriteMemory failed");
	}


	// Calculate safely header from the parsed PE, then scramble with junk bytes.
	if (!noHeaderScramble) // Branch is a bit confusing. By default we always scramble the header, but if                        
		                   // this arg is set to true by the user we leave the header intact.
	{
		JumpLine();
		LOG_INFO("Scrambling driver header before mapping...");
		uint32_t headerSize = drvImage.ntHeaders->OptionalHeader.SizeOfHeaders;
		
		auto junkBytes = X64Assembler::CreateNopSlide(headerSize);

		if (!m_loader.WriteMemory(kernelBase, junkBytes.data(), headerSize))
		{
			LOG_ERROR("Cannot write junk bytes into driver header.");
		}
		else
			LOG_SUCCESS_HEX("Scrambled bytes : ", headerSize);
	}

	// Fixing protection
	JumpLine();
	LOG_INFO("Fixing sections permissions...");
	JumpLine();

	for (const auto& sec : drvImage.sections)
	{
		char name[9] = { 0 };
		memcpy(name, sec.Name, 8);

		ULONG prot = PAGE_READONLY;

		if (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			prot = (sec.Characteristics & IMAGE_SCN_MEM_WRITE) ?
				PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
		}
		else if (sec.Characteristics & IMAGE_SCN_MEM_WRITE)
		{
			prot = PAGE_READWRITE;
		}

		ULONG64 sectionAddress = kernelBase + sec.VirtualAddress;
		ULONG32 sectionSize = (sec.Misc.VirtualSize + 0xFFF) & ~0xFFF; // Aligned

		//LOG_SUCCESS(L"Section : " << std::wstring(name, name + strnlen(name, 8)));
		//LOG_SUCCESS_HEX("RVA", sec.VirtualAddress);
		//LOG_SUCCESS_HEX("Kernel addr", kernelBase + sec.VirtualAddress);
		//LOG_SUCCESS_HEX("Size", static_cast<ULONG32>((sec.Misc.VirtualSize + 0xFFF) & ~0xFFF));
		//LOG_SUCCESS_HEX("Prot", prot);

		if (!m_loader.MmSetPageProtection(sectionAddress, sectionSize, prot))
		{
			LOG_ERROR("Failed to set protection for section " << std::wstring(name, name + strnlen(name, 8)));
		}
		else
		{
			LOG_SUCCESS("Protection applied successfully !");
		}
	}

	ULONG64 DriverEntryPoint = kernelBase + drvImage.ntHeaders->OptionalHeader.AddressOfEntryPoint;

	if (DriverEntryPoint != kernelBase)
	{
		LOG_SUCCESS_HEX("Calling driver entrypoint at : ", DriverEntryPoint);
		NTSTATUS status = 0;

		if (!m_loader.CallKernelFunction(m_loader.GetNtoskrnlBaseAddress(), &status, DriverEntryPoint, arg1, arg2))
		{
			LOG_ERROR("Driver entrypoint call failed");
			VirtualFree(localBase, 0, MEM_RELEASE);
			if (freeMemAfterUse)
				m_loader.MmFreeIndependentPages(kernelBase, allocSize);
			return 0;
		}


		if (exitCode)
			*exitCode = status;

	}

	VirtualFree(localBase, 0, MEM_RELEASE);


	// Free kernel pages if this is a non persistent driver.
	if (freeMemAfterUse)
	{
		JumpLine();
		LOG_INFO("Freeing kernel pages...");

		if (!m_loader.MmFreeIndependentPages(kernelBase, allocSize))
		{
			LOG_ERROR("Cannot free driver allocated pages !");
			return 1;
		}

		LOG_SUCCESS("Successfully unallocated pages.");
			
		return 0;
	}

	LOG_SUCCESS("Driver successfully loaded and persistent.");
	return kernelBase;

}


// Make the driver GS compatible and bypass stack security checks.
bool ValkyrieMapper::FixSecurityCookie(void* local_image, ULONG64 kernel_image_base)
{
	auto headers = GetNtHeadersValk(local_image);
	if (!headers)
		return false;

	uintptr_t image_size = headers->OptionalHeader.SizeOfImage;
	uintptr_t local_base = (uintptr_t)local_image;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		LOG_INFO("Load config directory not found or cookie not set. Skipping...");
		return true;
	}

	// Added security check. Now verifying if LOAD_CONFIG dir is in image bound.
	if (load_config_directory >= image_size - sizeof(IMAGE_LOAD_CONFIG_DIRECTORY))
	{
		LOG_ERROR("Load config directory is out of bound !");
		return false; // Should fail
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		LOG_SUCCESS("StackCookie not defined, fix cookie skipped");
		return true; // Normal behavior if the driver wasn't built with /GS
	}


	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image;

	// Default magic number set by the linker at runtime.
	// Since this is manual mapping, this should not have beed modified/set by anything else or something wrong.
	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232)
	{
		LOG_ERROR("StackCookie already modified or corrupt. Aborting");
		return false;
	}

	JumpLine();
	LOG_INFO("Security checks done. Generating StackCookie now...");
	JumpLine();

	auto new_cookie = []() -> uint64_t {

		LARGE_INTEGER perf;
		QueryPerformanceCounter(&perf);

		return 0x2B992DDFA232 ^
			(static_cast<long long>(GetCurrentProcessId()) << 16) ^
			(static_cast<long long>(GetCurrentThreadId()) << 32) ^
			(GetTickCount64() << 48) ^
			perf.QuadPart;
		}();

	*(uintptr_t*)(stack_cookie) = new_cookie;

	LOG_SUCCESS("New stack cookie generated successfully.");

	return true;
}