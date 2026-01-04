#pragma once

#include "Common.hpp"
#include "Win.hpp"
#include "IntelLoader.hpp"

class Experimental
{
public:

	explicit Experimental(IntelLoader& loader) : m_loader(loader) {}

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

		const auto usrFunction = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtSetInformationThread"));
		if (!usrFunction) { std::wcout << L"NtSetInformationThread not found\n"; return false; }

		const uint64_t kernelFunction = m_loader.GetKernelModuleExport(KernelBase, "NtSetInformationThread");
		if (!kernelFunction) { std::wcout << L"kernel NtSetInformationThread not found\n"; return false; }

		uint8_t original[12] = {};
		if (!m_loader.ReadMemory(kernelFunction, original, 12)) { std::wcout << L"ReadMemory original failed\n"; return false; }

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

		if (!m_loader.WriteToReadOnlyMemory(kernelFunction, hook, 12)) { std::wcout << L"Write hook failed\n"; return false; }

		using FunctionFn = T(__stdcall*)(A...);
		const auto fn = reinterpret_cast<FunctionFn>(usrFunction);

		if constexpr (is_void) {
			fn(arguments...);
			std::wcout << L"Void call done\n";
		}
		else {
			*out_result = fn(arguments...);
			std::wcout << L"Call returned 0x" << std::hex << *out_result << L"\n";
		}

		bool ok = m_loader.WriteToReadOnlyMemory(kernelFunction, original, 12);
		std::wcout << (ok ? L"Restore OK\n" : L"Restore FAILED\n");
		return ok;
	}

private:
	IntelLoader m_loader;
};