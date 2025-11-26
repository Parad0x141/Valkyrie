#pragma once

#include "Common.hpp"



struct RelocInfo
{
	ULONG64 address;
	USHORT* item;
	ULONG32 count;
};

struct ImportFunctionInfo
{
	std::string name;
	ULONG64* address;
};

struct ImportInfo
{
	std::string module_name;
	std::vector<ImportFunctionInfo> function_datas;
};


using vec_sections = std::vector<IMAGE_SECTION_HEADER>;
using vec_relocs = std::vector<RelocInfo>;
using vec_imports = std::vector<ImportInfo>;

enum class AllocationMode
{
	AllocateIndependentPages
};

using Callback = bool(*)(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize);


class ValkyrieMapper
{
private:
	IntelLoader& m_loader;

	void ImageRebase(vec_relocs relocs, const ULONG64 delta);
	PIMAGE_NT_HEADERS64 GetNtHeadersValk(void* image_base);
	vec_relocs GetRelocs(void* image_base);
	vec_imports GetImports(void* image_base);
	bool ResolveImports(vec_imports imports);
	bool FixSecurityCookie(void* localImageBase, ULONG64 kernelImageBase);




public:
	explicit ValkyrieMapper(IntelLoader& loader) : m_loader(loader) {}

	ULONG64 MapDriver(PEImage& drvImage,
		ULONG64 arg1,
		ULONG64 arg2,
		BOOL freeMemAfterUse,
		AllocationMode mode,
		BOOL PassAllocationAddressAsFirstParam,
		Callback callback,
		NTSTATUS* exitCode);

};