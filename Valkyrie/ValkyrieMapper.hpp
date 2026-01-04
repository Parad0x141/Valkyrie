#pragma once

#include "Common.hpp"
#include "IntelLoader.hpp"


inline static bool GetHardwareRandom64(uint64_t& out)
{
#ifdef _WIN64
	return _rdrand64_step(&out) == 1;
#else
	return false;
#endif
}


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
	UINT64 GenerateSecureCookie();




public:
	explicit ValkyrieMapper(IntelLoader& loader) : m_loader(loader) {}

	ULONG64 MapDriver(PEImage& drvImage,
		ULONG64 arg1,
		ULONG64 arg2,
		BOOL freeMemAfterUse,
		BOOL wipeHeader,
		AllocationMode mode,
		BOOL PassAllocationAddressAsFirstParam,
		NTSTATUS* exitCode);

};