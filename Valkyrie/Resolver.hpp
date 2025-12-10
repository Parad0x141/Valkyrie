#include "Common.hpp"
#include "IntelLoader.hpp"
#include "PatternScanner.hpp"
#include "SigTable.hpp"


// Early-resolve every kernel offsets.
// fail-fast on mismatch, remove run-time scans, lower IOCTL noise.




static constexpr struct
{
	UINT64 KernelOffsets::* ptr;
	const char* name;
} 

fields[] = {
	&KernelOffsets::ExFreePool,                                "ExFreePool",
	&KernelOffsets::ExAcquireResourceExclusiveLite,            "ExAcquireResourceExclusiveLite",
	&KernelOffsets::ExReleaseResourceLite,                     "ExReleaseResourceLite",
	&KernelOffsets::RtlDeleteElementGenericTableAvl,           "RtlDeleteElementGenericTableAvl",
	&KernelOffsets::RtlLookupElementGenericTableAvl,           "RtlLookupElementGenericTableAvl",
	&KernelOffsets::RtlEnumerateGenericTableWithoutSplayingAvl,"RtlEnumerateGenericTableWithoutSplayingAvl",
	&KernelOffsets::MmAllocateIndependentPagesEx,              "MmAllocateIndependentPagesEx",
	&KernelOffsets::MmFreeIndependentPages,                    "MmFreeIndependentPages",
	&KernelOffsets::MmSetPageProtection,                       "MmSetPageProtection",
	&KernelOffsets::PiDDBCacheTable,                           "GetPiDDBCacheTable",
	&KernelOffsets::PiDDBLock,                                 "PiDDBLock",
	&KernelOffsets::CiBucketList,                              "CiBucketList",
	&KernelOffsets::CiBucketLock,                              "CiBucketLock"
};



class Resolver
{
public:
	explicit Resolver(IntelLoader& loader) : m_loader(loader) {}

	
	ValkStatus ResolveAll();

	ValkStatus ResolveExported();
	ValkStatus ResolvePatterns();


	bool AllOffsetsResolved() const noexcept
	{
		for (const auto& f : fields)
			if (!(m_offsets.*f.ptr))
			{ 
				LOG_ERROR("Resolver failed to resolve : " << f.name);
				return false; 
			}

		return true;
	}


	const KernelOffsets& GetOffsets() const noexcept { return m_offsets; }

private:
	
	KernelOffsets m_offsets;
	IntelLoader& m_loader;
};