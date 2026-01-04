#pragma once

#include "Common.hpp"

#include <intrin.h>
#include <iphlpapi.h>
#include <tlhelp32.h> 
#include <setupapi.h>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")



class EnvProbe
{
public:

	struct Result
	{

		int Score = 0;
		std::vector<std::string> Flags;

	};


	Result Analyze() const;

private:
	BOOL IsHypervisorCPUID() const;
	BOOL IsBlacklistedManufacturer() const;
	BOOL IsBlacklistedMAC() const;
	BOOL IsSandBoxed() const;
	BOOL IsDebuggerProcess() const;
	BOOL IsDebuggerPresentPEB() const;
	BOOL IsDebuggerPresentTiming() const;
	BOOL IsFreshInstall() const;
	BOOL HasSuspiciousDiskSize() const;
	BOOL IsLowEndMachine() const;
	BOOL HasNoUSBDevices() const;
	
};