#pragma once

#include <Windows.h>
#include <vector>
#include <string>




class EnvProbe
{
public:

	struct Result
	{

		int Score = 0;
		std::vector<std::string> Flags;

	};


	Result Analyze() const;
	void DisplayResultFlags(const Result& Result) const;


private:
	BOOL IsHypervisorCPUID() const;
	BOOL IsBlacklistedManufacturer() const;
	BOOL IsBlacklistedMAC() const;
	BOOL IsSandBoxed() const;
	BOOL IsDebuggerProcess() const;
	BOOL IsDebuggerPresentPEB() const;
	BOOL IsDebuggerPresentTiming() const;
	BOOL IsFreshInstall() const;
	BOOL IsLowEndMachine() const;
	BOOL HasNoUSBDevices() const;
	
};