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
	[[nodiscard]] BOOL IsHypervisorCPUID() const;
	[[nodiscard]] BOOL IsBlacklistedManufacturer() const;
	[[nodiscard]] BOOL IsBlacklistedMAC() const;
	[[nodiscard]] BOOL IsSandBoxed() const;
	[[nodiscard]] BOOL IsDebuggerProcess() const;
	[[nodiscard]] BOOL IsDebuggerPresentPEB() const;
	[[nodiscard]] BOOL IsDebuggerPresentTiming() const;
	[[nodiscard]] BOOL IsFreshInstall() const;
	[[nodiscard]] BOOL IsLowEndMachine() const;
	[[nodiscard]] BOOL HasNoUSBDevices() const;
	
};