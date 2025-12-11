// Code by Cyril "Parad0x141" Bouvier - 2025  Valkyrie v0.3

// This is a work in progress even if the most of the main features are impl and working.


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
#include "Resolver.hpp"
#include "Experimental.hpp"

// Workflow will change to :

// [1 -> Setup]

//1. Load Intel driver
//2. Early offsets resolve
//3. Offsets validation
//4. if(failed) -> cleanup

// [2 -> Operations]

// 5. Map driver(using offset cache)
// 6. (PiDDB, CI, etc.)
// 7. Unload driver
// 8. Misc cleanup (ETW restore...)

// Make more sense and will be way more stable like this.



static void MapDriver(IntelLoader& loader, StealthKit& stealthKit, ValkyrieMapper& mapper, Args& args)
{
	// Intel driver timestamp
	ULONG timestamp = GetPETimeStamp(loader.GetDriverPath());

	// User driver path
	std::string narrowedPath = WStringToString(args.driverPath);


	// Load and validate.
	auto pe = PEUtils::ParsePE(narrowedPath);

	if (!pe || !PEUtils::ValidateDriverPE(*pe))
	{
		LOG_ERROR("Invalid driver PE. Aborting.");
		return;
	}

	// Optionnaly show PE metas
	if(args.showDriverInfo)
		PEUtils::ShowPEDetails(*pe,args.DriverName());  

	// Clean if user abort operations.

	system("cls");
	LOG_INFO("You're about to map : " << args.DriverName());
	JumpLine();
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


	system("cls");
	LOG_INFO("Mapping driver...");
	JumpLine();

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

	// TODO : Encrypt all strings.
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
		return EXIT_SUCCESS;
	}


	Splash();
	JumpLine();
	std::cout << "Press Enter to continue..." << "\n";
	std::wcin.ignore();

	if (!IsAdmin())
	{
		LOG_ERROR("Valkyrie need to be launched as administrator.");
		std::wcin.ignore();

		return EXIT_FAILURE;
	}

	ValkStatus status = ValkStatus::OK;

	IntelLoader loader;
	loader.SetKernelBaseAddress();

	Resolver resolver(loader);

	ValkyrieMapper mapper(loader);
	
	LOG_INFO("Dropping driver...\n");
	if (!WriteDriverFile()) 
	{
		LOG_ERROR("Failed to drop write driver file to disk. Aborting.");
		return EXIT_FAILURE;
	}


	LOG_INFO("Loading vulnerable driver...\n");
	if (!loader.LoadVulnDriver())
	{
		LOG_ERROR("Failed to load Intel driver. Aborting.");
		DeleteDriverFile();
		return EXIT_FAILURE;
	}

	
	LOG_INFO("Opening device...");
	if (!loader.OpenDevice()) 
	{
		LOG_ERROR("Failed to open device. Aborting.");
		loader.UnloadVulnDriver();
		DeleteDriverFile();
		return EXIT_FAILURE;
	}


	if (resolver.ResolveExported() != ValkStatus::OK)
	{
		LOG_ERROR("Resolver failed to resolve one or more exported functions. Aborting.");
	}

	StealthKit stealthKit(loader, resolver.GetOffsets());


	resolver.ResolvePatterns();
	if (!resolver.AllOffsetsResolved())
	{
		system("cls");
		LOG_ERROR("Failed to resolve at least one critical kernel offsets. Aborting.");
		std::wcin.ignore();
		return EXIT_FAILURE;
	}

	LOG_SUCCESS("All kernel offsets successfully resolved, mapper ready.");
	std::wcin.ignore();

	loader.SetOffsets(resolver.GetOffsets());
	
	MapDriver(loader, stealthKit, mapper, args);

	return EXIT_SUCCESS;

} 



