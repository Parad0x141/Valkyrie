#pragma once
#include "XorLog.hpp"

namespace StringTable
{
	// ---------------------------------------------------------------------------
	//  Args.hpp strings
	// ---------------------------------------------------------------------------
	inline constexpr auto ARGS_USAGE = XSTR("Usage: Valkyrie.exe [options] <MyEvilDriver.sys>");
	inline constexpr auto ARGS_OPTIONS = XSTR("Options :");
	inline constexpr auto ARGS_HELP = XSTR("  -h      --help                Show this help");
	inline constexpr auto ARGS_DRIVER_INFO = XSTR("  -di     --driverInfo          Show driver PE metadatas");
	inline constexpr auto ARGS_NO_STEALTH = XSTR("  -nost   --noStealth           Do not erase Intel driver traces after mapping (Only delete driver file)");
	inline constexpr auto ARGS_FREE_MEM = XSTR("  -fm     --freeMemory          Free memory after driver entry call (One-shot driver)");
	inline constexpr auto ARGS_NO_HEADER_SCRAMBLE = XSTR("  -nosc   --noHeaderScramble    Leave driver header intact before mapping.");
	inline constexpr auto ARGS_DEEP_WIPE = XSTR("  -dw     --deepWipe            Write random safes opcodes in previously allocated driver memory");
	inline constexpr auto ARGS_UNKNOWN_FLAG = XSTR("Unknown flag : ");
	inline constexpr auto ARGS_SEE_HELP = XSTR("  (see -h)");
	inline constexpr auto ARGS_EXTRA_ARG = XSTR("Extra argument : ");
	inline constexpr auto ARGS_NO_DRIVER = XSTR("No driver file provided !");
	inline constexpr auto ARGS_FILE_NOT_FOUND = XSTR("File not found : ");
	inline constexpr auto ARGS_BAD_EXT = XSTR("Extension not .sys, continue anyway");


	// --------------------------------------------------------------------------
	// Main.cpp strings
	//---------------------------------------------------------------------------

	inline constexpr auto MAIN_DRV_LOAD = XSTR("Loading -> : ");
	inline constexpr auto MAIN_SUCCES_MSG = XSTR("All operations completed. Press Enter to exit. Farewell !");
	inline constexpr auto MAIN_MAPPING_MSG = XSTR("Mapping driver...");
	inline constexpr auto MAIN_DRV_MAPPED = XSTR("Driver mapped ! Driver entry called, returned : ");
	inline constexpr auto MAIN_DRV_BASEADDR = XSTR("Base address of mapped driver : ");
	inline constexpr auto MAIN_MEMORY_CLEANED = XSTR("Memory cleaned, driver unloaded !");
	inline constexpr auto MAIN_INTEL_CLEANING = XSTR("Cleaning Intel driver traces...");
	inline constexpr auto MAIN_PRESS_ENTER = XSTR("Press Enter to continue...");
	inline constexpr auto MAIN_ADMINCHECK = XSTR("Valkyrie need to be launched as administrator.");



	//----------------------------------------------------------------------------
	// EnvProbe.cpp string
	//----------------------------------------------------------------------------

	inline constexpr auto PROBE_VMWARE = XSTR("VMwareVMware");
	inline constexpr auto PROBE_VBOX = XSTR("VBoxVBoxVBox");
	inline constexpr auto PROBE_KVM = XSTR("KVMKVMKVM");
	inline constexpr auto PROBE_HYPERV = XSTR("Microsoft Hv");


} // namespace StringTable