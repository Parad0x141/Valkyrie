#pragma once
#include "XorLog.hpp"

namespace StringTable
{
	// ---------------------------------------------------------------------------
	//  Args.hpp strings
	// ---------------------------------------------------------------------------
	inline constexpr auto S_USAGE = XSTR("Usage: Valkyrie.exe [options] <MyEvilDriver.sys>");
	inline constexpr auto S_OPTIONS = XSTR("Options :");
	inline constexpr auto S_HELP = XSTR("  -h      --help                Show this help");
	inline constexpr auto S_DRIVER_INFO = XSTR("  -di     --driverInfo          Show driver PE metadatas");
	inline constexpr auto S_NO_STEALTH = XSTR("  -nost   --noStealth           Do not erase Intel driver traces after mapping (Only delete driver file)");
	inline constexpr auto S_FREE_MEM = XSTR("  -fm     --freeMemory          Free memory after driver entry call (One-shot driver)");
	inline constexpr auto S_NO_HEADER_SCRAMBLE = XSTR("  -nosc   --noHeaderScramble    Leave driver header intact before mapping.");
	inline constexpr auto S_DEEP_WIPE = XSTR("  -dw     --deepWipe            Write random safes opcodes in previously allocated driver memory");
	inline constexpr auto S_UNKNOWN_FLAG = XSTR("Unknown flag : ");
	inline constexpr auto S_SEE_HELP = XSTR("  (see -h)");
	inline constexpr auto S_EXTRA_ARG = XSTR("Extra argument : ");
	inline constexpr auto S_NO_DRIVER = XSTR("No driver file provided !");
	inline constexpr auto S_FILE_NOT_FOUND = XSTR("File not found : ");
	inline constexpr auto S_BAD_EXT = XSTR("Extension not .sys, continue anyway");



	// --------------------------------------------------------------------------
	// EnvProbe.cpp strings
	//---------------------------------------------------------------------------








} // namespace StringTable