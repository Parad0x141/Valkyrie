#pragma once
#include "XorLog.hpp"

namespace StringTable
{
	// ---------------------------------------------------------------------------
	//  Args.hpp strings
	// ---------------------------------------------------------------------------
	inline constexpr auto S_USAGE = XorLog::Encrypt("Usage: Valkyrie.exe [options] <MyEvilDriver.sys>");
	inline constexpr auto S_OPTIONS = XorLog::Encrypt("Options :");
	inline constexpr auto S_HELP = XorLog::Encrypt("  -h      --help                Show this help");
	inline constexpr auto S_DRIVER_INFO = XorLog::Encrypt("  -di     --driverInfo          Show driver PE metadatas");
	inline constexpr auto S_NO_STEALTH = XorLog::Encrypt("  -nost   --noStealth           Do not erase Intel driver traces after mapping (Only delete driver file)");
	inline constexpr auto S_FREE_MEM = XorLog::Encrypt("  -fm     --freeMemory          Free memory after driver entry call (One-shot driver)");
	inline constexpr auto S_NO_HEADER_SCRAMBLE = XorLog::Encrypt("  -nosc   --noHeaderScramble    Leave driver header intact before mapping.");
	inline constexpr auto S_DEEP_WIPE = XorLog::Encrypt("  -dw     --deepWipe            Write random safes opcodes in previously allocated driver memory");
	inline constexpr auto S_UNKNOWN_FLAG = XorLog::Encrypt("Unknown flag : ");
	inline constexpr auto S_SEE_HELP = XorLog::Encrypt("  (see -h)");
	inline constexpr auto S_EXTRA_ARG = XorLog::Encrypt("Extra argument : ");
	inline constexpr auto S_NO_DRIVER = XorLog::Encrypt("No driver file provided !");
	inline constexpr auto S_FILE_NOT_FOUND = XorLog::Encrypt("File not found : ");
	inline constexpr auto S_BAD_EXT = XorLog::Encrypt("Extension not .sys, continue anyway");


	// --------------------------------------------------------------------------
	// EnvProbe.cpp strings
	//---------------------------------------------------------------------------






} // namespace StringTable