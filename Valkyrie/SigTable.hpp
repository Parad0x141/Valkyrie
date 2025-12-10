#pragma once

#include <array>
#include <string_view>

#include "Common.hpp"

#ifdef __INTELLISENSE__ 
#pragma diag_suppress 2904
#endif


namespace SigTable
{

	struct SigEntry
	{
		const char* name;
		const char* section;
		const char* bytes;
		const char* mask;
	};

	namespace Signatures
	{
		constexpr SigEntry PiDDBLock0
		{
			.name = "PiDDBLock0",
			.section = "PAGE",
			.bytes = "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D",
			.mask = "xxxxxx????xxxxx????xxx????xxxxx????",


		};

		constexpr SigEntry PiDDBLock1
		{
			.name = "PiDDBLock1",
			.section = "PAGE",
			.bytes = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D",
			.mask = "xxx????xxxxx????xxx????",


		};
		constexpr SigEntry PiDDBLock2
		{
			.name = "PiDDBLock2",
			.section = "PAGE",
			.bytes = "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D",
			.mask = "xxxxxx????xxxxx????xxx????",


		};

		constexpr SigEntry PiDDBCacheTable0
		{
			.name = "PiDDBCacheTable0",
			.section = "PAGE",
			.bytes = "\x66\x03\xD2\x48\x8D\x0D",
			.mask = "xxxxxx",


		};

		constexpr SigEntry PiDBBCacheTable1
		{
			.name = "PiDBBCacheTable1",
			.section = "PAGE",
			.bytes = "\x48\x8B\xF9\x33\xC0\x48\x8D\x0D",
			.mask = "xxxxxxxx",


		};

		constexpr SigEntry CiBucketList0
		{
			.name = "CiBucketList0",
			.section = "PAGE",
			.bytes = "\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00",
			.mask = "xxx????x?xxxxxxx",

		};

		constexpr SigEntry CiBucketLock0
		{
			.name = "CiBucketLock0",
	        .section = "PAGE",
	        .bytes = "\x48\x8D\x0D",
	        .mask = "xxx",

		};

		constexpr SigEntry MmAllocateIndependentPagesEx
		{
			.name = "MmAllocateIndependentPagesEx",
			.section = ".text",
			.bytes = "\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8",
			.mask = "xxxxxxxxx????xxx",


		};

		constexpr SigEntry MmFreeIndependentPages
		{
			.name = "MmFreeIndependentPages",
			.section = "PAGE",
			.bytes = "\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF",
			.mask = "xxxxxxxxx????xxxxxxx",


		};

		constexpr SigEntry MmSetPageProtection0
		{
			.name = "MmSetPageProtection0",
			.section = "PAGELK",
			.bytes = "\x0F\x45\x00\x00\x8D\x00\x00\x00\xFF\xFF\xE8",
			.mask = "xx??x???xxx",


		};

		constexpr SigEntry MmSetPageProtection1
		{
			.name = "MmSetPageProtection1",
			.section = "PAGELK",
			.bytes = "\x0F\x45\x00\x00\x45\x8B\x00\x00\x00\x00\x8D\x00\x00\x00\x00\x00\x00\xFF\xFF\xE8",
			.mask = "xx??xx????x???xxx",

		};

	}

}