#pragma once

#include "Common.hpp"
#include <iomanip>
#include <sstream>

namespace DebugTools
{
	VOID TestKernelMemAPI(IntelLoader& loader);
	VOID ListKernelModuleExports(IntelLoader& loader);
	VOID TestBestCandidates(IntelLoader& loader);
	VOID AnalyzePrologues(IntelLoader& loader);
	VOID ListWinServices();

}