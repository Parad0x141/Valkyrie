#pragma once

#include "Common.hpp"
#include "IntelLoader.hpp"
#include <iomanip>
#include <sstream>

namespace DebugTools
{
	VOID ListKernelModuleExports(IntelLoader& loader);
	VOID AnalyzePrologues(IntelLoader& loader);
	VOID ListWinServices();

}