#pragma once

#include "Common.hpp"
#include "IntelLoader.hpp"
#include <iomanip>
#include <sstream>

namespace DebugTools
{

	VOID AnalyzePrologues(IntelLoader& loader);
	VOID ListWinServices();

}