#pragma once

#pragma warning(disable : 4005) // macro redefinition

#define NOMINMAX // Avoid min/max redef by Windows.h


// Standard libs
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include <mutex>

#include <winternl.h>
#include <io.h>           
#include <fcntl.h>        
#include <memory>
#include <fstream>
#include <stdexcept>
#include <algorithm>


// Internal 
#include "ValkStatus.hpp"
#include "ValkLogger.hpp"









