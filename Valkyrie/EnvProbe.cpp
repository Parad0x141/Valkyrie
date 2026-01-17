// Code by Cyril "Parad0x141" Bouvier - 2026
#include "EnvProbe.hpp"

#include <cstdint>
#include <corecrt.h>
#include <string.h>
#include <iphlpapi.h>
#include <IPTypes.h>
#include <SetupAPI.h>
#include <TlHelp32.h>
#include <Windows.h>
#include <cstdlib>
#include <ctime>
#include <intrin.h>
#include <vector>

#include "Helpers.hpp"
#include "XorLog.hpp" 
#include <string>
#include <iostream>
#include <string_view>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")

BOOL EnvProbe::IsHypervisorCPUID() const
{
	int cpuInfo[4];
	__cpuid(cpuInfo, 1);

	if (!((cpuInfo[2] >> 31) & 1))
		return FALSE;

	__cpuid(cpuInfo, 0x40000000);

	char vendor[13] = { 0 };
	memcpy(vendor, &cpuInfo[1], 4);
	memcpy(vendor + 4, &cpuInfo[2], 4);
	memcpy(vendor + 8, &cpuInfo[3], 4);

	constexpr auto VMWARE = XSTR("VMwareVMware");
	constexpr auto VBOX = XSTR("VBoxVBoxVBox");
	constexpr auto KVM = XSTR("KVMKVMKVM");
	constexpr auto HYPERV = XSTR("Microsoft Hv");

	if (strcmp(vendor, DecodeSv(VMWARE).data()) == 0 ||
		strcmp(vendor, DecodeSv(VBOX).data()) == 0 ||
		strcmp(vendor, DecodeSv(KVM).data()) == 0 ||
		strcmp(vendor, DecodeSv(HYPERV).data()) == 0)
		return TRUE;

	return FALSE;
}

BOOL EnvProbe::IsBlacklistedMAC() const
{
	ULONG bufLen = 0;

	if (GetAdaptersInfo(nullptr, &bufLen) != ERROR_BUFFER_OVERFLOW || bufLen == 0)
		return FALSE;

	std::vector<BYTE> buffer(bufLen, 0);
	PIP_ADAPTER_INFO info = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());


	const BYTE VM_OUIS[][3] = {
		{0x08, 0x00, 0x27},  // VirtualBox
		{0x00, 0x05, 0x69},  // VMware
		{0x00, 0x0C, 0x29},  // VMware
		{0x00, 0x50, 0x56},  // VMware ESXi
		{0x00, 0x1C, 0x42},  // Parallels
		{0x00, 0x15, 0x5D},  // Hyper-V
		{0x00, 0x16, 0x3E},  // Xen
		{0x52, 0x54, 0x00},  // KVM/QEMU
	};

	if (GetAdaptersInfo(info, &bufLen) == NO_ERROR)
	{
		for (PIP_ADAPTER_INFO p = info; p; p = p->Next)
		{
			if (p->AddressLength < 3)
				continue;

			for (const auto& oui : VM_OUIS)
			{
				if (memcmp(p->Address, oui, 3) == 0)
					return TRUE;
			}
		}
	}

	return FALSE;
}

BOOL EnvProbe::IsBlacklistedManufacturer() const
{
	char manufacturer[256] = { 0 };
	char model[256] = { 0 };
	DWORD sz = sizeof(manufacturer) - 1;

	constexpr auto REG_PATH = XSTR(R"_(SYSTEM\CurrentControlSet\Control\SystemInformation)_");
	constexpr auto REG_MANUFACTURER = XSTR("SystemManufacturer");
	constexpr auto REG_MODEL = XSTR("SystemProductName");
	
	if (RegGetValueA(HKEY_LOCAL_MACHINE,
		DecodeSv(REG_PATH).data(),
		DecodeSv(REG_MANUFACTURER).data(),
		RRF_RT_REG_SZ, nullptr, manufacturer, &sz) != ERROR_SUCCESS)
	{
		std::cout << "Error fetching manufacturer from registry !" << "\n";
		return FALSE;
	}

	if (sz >= sizeof(manufacturer))
		sz = sizeof(manufacturer) - 1;

	manufacturer[sz] = '\0';


	sz = sizeof(model) - 1;
	RegGetValueA(HKEY_LOCAL_MACHINE,
		DecodeSv(REG_PATH).data(),
		DecodeSv(REG_MODEL).data(),
		RRF_RT_REG_SZ, nullptr, model, &sz);

	if (sz >= sizeof(model))
		sz = sizeof(model) - 1;

	model[sz] = '\0';

	constexpr auto VMWARE = XSTR("VMware");
	constexpr auto INNOTEK = XSTR("innotek");
	constexpr auto QEMU = XSTR("QEMU");
	constexpr auto XEN = XSTR("Xen");

	if (stristr(manufacturer, DecodeSv(VMWARE).data()) ||
		stristr(manufacturer, DecodeSv(INNOTEK).data()) ||
		stristr(manufacturer, DecodeSv(QEMU).data()) ||
		stristr(manufacturer, DecodeSv(XEN).data()))
		return TRUE;

	constexpr auto VBOX_MODEL = XSTR("VirtualBox");
	constexpr auto VMWARE_MODEL = XSTR("VMware Virtual Platform");
	constexpr auto VIRTUAL_MACHINE = XSTR("Virtual Machine");
	constexpr auto KVM_MODEL = XSTR("KVM");
	constexpr auto STANDARD_PC = XSTR("Standard PC");

	if (stristr(model, DecodeSv(VBOX_MODEL).data()) ||
		stristr(model, DecodeSv(VMWARE_MODEL).data()) ||
		stristr(model, DecodeSv(VIRTUAL_MACHINE).data()) ||
		stristr(model, DecodeSv(KVM_MODEL).data()) ||
		stristr(model, DecodeSv(STANDARD_PC).data()))
		return TRUE;

	constexpr auto MICROSOFT = XSTR("Microsoft Corporation");
	constexpr auto MS_VM_COMBO = XSTR("Virtual Machine");

	if (stristr(manufacturer, DecodeSv(MICROSOFT).data()) &&
		stristr(model, DecodeSv(MS_VM_COMBO).data()))
		return TRUE;

	return FALSE;
}



BOOL EnvProbe::IsDebuggerProcess() const
{
	constexpr auto OLLYDBG = XSTR("ollydbg.exe");
	constexpr auto X64DBG = XSTR("x64dbg.exe");
	constexpr auto X32DBG = XSTR("x32dbg.exe");
	constexpr auto IDAQ = XSTR("idaq.exe");
	constexpr auto IDAQ64 = XSTR("idaq64.exe");
	constexpr auto WINDBG = XSTR("windbg.exe");
	constexpr auto DBGVIEW = XSTR("dbgview.exe");
	constexpr auto PROCEXP = XSTR("procexp.exe");
	constexpr auto PROCEXP64 = XSTR("procexp64.exe");
	constexpr auto CHEATENGINE = XSTR("cheatengine.exe");
	constexpr auto SCYLLA = XSTR("scylla.exe");
	constexpr auto SCYLLA_X64 = XSTR("scylla_x64.exe");
	constexpr auto SCYLLA_X86 = XSTR("scylla_x86.exe");
	constexpr auto IMMUNITY = XSTR("IMMUNITYDEBUGGER.EXE");
	constexpr auto WIRESHARK = XSTR("Wireshark.exe");
	constexpr auto DUMPCAP = XSTR("dumpcap.exe");
	constexpr auto HOOKEXPLORER = XSTR("HookExplorer.exe");
	constexpr auto IMPORTREC = XSTR("ImportREC.exe");
	constexpr auto PETOOLS = XSTR("PETools.exe");
	constexpr auto LORDPE = XSTR("LordPE.exe");
	constexpr auto SYSINSPECTOR = XSTR("SysInspector.exe");
	constexpr auto PROCMON = XSTR("procmon.exe");
	constexpr auto TCPVIEW = XSTR("tcpview.exe");
	constexpr auto AUTORUNS = XSTR("autoruns.exe");
	constexpr auto AUTORUNSC = XSTR("autorunsc.exe");
	constexpr auto FILEMON = XSTR("filemon.exe");
	constexpr auto REGMON = XSTR("regmon.exe");
	constexpr auto IDA = XSTR("ida.exe");
	constexpr auto IDA64 = XSTR("ida64.exe");

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	struct Guard 
	{
		HANDLE h;
		~Guard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }

	} guard{ snapshot };

	PROCESSENTRY32W pe = { sizeof(pe) };

	if (!Process32FirstW(snapshot, &pe))
		return FALSE;

	do {
		std::string exeName = WStringToString(pe.szExeFile);


		// Courtesy of Kimi AI
		if (_stricmp(exeName.c_str(), DecodeSv(OLLYDBG).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(X64DBG).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(X32DBG).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(IDAQ).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(IDAQ64).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(WINDBG).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(DBGVIEW).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(PROCEXP).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(PROCEXP64).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(CHEATENGINE).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(SCYLLA).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(SCYLLA_X64).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(SCYLLA_X86).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(IMMUNITY).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(WIRESHARK).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(DUMPCAP).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(HOOKEXPLORER).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(IMPORTREC).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(PETOOLS).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(LORDPE).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(SYSINSPECTOR).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(PROCMON).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(TCPVIEW).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(AUTORUNS).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(AUTORUNSC).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(FILEMON).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(REGMON).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(IDA).data()) == 0 ||
			_stricmp(exeName.c_str(), DecodeSv(IDA64).data()) == 0)

			return TRUE;

	} while (Process32NextW(snapshot, &pe));

	return FALSE;
}


BOOL EnvProbe::IsSandBoxed() const
{
	constexpr auto SBIE = XSTR("SbieDll.dll");
	constexpr auto API_LOG = XSTR("api_log.dll");
	constexpr auto DIR_WATCH = XSTR("dir_watch.dll");



	if (GetModuleHandleA(DecodeSv(SBIE).data())) return TRUE;
	if (GetModuleHandleA(DecodeSv(API_LOG).data())) return TRUE;
	if (GetModuleHandleA(DecodeSv(DIR_WATCH).data())) return TRUE;

	return FALSE;
}

BOOL EnvProbe::IsDebuggerPresentPEB() const
{
#ifdef _WIN64
	
	return *(uint8_t*)(__readgsqword(0x60) + 0x2) != 0;
#else
	return IsDebuggerPresent();
#endif
}

BOOL EnvProbe::IsDebuggerPresentTiming() const
{
	// FIX: Drastically increased thresholds & iterations to reduce false positives,
	// this is not the most accurat test and will have minimal impact on the final score
	// to compensate inaccuracy.
	DWORD64 t1 = __rdtsc();
	volatile int x = 0;

	for (int i = 0; i < 1000; ++i) x++;
	DWORD64 t2 = __rdtsc();


	if ((t2 - t1) > 50000)
		return TRUE;


	UINT64 tick1 = GetTickCount64();
	LARGE_INTEGER qpc1, qpc2, freq;

	QueryPerformanceCounter(&qpc1);

	Sleep(50);

	UINT64 tick2 = GetTickCount64();
	QueryPerformanceCounter(&qpc2);
	QueryPerformanceFrequency(&freq);

	UINT64 tickDelta = tick2 - tick1;
	UINT64 qpcDelta = ((qpc2.QuadPart - qpc1.QuadPart) * 1000) / freq.QuadPart;

	if (llabs((long long)(tickDelta - qpcDelta)) > 100)
		return TRUE;

	return FALSE;
}

BOOL EnvProbe::IsFreshInstall() const
{
	constexpr auto REG_PATH = XSTR(R"_(SOFTWARE\Microsoft\Windows NT\CurrentVersion)_");
	constexpr auto REG_INSTALL = XSTR("InstallDate");

	DWORD installDate = 0;
	DWORD sz = sizeof(installDate);

	if (RegGetValueA(HKEY_LOCAL_MACHINE,
		DecodeSv(REG_PATH).data(),
		DecodeSv(REG_INSTALL).data(),
		RRF_RT_REG_DWORD, nullptr, &installDate, &sz) != ERROR_SUCCESS)
	{
		//std::cout << "Failed to get installation date from registry." << "\n";
		return FALSE;
	}

	time_t now = time(nullptr);
	UINT64 daysSinceInstall = (now - installDate) / (24 * 3600);


	return daysSinceInstall < 3;
}


BOOL EnvProbe::IsLowEndMachine() const
{
	SYSTEM_INFO si = { 0 };
	GetSystemInfo(&si);

	if (si.dwNumberOfProcessors < 2)
		return TRUE;

	MEMORYSTATUSEX ms = { sizeof(ms) };

	return GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys < 6ULL * 1024 * 1024 * 1024;
}

BOOL EnvProbe::HasNoUSBDevices() const
{
	HDEVINFO deviceInfo = SetupDiGetClassDevsA(
		nullptr, "USB", nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES
	);

	if (deviceInfo == INVALID_HANDLE_VALUE)
	{
		std::cout << "Error, bad handle." << "\n";
		return FALSE;
	}

	SP_DEVINFO_DATA deviceData = { sizeof(SP_DEVINFO_DATA) };
	DWORD deviceCount = 0;

	for (DWORD i = 0; SetupDiEnumDeviceInfo(deviceInfo, i, &deviceData); i++)
	{
		char deviceID[256] = { 0 };
		if (SetupDiGetDeviceInstanceIdA(deviceInfo, &deviceData, deviceID, sizeof(deviceID), nullptr))
		{
			if (!strstr(deviceID, "ROOT_HUB") && !strstr(deviceID, "USB\\\\ROOT"))
				deviceCount++;
		}
	}

	//std::cout << "Device count : " << deviceCount << "\n";

	SetupDiDestroyDeviceInfoList(deviceInfo);

	return deviceCount < 2;
}


void EnvProbe::DisplayResultFlags(const Result& Result) const
{

	if (!Result.Flags.empty())
	{

		std::cout << "Flags :\n";
		for (std::string_view flag : Result.Flags)
		{
			std::cout << flag << "\n";
		}
	}

	std::cout << "Environement scored : " << Result.Score << "\n";
}


EnvProbe::Result EnvProbe::Analyze() const
{
	Result probeResults;


	std::cout << "Analyzing environement..." << "\n";

	if (IsDebuggerPresentPEB())
	{
		probeResults.Score = 100;
		probeResults.Flags.push_back("CRITICAL : Debugger attached (PEB)");
		// return probeResults;
	}

	if (IsSandBoxed())
	{
		probeResults.Score = 100;
		probeResults.Flags.push_back("CRITICAL : Sandbox DLL detected");
		// return probeResults;
	}

	if (IsHypervisorCPUID())
	{
		probeResults.Score += 40;
		probeResults.Flags.push_back("Hypervisor CPUID detected");
	}

	if (IsBlacklistedManufacturer())
	{
		probeResults.Score += 35;
		probeResults.Flags.push_back("VM manufacturer detected");
	}

	if (IsBlacklistedMAC())
	{
		probeResults.Score += 25;
		probeResults.Flags.push_back("VM MAC address detected");
	}

	if (IsDebuggerProcess())
	{
		probeResults.Score += 25;
		probeResults.Flags.push_back("Debugger process detected");
	}

	if (IsDebuggerPresentTiming())
	{
		probeResults.Score += 5; // Less weight, inaccurate test
		probeResults.Flags.push_back("Timing anomaly (low confidence)");
	}

	if (IsFreshInstall())
	{
		probeResults.Score += 15;
		probeResults.Flags.push_back("Fresh install detected");
	}

	if (IsLowEndMachine())
	{
		probeResults.Score += 20;
		probeResults.Flags.push_back("Low-end hardware detected");
	}

	if (HasNoUSBDevices())
	{
		probeResults.Score += 10;
		probeResults.Flags.push_back("No USB devices found");
	}

	DisplayResultFlags(probeResults);


	return probeResults;
}