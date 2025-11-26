#include "Common.hpp"


struct Args
{
    std::wstring driverSysPath;
    bool clean;
    bool isPersistent;
    bool showHelp;

};

[[nodiscard]] Args ParseArgs(int argc, wchar_t* argv[])
{
    Args a;
	a.clean = false;
	a.isPersistent = false;
	a.showHelp = false;

    auto Next = [&](int i) -> std::optional<std::wstring>
        {
            if (i + 1 < argc) return argv[i + 1];
            return std::nullopt;
        };

    for (int i = 1; i < argc; ++i)
    {
        const std::wstring arg = argv[i];

        if (arg.starts_with(L"-"))         
        {
      
            if (arg == L"-h" || arg == L"--help") { a.showHelp = true; continue; }

           
            if (arg == L"-c" || arg == L"--clean") { a.clean = true; continue; }

            
            if (arg == L"-u" || arg == L"--unmap") { a.isPersistent = true; continue; }

            
            if (arg == L"-l" || arg == L"--load")
            {
                if (auto path = Next(i)) { a.driverSysPath = *path; ++i; continue; }
                std::wcerr << L"Error: --load requires <file>\n";
                a.showHelp = true;
                break;
            }

            
            std::wcerr << L"Unknown flag: " << arg << L'\n';
            a.showHelp = true;
            break;
        }
        else if (a.driverSysPath.empty())
        {

            a.driverSysPath = arg;
        }
        else
        {
            std::wcerr << L"Error: extra argument \"" << arg << L"\"\n";
            a.showHelp = true;
            break;
        }
    }
    return a;
}