// winx-ld64-shim: installed as toolset/bin/ld64.lld.exe inside the Darwin SDK
// bundle. SwiftPM asks the "linker" to produce relocatable objects with -r,
// which lld's Mach-O port does not support; xtool works around this by
// building a static archive instead, and this program does the same. Every
// other invocation is passed straight through to the real linker in orig/.

#include <windows.h>

#include <process.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "winx/process.hpp"
#include "winx/text.hpp"

namespace {

int spawn(const std::filesystem::path& program, const std::vector<std::wstring>& arguments) {
    // The CRT joins argv with spaces and does not quote, so quote here.
    std::vector<std::wstring> quoted;
    quoted.push_back(winx::to_wide(winx::process::quote_argument(winx::to_utf8(program.wstring()))));
    for (const std::wstring& argument : arguments) {
        quoted.push_back(winx::to_wide(winx::process::quote_argument(winx::to_utf8(argument))));
    }
    std::vector<const wchar_t*> argv;
    for (const std::wstring& argument : quoted) argv.push_back(argument.c_str());
    argv.push_back(nullptr);
    const intptr_t result = _wspawnv(_P_WAIT, program.c_str(), argv.data());
    if (result == -1) {
        std::wcerr << L"winx-ld64-shim: cannot run " << program.wstring() << L'\n';
        return 127;
    }
    return static_cast<int>(result);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    wchar_t self[MAX_PATH * 2];
    const DWORD length = GetModuleFileNameW(nullptr, self, static_cast<DWORD>(std::size(self)));
    const std::filesystem::path directory = std::filesystem::path(std::wstring(self, length)).parent_path();

    std::vector<std::wstring> arguments(argv + 1, argv + argc);
    bool relocatable = false;
    for (const std::wstring& argument : arguments) relocatable = relocatable || argument == L"-r";
    if (!relocatable) return spawn(directory / L"orig" / L"ld64.lld.exe", arguments);

    // Keep only what a librarian understands.
    std::vector<std::wstring> archive = {L"-static"};
    for (std::size_t i = 0; i < arguments.size(); ++i) {
        const std::wstring& argument = arguments[i];
        if ((argument == L"-filelist" || argument == L"-dependency_info" || argument == L"-o") &&
            i + 1 < arguments.size()) {
            archive.push_back(argument);
            archive.push_back(arguments[++i]);
        }
    }
    return spawn(directory / L"llvm-lib.exe", archive);
}
