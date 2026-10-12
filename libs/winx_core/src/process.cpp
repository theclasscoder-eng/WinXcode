#include "winx/process.hpp"

#include <windows.h>

#include <algorithm>
#include <map>

#include "winx/text.hpp"

namespace winx::process {
namespace {

struct HandleCloser {
    HANDLE handle = nullptr;
    ~HandleCloser() {
        if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    }
};

// A Unicode environment block: the parent's variables with overrides applied.
std::wstring environment_block(const std::vector<std::pair<std::string, std::string>>& overrides) {
    // Windows treats variable names case-insensitively.
    const auto less = [](const std::wstring& a, const std::wstring& b) {
        return _wcsicmp(a.c_str(), b.c_str()) < 0;
    };
    std::map<std::wstring, std::wstring, decltype(less)> variables(less);
    if (wchar_t* block = GetEnvironmentStringsW()) {
        for (const wchar_t* entry = block; *entry; entry += wcslen(entry) + 1) {
            const std::wstring_view text(entry);
            // Entries such as "=C:=C:\dir" start with '=' and are kept verbatim.
            const auto equals = text.find(L'=', 1);
            if (equals == std::wstring_view::npos) continue;
            variables[std::wstring(text.substr(0, equals))] = std::wstring(text.substr(equals + 1));
        }
        FreeEnvironmentStringsW(block);
    }
    for (const auto& [name, value] : overrides) variables[to_wide(name)] = to_wide(value);

    std::wstring out;
    for (const auto& [name, value] : variables) {
        out += name;
        out += L'=';
        out += value;
        out += L'\0';
    }
    out += L'\0';
    return out;
}

}  // namespace

std::string quote_argument(std::string_view argument) {
    if (!argument.empty() && argument.find_first_of(" \t\n\v\"") == std::string_view::npos) {
        return std::string(argument);
    }
    std::string out = "\"";
    std::size_t backslashes = 0;
    for (const char c : argument) {
        if (c == '\\') {
            ++backslashes;
            continue;
        }
        if (c == '"') {
            // Backslashes before a quote must be doubled, and the quote escaped.
            out.append(backslashes * 2 + 1, '\\');
        } else {
            out.append(backslashes, '\\');
        }
        backslashes = 0;
        out += c;
    }
    out.append(backslashes * 2, '\\');  // those before the closing quote
    out += '"';
    return out;
}

std::optional<std::filesystem::path> find_on_path(std::wstring_view name) {
    const std::wstring file(name);
    wchar_t buffer[MAX_PATH * 4];
    const DWORD length = SearchPathW(nullptr, file.c_str(), nullptr,
                                     static_cast<DWORD>(std::size(buffer)), buffer, nullptr);
    if (length == 0 || length >= std::size(buffer)) return std::nullopt;
    return std::filesystem::path(std::wstring(buffer, length));
}

Result run(const std::filesystem::path& executable, const std::vector<std::string>& arguments,
           const Options& options) {
    std::string command = quote_argument(to_utf8(executable.wstring()));
    for (const std::string& argument : arguments) command += " " + quote_argument(argument);
    std::wstring command_line = to_wide(command);

    SECURITY_ATTRIBUTES inheritable{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HandleCloser read_end;
    HandleCloser write_end;
    if (!CreatePipe(&read_end.handle, &write_end.handle, &inheritable, 0)) {
        throw ProcessError("cannot create a pipe: " + win32_error_message(GetLastError()));
    }
    SetHandleInformation(read_end.handle, HANDLE_FLAG_INHERIT, 0);
    HandleCloser null_input{CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        &inheritable, OPEN_EXISTING, 0, nullptr)};

    // The job makes sure grandchildren (swift-build starts many) die with us.
    HandleCloser job{CreateJobObjectW(nullptr, nullptr)};
    if (job.handle) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job.handle, JobObjectExtendedLimitInformation, &limits,
                                sizeof(limits));
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = null_input.handle;
    startup.hStdOutput = write_end.handle;
    startup.hStdError = write_end.handle;

    std::wstring environment = environment_block(options.environment);
    const std::wstring directory = options.working_directory.wstring();
    PROCESS_INFORMATION info{};
    if (!CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                        environment.data(), directory.empty() ? nullptr : directory.c_str(),
                        &startup, &info)) {
        throw ProcessError("cannot start " + to_utf8(executable.wstring()) + ": " +
                           win32_error_message(GetLastError()));
    }
    HandleCloser process{info.hProcess};
    HandleCloser thread{info.hThread};
    if (job.handle) AssignProcessToJobObject(job.handle, info.hProcess);
    ResumeThread(info.hThread);
    // Close our copy so the pipe reports EOF once the child side is gone.
    CloseHandle(write_end.handle);
    write_end.handle = nullptr;

    Result result;
    std::string pending;
    const auto flush_lines = [&](bool final) {
        std::size_t start = 0;
        for (;;) {
            const auto end = pending.find('\n', start);
            if (end == std::string::npos) break;
            std::string_view line(pending.data() + start, end - start);
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            if (options.on_line) options.on_line(line);
            start = end + 1;
        }
        pending.erase(0, start);
        if (final && !pending.empty()) {
            if (options.on_line) options.on_line(pending);
            pending.clear();
        }
    };

    char buffer[8192];
    for (;;) {
        if (options.stop.stop_requested()) {
            result.cancelled = true;
            if (job.handle) {
                TerminateJobObject(job.handle, 1);
            } else {
                TerminateProcess(info.hProcess, 1);
            }
            break;
        }
        DWORD available = 0;
        if (!PeekNamedPipe(read_end.handle, nullptr, 0, nullptr, &available, nullptr)) break;  // EOF
        if (available == 0) {
            if (WaitForSingleObject(info.hProcess, 25) == WAIT_OBJECT_0) {
                // The child exited; drain whatever it wrote last.
                if (!PeekNamedPipe(read_end.handle, nullptr, 0, nullptr, &available, nullptr) ||
                    available == 0) {
                    break;
                }
            }
            continue;
        }
        DWORD read = 0;
        if (!ReadFile(read_end.handle, buffer, std::min<DWORD>(available, sizeof(buffer)), &read,
                      nullptr) ||
            read == 0) {
            break;
        }
        result.output.append(buffer, read);
        pending.append(buffer, read);
        flush_lines(false);
    }
    flush_lines(true);

    WaitForSingleObject(info.hProcess, result.cancelled ? 5000 : INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(info.hProcess, &exit_code);
    result.exit_code = static_cast<int>(exit_code);
    return result;
}

}  // namespace winx::process
