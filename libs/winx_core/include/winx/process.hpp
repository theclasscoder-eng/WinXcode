#pragma once

#include <filesystem>
#include <functional>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Running child processes with captured output.
namespace winx::process {

class ProcessError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Options {
    std::filesystem::path working_directory;
    // Added to, or replacing entries of, the parent's environment.
    std::vector<std::pair<std::string, std::string>> environment;
    // Called for every line of combined stdout and stderr, without the line ending.
    std::function<void(std::string_view line)> on_line;
    // Requesting stop terminates the child and everything it started.
    std::stop_token stop;
};

struct Result {
    int exit_code = 0;
    bool cancelled = false;
    std::string output;  // everything the child wrote

    bool ok() const noexcept { return !cancelled && exit_code == 0; }
};

// Runs `executable` with `arguments` and waits for it to finish. Throws
// ProcessError if the process cannot be started.
Result run(const std::filesystem::path& executable, const std::vector<std::string>& arguments,
           const Options& options = {});

// Quotes one argument the way CommandLineToArgvW and the MSVC runtime parse it.
std::string quote_argument(std::string_view argument);

// First match for `name` in the directories of %PATH%.
std::optional<std::filesystem::path> find_on_path(std::wstring_view name);

}  // namespace winx::process
