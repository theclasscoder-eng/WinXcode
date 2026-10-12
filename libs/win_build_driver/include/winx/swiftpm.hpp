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

#include "winx/project.hpp"

// Drives the Swift for Windows toolchain to cross-compile for iOS.
namespace winx::build {

class BuildError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Toolchain {
    std::filesystem::path swift;    // swift.exe
    std::filesystem::path bin_dir;  // its directory: swiftc, lld and friends live here
    std::string version_text;       // first line of `swift --version`
    int major = 0;
    int minor = 0;
};

// xtool's SDK layout relies on linker and librarian handling that is only
// correct from this release on.
inline constexpr int kMinimumSwiftMajor = 6;
inline constexpr int kMinimumSwiftMinor = 4;

std::optional<std::pair<int, int>> parse_swift_version(std::string_view version_output);

// Finds swift.exe: an explicit path, then %WINX_SWIFT%, then %PATH%, then the
// standard install locations. Throws BuildError with install guidance when
// none is found.
Toolchain find_toolchain(const std::optional<std::filesystem::path>& explicit_path = {});

struct Diagnostic {
    enum class Severity { Error, Warning, Note };
    std::string file;
    int line = 0;
    int column = 0;
    Severity severity = Severity::Error;
    std::string message;
};

// Recognises "<file>:<line>:<column>: error: <message>" as swiftc and clang
// print it, including Windows paths with a drive letter.
std::optional<Diagnostic> parse_diagnostic(std::string_view line);

struct BuildRequest {
    std::filesystem::path project_dir;
    ProjectConfig config;
    Toolchain toolchain;
    // Directory holding darwin.artifactbundle (see sdk.hpp).
    std::filesystem::path sdk_bundles_dir;
    bool release = false;
    std::function<void(std::string_view)> on_output;
    std::function<void(const Diagnostic&)> on_diagnostic;
    std::stop_token stop;
};

struct BuildResult {
    bool success = false;
    bool cancelled = false;
    int exit_code = 0;
    std::string product;
    PackageInfo package;
    std::filesystem::path bin_dir;
    std::filesystem::path executable;
    std::vector<Diagnostic> diagnostics;
};

// The wrapper package that turns the project's library product into an
// executable, as xtool does: an executable target with an empty C source that
// links the library, whose @main type supplies the entry point.
std::string wrapper_manifest(const PackageInfo& package, const std::string& product,
                             const std::string& root_relative_path);
std::string wrapper_target_name(const std::string& product);

// Dumps the package, generates the wrapper under <project>/.build/winx and
// runs `swift build --swift-sdk arm64-apple-ios`.
BuildResult build_package(const BuildRequest& request);

}  // namespace winx::build
