#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "winx/archive.hpp"
#include "winx/swiftpm.hpp"

// Turns the user's own Xcode.xip into a SwiftPM "Swift SDK" artifact bundle
// for arm64-apple-ios, laid out as xtool lays it out on Linux.
namespace winx::build {

inline constexpr const wchar_t* kSdkBundleName = L"darwin.artifactbundle";

// Default parent directory of the bundle: <app data>/sdk.
std::filesystem::path default_sdk_dir();

// Whether an archive path (as stored in the xip, e.g.
// "Xcode.app/Contents/Developer/Platforms/...") belongs in the SDK. On a
// match `relative` receives the path inside the bundle.
bool select_sdk_path(std::string_view archive_path, std::string& relative);

// Why a path cannot be created on NTFS as is, or empty if it can.
std::string windows_path_problem(std::string_view relative_path);

struct InstalledSdk {
    std::filesystem::path bundle;  // .../darwin.artifactbundle
    std::string sdk_name;          // e.g. "iPhoneOS18.2.sdk"
    std::string version;           // e.g. "18.2"
};

std::optional<InstalledSdk> find_installed_sdk(const std::filesystem::path& sdk_dir);

nlohmann::json make_info_json();
nlohmann::json make_toolset_json();
nlohmann::json make_swift_sdk_json(const std::string& sdk_name);

struct SdkInstallReport {
    InstalledSdk sdk;
    std::uint64_t files = 0;
    std::uint64_t bytes = 0;
    std::uint64_t links_as_links = 0;
    std::uint64_t links_as_copies = 0;
    // Paths that could not be represented on Windows, with the reason.
    std::vector<std::string> skipped;
    // Tools the bundle expects from the Swift toolchain but did not find.
    std::vector<std::string> missing_tools;
};

struct SdkInstallOptions {
    std::filesystem::path xip;
    std::filesystem::path sdk_dir;  // parent of the bundle; default_sdk_dir() when empty
    // Where ld64.lld and the librarian are copied from.
    std::optional<Toolchain> toolchain;
    // Path of winx-ld64-shim.exe; next to the running program when empty.
    std::filesystem::path linker_shim;
    std::function<void(const std::string&)> log;
    std::function<void(std::uint64_t done, std::uint64_t total)> progress;
    std::stop_token stop;
};

// Streams the xip once, writing only the selected paths. Replaces any
// previously installed bundle.
SdkInstallReport install_sdk(const SdkInstallOptions& options);

// The extraction core, separated from the xar container so that it can be
// driven from memory in tests: reads cpio entries from `source` into `bundle`.
void extract_sdk_entries(ByteSource& source, const std::filesystem::path& bundle,
                         SdkInstallReport& report, const std::stop_token& stop = {},
                         const std::function<void()>& tick = {});

}  // namespace winx::build
