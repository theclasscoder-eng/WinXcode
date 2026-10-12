#include "winx/sdk.hpp"

#include <windows.h>

#include <winioctl.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <format>
#include <fstream>
#include <map>
#include <regex>
#include <set>

#include "winx/files.hpp"
#include "winx/text.hpp"

namespace winx::build {
namespace {

namespace fs = std::filesystem;
using nlohmann::json;

constexpr std::string_view kDeveloperPrefix = "Contents/Developer/";
constexpr std::string_view kToolchainLib = "Toolchains/XcodeDefault.xctoolchain/usr/lib/";
constexpr std::string_view kPlatform = "Platforms/iPhoneOS.platform/";

// Swift and clang runtime directories for platforms other than iOS devices.
constexpr std::string_view kOtherPlatforms[] = {
    "macosx",          "appletvos",      "appletvsimulator", "watchos",   "watchsimulator",
    "xros",            "xrsimulator",    "iphonesimulator",  "driverkit", "maccatalyst",
    "prebuilt-modules"};

// Prefixes a path so Win32 accepts more than MAX_PATH characters. SDK paths
// routinely exceed 260.
fs::path long_path(const fs::path& path) {
    const std::wstring text = fs::absolute(path).wstring();
    if (text.starts_with(L"\\\\?\\")) return path;
    return fs::path(L"\\\\?\\" + text);
}

std::string lower(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

struct PendingLink {
    std::string path;    // bundle-relative
    std::string target;  // as stored, relative to the link's directory
};

// Parent directory of a forward-slash path, with trailing slash, or "".
std::string_view directory_of(std::string_view path) {
    const auto slash = path.rfind('/');
    return slash == std::string_view::npos ? std::string_view{} : path.substr(0, slash + 1);
}

// Resolves "a/b/../c" style paths; returns false if it escapes the root.
bool normalize(std::string_view path, std::string& out) {
    std::vector<std::string_view> parts;
    std::size_t pos = 0;
    while (pos <= path.size()) {
        auto end = path.find('/', pos);
        if (end == std::string_view::npos) end = path.size();
        const std::string_view part = path.substr(pos, end - pos);
        if (part == "..") {
            if (parts.empty()) return false;
            parts.pop_back();
        } else if (!part.empty() && part != ".") {
            parts.push_back(part);
        }
        pos = end + 1;
    }
    out.clear();
    for (const std::string_view part : parts) {
        if (!out.empty()) out += '/';
        out += part;
    }
    return true;
}

void copy_tool(const fs::path& from, const fs::path& to) {
    fs::create_directories(to.parent_path());
    fs::copy_file(from, to, fs::copy_options::overwrite_existing);
}

// Directory junction at `link` pointing to the absolute directory `target`.
bool create_junction(const fs::path& link, const fs::path& target) {
    std::error_code ec;
    fs::create_directory(link, ec);
    const HANDLE handle =
        CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;

    std::wstring print_name = target.wstring();
    if (print_name.starts_with(L"\\\\?\\")) print_name.erase(0, 4);
    const std::wstring substitute = L"\\??\\" + print_name;
    const auto substitute_bytes = static_cast<USHORT>(substitute.size() * sizeof(wchar_t));
    const auto print_bytes = static_cast<USHORT>(print_name.size() * sizeof(wchar_t));

    // REPARSE_DATA_BUFFER for IO_REPARSE_TAG_MOUNT_POINT: an 8-byte header,
    // four USHORT offsets/lengths, then both names, each NUL-terminated.
    const std::size_t path_bytes = substitute_bytes + sizeof(wchar_t) + print_bytes + sizeof(wchar_t);
    std::vector<std::uint8_t> buffer(8 + 8 + path_bytes, 0);
    const auto put16 = [&](std::size_t offset, USHORT value) {
        std::memcpy(buffer.data() + offset, &value, sizeof(value));
    };
    const ULONG tag = IO_REPARSE_TAG_MOUNT_POINT;
    std::memcpy(buffer.data(), &tag, sizeof(tag));
    put16(4, static_cast<USHORT>(8 + path_bytes));  // ReparseDataLength
    put16(8, 0);                                    // SubstituteNameOffset
    put16(10, substitute_bytes);
    put16(12, static_cast<USHORT>(substitute_bytes + sizeof(wchar_t)));  // PrintNameOffset
    put16(14, print_bytes);
    std::memcpy(buffer.data() + 16, substitute.data(), substitute_bytes);
    std::memcpy(buffer.data() + 16 + substitute_bytes + sizeof(wchar_t), print_name.data(),
                print_bytes);

    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, buffer.data(),
                                    static_cast<DWORD>(buffer.size()), nullptr, 0, &returned,
                                    nullptr);
    CloseHandle(handle);
    if (!ok) fs::remove(link, ec);
    return ok != FALSE;
}

std::optional<std::pair<std::string, std::string>> detect_sdk(const fs::path& bundle) {
    const fs::path sdks = bundle / L"Developer" / L"Platforms" / L"iPhoneOS.platform" /
                          L"Developer" / L"SDKs";
    // "iPhoneOS18.2.sdk" is the real directory; "iPhoneOS.sdk" is a link to it.
    static const std::regex pattern(R"(^iPhoneOS(\d+(\.\d+)*)\.sdk$)");
    std::error_code ec;
    std::optional<std::pair<std::string, std::string>> found;
    for (const auto& entry : fs::directory_iterator(sdks, ec)) {
        const std::string name = to_utf8(entry.path().filename().wstring());
        std::smatch match;
        if (std::regex_match(name, match, pattern)) found = std::pair{name, match[1].str()};
    }
    return found;
}

}  // namespace

fs::path default_sdk_dir() { return app_data_dir() / L"sdk"; }

bool select_sdk_path(std::string_view archive_path, std::string& relative) {
    // Entries look like "Xcode.app/Contents/Developer/..." (or Xcode-beta.app).
    const auto developer = archive_path.find(kDeveloperPrefix);
    if (developer == std::string_view::npos) return false;
    const std::string_view app = archive_path.substr(0, developer);
    if (!app.ends_with(".app/") || app.find('/') != app.size() - 1) return false;
    const std::string_view rest = archive_path.substr(developer + kDeveloperPrefix.size());

    bool wanted = false;
    if (rest.starts_with(kToolchainLib)) {
        const std::string_view inside = rest.substr(kToolchainLib.size());
        const auto first_end = inside.find('/');
        const std::string_view top = inside.substr(0, first_end);
        if (top == "swift" || top == "swift_static" || top == "clang") {
            wanted = true;
            // Drop runtime directories for platforms this tool does not target.
            std::size_t pos = 0;
            while (pos <= inside.size()) {
                auto end = inside.find('/', pos);
                if (end == std::string_view::npos) end = inside.size();
                const std::string_view component = inside.substr(pos, end - pos);
                if (std::find(std::begin(kOtherPlatforms), std::end(kOtherPlatforms), component) !=
                    std::end(kOtherPlatforms)) {
                    wanted = false;
                    break;
                }
                pos = end + 1;
            }
            // clang's own headers come from the host toolchain, as in xtool.
            if (wanted && top == "clang" && inside.find("/include/") != std::string_view::npos) {
                wanted = false;
            }
        }
    } else if (rest.starts_with(kPlatform)) {
        const std::string_view inside = rest.substr(kPlatform.size());
        wanted = inside == "Info.plist" || inside.starts_with("Developer/SDKs/") ||
                 inside.starts_with("Developer/Library/Frameworks/") ||
                 inside.starts_with("Developer/Library/PrivateFrameworks/") ||
                 inside.starts_with("Developer/usr/lib/");
    }
    if (!wanted) return false;
    relative = "Developer/" + std::string(rest);
    return true;
}

std::string windows_path_problem(std::string_view relative_path) {
    static constexpr std::string_view kReserved[] = {"con",  "prn",  "aux",  "nul",  "com1", "com2",
                                                     "com3", "com4", "com5", "com6", "com7", "com8",
                                                     "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5",
                                                     "lpt6", "lpt7", "lpt8", "lpt9"};
    std::size_t pos = 0;
    while (pos <= relative_path.size()) {
        auto end = relative_path.find('/', pos);
        if (end == std::string_view::npos) end = relative_path.size();
        const std::string_view component = relative_path.substr(pos, end - pos);
        if (!component.empty()) {
            if (component.find_first_of("<>:\"\\|?*") != std::string_view::npos) {
                return "contains a character Windows does not allow in file names";
            }
            for (const char c : component) {
                if (static_cast<unsigned char>(c) < 0x20) return "contains a control character";
            }
            if (component.back() == '.' || component.back() == ' ') {
                return "ends in a dot or space";
            }
            const std::string stem = lower(component.substr(0, component.find('.')));
            if (std::find(std::begin(kReserved), std::end(kReserved), stem) != std::end(kReserved)) {
                return "uses a reserved device name";
            }
        }
        pos = end + 1;
    }
    return {};
}

json make_info_json() {
    return {{"schemaVersion", "1.0"},
            {"artifacts",
             {{"darwin",
               {{"type", "swiftSDK"},
                {"version", "0.0.1"},
                {"variants",
                 json::array({{{"path", "."},
                               {"supportedTriples",
                                {"x86_64-unknown-windows-msvc", "aarch64-unknown-windows-msvc"}}}})}}}}}};
}

json make_toolset_json() {
    return {{"schemaVersion", "1.0"},
            {"rootPath", "toolset/bin"},
            {"linker", {{"path", "ld64.lld.exe"}}},
            {"librarian", {{"path", "llvm-lib.exe"}}},
            {"swiftCompiler",
             {{"extraCLIOptions", {"-Xfrontend", "-enable-cross-import-overlays", "-use-ld=lld"}}}}};
}

json make_swift_sdk_json(const std::string& sdk_name) {
    const std::string platform = "Developer/Platforms/iPhoneOS.platform/Developer";
    const std::string toolchain = "Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib";
    return {{"schemaVersion", "4.0"},
            {"targetTriples",
             {{"arm64-apple-ios",
               {{"sdkRootPath", platform + "/SDKs/" + sdk_name},
                {"includeSearchPaths", json::array({platform + "/usr/lib"})},
                {"librarySearchPaths", json::array({platform + "/usr/lib"})},
                {"swiftResourcesPath", toolchain + "/swift"},
                {"swiftStaticResourcesPath", toolchain + "/swift_static"},
                {"toolsetPaths", json::array({"toolset.json"})}}}}}};
}

std::optional<InstalledSdk> find_installed_sdk(const fs::path& sdk_dir) {
    const fs::path bundle = sdk_dir / kSdkBundleName;
    std::error_code ec;
    // swift-sdk.json is written last, so its presence marks a complete install.
    if (!fs::is_regular_file(bundle / L"swift-sdk.json", ec)) return std::nullopt;
    const auto sdk = detect_sdk(bundle);
    if (!sdk) return std::nullopt;
    return InstalledSdk{bundle, sdk->first, sdk->second};
}

void extract_sdk_entries(ByteSource& source, const fs::path& bundle, SdkInstallReport& report,
                         const std::stop_token& stop, const std::function<void()>& tick) {
    CpioReader cpio(source);
    ArchiveEntry entry;
    std::set<std::string> written;  // lower-cased, to detect case collisions
    std::vector<PendingLink> links;

    while (cpio.next(entry)) {
        if (stop.stop_requested()) throw ArchiveError("the SDK installation was cancelled");
        if (tick) tick();

        std::string relative;
        if (!select_sdk_path(entry.path, relative)) continue;
        if (const std::string problem = windows_path_problem(relative); !problem.empty()) {
            report.skipped.push_back(relative + ": " + problem);
            continue;
        }
        const fs::path target = long_path(bundle / to_wide(relative));

        if (entry.type == ArchiveEntry::Type::Directory) {
            fs::create_directories(target);
        } else if (entry.type == ArchiveEntry::Type::File) {
            if (!written.insert(lower(relative)).second) {
                report.skipped.push_back(relative + ": differs only by case from another file");
                continue;
            }
            fs::create_directories(target.parent_path());
            std::ofstream out(target, std::ios::binary | std::ios::trunc);
            if (!out) throw ArchiveError("cannot write " + relative);
            cpio.read_data([&](ByteView chunk) {
                out.write(reinterpret_cast<const char*>(chunk.data()),
                          static_cast<std::streamsize>(chunk.size()));
                report.bytes += chunk.size();
            });
            if (!out) throw ArchiveError("cannot write " + relative + " (is the disk full?)");
            ++report.files;
        } else if (entry.type == ArchiveEntry::Type::Symlink) {
            links.push_back({relative, entry.link_target});
        }
    }

    // Links are materialised last, when their targets exist. Creating a real
    // symbolic link needs Developer Mode or elevation on Windows, so fall
    // back to a copy; several passes resolve links that point at links.
    for (int pass = 0; pass < 8 && !links.empty(); ++pass) {
        std::vector<PendingLink> unresolved;
        for (const PendingLink& link : links) {
            std::string resolved;
            if (link.target.starts_with('/') ||
                !normalize(std::string(directory_of(link.path)) + link.target, resolved)) {
                report.skipped.push_back(link.path + ": link points outside the SDK");
                continue;
            }
            const fs::path from = long_path(bundle / to_wide(resolved));
            const fs::path to = long_path(bundle / to_wide(link.path));
            std::error_code ec;
            if (!fs::exists(from, ec)) {
                unresolved.push_back(link);
                continue;
            }
            fs::create_directories(to.parent_path(), ec);
            fs::remove_all(to, ec);
            const bool directory = fs::is_directory(from, ec);
            std::wstring link_text = to_wide(link.target);
            std::replace(link_text.begin(), link_text.end(), L'/', L'\\');
            ec.clear();
            if (directory) {
                fs::create_directory_symlink(link_text, to, ec);
                // Junctions need no privilege and avoid duplicating a whole
                // directory such as iPhoneOS.sdk -> iPhoneOS18.2.sdk.
                if (ec && create_junction(to, fs::absolute(bundle / to_wide(resolved)))) ec.clear();
            } else {
                fs::create_symlink(link_text, to, ec);
                if (ec && CreateHardLinkW(to.c_str(), from.c_str(), nullptr)) ec.clear();
            }
            if (!ec) {
                ++report.links_as_links;
                continue;
            }
            ec.clear();
            fs::remove_all(to, ec);
            fs::copy(from, to, fs::copy_options::recursive | fs::copy_options::overwrite_existing, ec);
            if (ec) {
                report.skipped.push_back(link.path + ": could not be linked or copied");
            } else {
                ++report.links_as_copies;
            }
        }
        if (unresolved.size() == links.size()) {
            for (const PendingLink& link : unresolved) {
                report.skipped.push_back(link.path + ": link target is not part of the SDK");
            }
            break;
        }
        links = std::move(unresolved);
    }
}

SdkInstallReport install_sdk(const SdkInstallOptions& options) {
    const auto say = [&](const std::string& message) {
        if (options.log) options.log(message);
    };
    const fs::path sdk_dir = options.sdk_dir.empty() ? default_sdk_dir() : options.sdk_dir;
    const fs::path bundle = sdk_dir / kSdkBundleName;
    // Written in place: junctions hold absolute paths, so the tree cannot be
    // assembled elsewhere and renamed. An interrupted install is recognisable
    // by its missing swift-sdk.json.
    const fs::path& staging = bundle;

    const std::vector<XarMember> members = read_xar_members(options.xip);
    const auto content = std::find_if(members.begin(), members.end(),
                                      [](const XarMember& member) { return member.name == "Content"; });
    if (content == members.end()) {
        throw ArchiveError("the archive has no Content member; is this an Xcode .xip?");
    }
    if (!content->encoding.empty() && content->encoding != "application/octet-stream") {
        throw ArchiveError("the xip stores its content with an unsupported encoding: " +
                           content->encoding);
    }

    std::error_code ec;
    fs::remove_all(long_path(staging), ec);
    fs::create_directories(staging);

    SdkInstallReport report;
    say("Unpacking the iOS SDK from " + to_utf8(options.xip.filename().wstring()));
    FileRangeSource file(options.xip, content->offset, content->length);
    PbzxSource pbzx(file);
    extract_sdk_entries(pbzx, staging, report, options.stop, [&] {
        if (options.progress) options.progress(file.consumed(), file.length());
    });
    if (options.progress) options.progress(file.length(), file.length());

    // Toolset: the linker and librarian come from the Swift toolchain.
    const fs::path tools = staging / L"toolset" / L"bin";
    fs::create_directories(tools / L"orig");
    if (options.toolchain) {
        const fs::path& bin = options.toolchain->bin_dir;
        // lld picks its personality from the name it is started under.
        fs::path linker = bin / L"ld64.lld.exe";
        if (!fs::is_regular_file(linker, ec)) linker = bin / L"lld.exe";
        if (fs::is_regular_file(linker, ec)) {
            copy_tool(linker, tools / L"orig" / L"ld64.lld.exe");
        } else {
            report.missing_tools.emplace_back("ld64.lld.exe (or lld.exe)");
        }
        const fs::path librarian = bin / L"llvm-libtool-darwin.exe";
        if (fs::is_regular_file(librarian, ec)) {
            copy_tool(librarian, tools / L"llvm-lib.exe");
        } else {
            report.missing_tools.emplace_back("llvm-libtool-darwin.exe");
        }
    } else {
        report.missing_tools.emplace_back("the Swift toolchain itself");
    }
    fs::path shim = options.linker_shim;
    if (shim.empty()) {
        wchar_t self[MAX_PATH * 2];
        const DWORD length = GetModuleFileNameW(nullptr, self, static_cast<DWORD>(std::size(self)));
        shim = fs::path(std::wstring(self, length)).parent_path() / L"winx-ld64-shim.exe";
    }
    if (fs::is_regular_file(shim, ec)) {
        copy_tool(shim, tools / L"ld64.lld.exe");
    } else {
        report.missing_tools.emplace_back("winx-ld64-shim.exe");
    }

    const auto sdk = detect_sdk(bundle);
    if (!sdk) {
        throw ArchiveError("the archive did not contain an iPhoneOS SDK; is this an Xcode .xip?");
    }
    write_text_file(bundle / L"info.json", make_info_json().dump(2));
    write_text_file(bundle / L"toolset.json", make_toolset_json().dump(2));
    write_text_file(bundle / L"swift-sdk.json", make_swift_sdk_json(sdk->first).dump(2));
    report.sdk = InstalledSdk{bundle, sdk->first, sdk->second};
    say(std::format("Installed {} ({} files, {:.1f} GB)", sdk->first, report.files,
                    static_cast<double>(report.bytes) / (1024.0 * 1024.0 * 1024.0)));
    return report;
}

}  // namespace winx::build
