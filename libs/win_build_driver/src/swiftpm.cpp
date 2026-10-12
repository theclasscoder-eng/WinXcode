#include "winx/swiftpm.hpp"

#include <windows.h>

#include <knownfolders.h>
#include <shlobj.h>

#include <algorithm>
#include <charconv>
#include <format>

#include "winx/files.hpp"
#include "winx/process.hpp"
#include "winx/text.hpp"

namespace winx::build {
namespace {

namespace fs = std::filesystem;

constexpr const char* kTriple = "arm64-apple-ios";

std::optional<fs::path> newest_toolchain_under(const fs::path& toolchains) {
    std::error_code ec;
    std::vector<fs::path> candidates;
    for (const auto& entry : fs::directory_iterator(toolchains, ec)) {
        const fs::path swift = entry.path() / L"usr" / L"bin" / L"swift.exe";
        if (fs::is_regular_file(swift, ec)) candidates.push_back(swift);
    }
    if (candidates.empty()) return std::nullopt;
    // Toolchain directory names sort by version ("6.4.0+Asserts", ...).
    std::sort(candidates.begin(), candidates.end());
    return candidates.back();
}

fs::path known_folder(REFKNOWNFOLDERID id) {
    PWSTR raw = nullptr;
    fs::path result;
    if (SUCCEEDED(SHGetKnownFolderPath(id, 0, nullptr, &raw))) result = raw;
    CoTaskMemFree(raw);
    return result;
}

std::optional<int> parse_int(std::string_view text) {
    int value = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || end != text.data() + text.size() || text.empty()) return std::nullopt;
    return value;
}

std::string first_line(const std::string& text) {
    const auto end = text.find_first_of("\r\n");
    return text.substr(0, end);
}

}  // namespace

std::optional<std::pair<int, int>> parse_swift_version(std::string_view output) {
    // "Swift version 6.4 (swift-6.4-RELEASE)" or "... Swift version 6.4.1-dev ..."
    constexpr std::string_view marker = "Swift version ";
    const auto start = output.find(marker);
    if (start == std::string_view::npos) return std::nullopt;
    std::string_view rest = output.substr(start + marker.size());
    const auto digits_end = rest.find_first_not_of("0123456789.");
    rest = rest.substr(0, digits_end);
    const auto dot = rest.find('.');
    if (dot == std::string_view::npos) return std::nullopt;
    std::string_view minor_text = rest.substr(dot + 1);
    minor_text = minor_text.substr(0, minor_text.find('.'));
    const auto major = parse_int(rest.substr(0, dot));
    const auto minor = parse_int(minor_text);
    if (!major || !minor) return std::nullopt;
    return std::pair{*major, *minor};
}

Toolchain find_toolchain(const std::optional<fs::path>& explicit_path) {
    std::optional<fs::path> swift = explicit_path;
    if (!swift) {
        wchar_t override_path[MAX_PATH * 2];
        const DWORD length = GetEnvironmentVariableW(L"WINX_SWIFT", override_path,
                                                     static_cast<DWORD>(std::size(override_path)));
        if (length > 0 && length < std::size(override_path)) swift = fs::path(override_path);
    }
    if (!swift) swift = process::find_on_path(L"swift.exe");
    if (!swift) {
        // Per-user installs (the default since Swift 5.9), then the older machine-wide location.
        swift = newest_toolchain_under(known_folder(FOLDERID_LocalAppData) / L"Programs" / L"Swift" /
                                       L"Toolchains");
    }
    if (!swift) swift = newest_toolchain_under(L"C:\\Library\\Developer\\Toolchains");
    std::error_code ec;
    if (!swift || !fs::is_regular_file(*swift, ec)) {
        throw BuildError(
            "the Swift toolchain was not found. Install Swift for Windows 6.4 or newer from "
            "https://www.swift.org/install/windows/ (or `winget install Swift.Toolchain`), or set "
            "WINX_SWIFT to the path of swift.exe");
    }

    Toolchain toolchain;
    toolchain.swift = *swift;
    toolchain.bin_dir = swift->parent_path();
    const process::Result version = process::run(toolchain.swift, {"--version"});
    if (!version.ok()) {
        throw BuildError("`swift --version` failed: " + first_line(version.output));
    }
    toolchain.version_text = first_line(version.output);
    if (const auto parsed = parse_swift_version(version.output)) {
        toolchain.major = parsed->first;
        toolchain.minor = parsed->second;
    }
    return toolchain;
}

std::optional<Diagnostic> parse_diagnostic(std::string_view line) {
    // Search from the right-hand side of the location so that a drive letter's
    // colon ("C:\...") is not mistaken for a separator.
    for (const auto& [text, severity] :
         {std::pair{std::string_view(": error: "), Diagnostic::Severity::Error},
          std::pair{std::string_view(": warning: "), Diagnostic::Severity::Warning},
          std::pair{std::string_view(": note: "), Diagnostic::Severity::Note}}) {
        const auto marker = line.find(text);
        if (marker == std::string_view::npos) continue;
        const std::string_view location = line.substr(0, marker);
        const auto column_sep = location.rfind(':');
        if (column_sep == std::string_view::npos || column_sep == 0) continue;
        const auto line_sep = location.rfind(':', column_sep - 1);
        if (line_sep == std::string_view::npos || line_sep == 0) continue;
        const auto column = parse_int(location.substr(column_sep + 1));
        const auto row = parse_int(location.substr(line_sep + 1, column_sep - line_sep - 1));
        if (!column || !row) continue;

        Diagnostic diagnostic;
        diagnostic.file = std::string(location.substr(0, line_sep));
        diagnostic.line = *row;
        diagnostic.column = *column;
        diagnostic.severity = severity;
        diagnostic.message = std::string(line.substr(marker + text.size()));
        return diagnostic;
    }
    return std::nullopt;
}

std::string wrapper_target_name(const std::string& product) { return product + "-App"; }

std::string wrapper_manifest(const PackageInfo& package, const std::string& product,
                             const std::string& root_relative_path) {
    const std::string deployment =
        package.ios_deployment_target.empty() ? "17.0" : package.ios_deployment_target;
    return std::format(
        "// swift-tools-version: 6.0\n"
        "// Generated by WinXcode. Do not edit; it is rewritten on every build.\n"
        "\n"
        "import PackageDescription\n"
        "\n"
        "let package = Package(\n"
        "    name: \"{0}-winx\",\n"
        "    platforms: [.iOS(\"{1}\")],\n"
        "    dependencies: [\n"
        "        .package(name: \"RootPackage\", path: \"{2}\"),\n"
        "    ],\n"
        "    targets: [\n"
        "        .executableTarget(\n"
        "            name: \"{3}\",\n"
        "            dependencies: [\n"
        "                .product(name: \"{0}\", package: \"RootPackage\"),\n"
        "            ],\n"
        "            linkerSettings: [\n"
        "                .unsafeFlags([\"-Xlinker\", \"-rpath\", \"-Xlinker\", "
        "\"@executable_path/Frameworks\"]),\n"
        "            ]\n"
        "        ),\n"
        "    ]\n"
        ")\n",
        product, deployment, root_relative_path, wrapper_target_name(product));
}

BuildResult build_package(const BuildRequest& request) {
    BuildResult result;
    const fs::path& swift = request.toolchain.swift;

    if (request.toolchain.major != 0 &&
        std::pair{request.toolchain.major, request.toolchain.minor} <
            std::pair{kMinimumSwiftMajor, kMinimumSwiftMinor}) {
        throw BuildError(std::format(
            "{} is too old to cross-compile for iOS; Swift {}.{} or newer is required",
            request.toolchain.version_text, kMinimumSwiftMajor, kMinimumSwiftMinor));
    }
    std::error_code ec;
    if (!fs::is_directory(request.sdk_bundles_dir / L"darwin.artifactbundle", ec)) {
        throw BuildError("the iOS SDK is not installed; run `winx sdk install <Xcode.xip>` first");
    }

    // 1. What does the package offer?
    process::Options dump_options;
    dump_options.working_directory = request.project_dir;
    dump_options.stop = request.stop;
    const process::Result dump = process::run(swift, {"package", "dump-package"}, dump_options);
    if (dump.cancelled) {
        result.cancelled = true;
        return result;
    }
    if (!dump.ok()) {
        if (request.on_output) request.on_output(dump.output);
        throw BuildError("`swift package dump-package` failed; is Package.swift valid?");
    }
    // The manifest compiler can print warnings before the JSON document.
    const auto json_start = dump.output.find('{');
    result.package = parse_package_dump(
        json_start == std::string::npos ? std::string_view{} : std::string_view(dump.output).substr(json_start));
    result.product = select_product(request.config, result.package);

    // 2. Generate the wrapper package.
    const fs::path work = request.project_dir / L".build" / L"winx";
    const fs::path wrapper = work / L"package";
    const std::string target = wrapper_target_name(result.product);
    write_text_file(wrapper / L"Package.swift",
                    wrapper_manifest(result.package, result.product, "../../.."));
    write_text_file(wrapper / L"Sources" / to_wide(target) / L"stub.c",
                    "// The app's entry point comes from the @main type in the linked library.\n");

    // 3. Build.
    const fs::path scratch = work / L"build";
    std::vector<std::string> arguments = {
        "build",
        "--package-path", to_utf8(wrapper.wstring()),
        "--scratch-path", to_utf8(scratch.wstring()),
        "--swift-sdks-path", to_utf8(request.sdk_bundles_dir.wstring()),
        "--swift-sdk", kTriple,
        "--configuration", request.release ? "release" : "debug",
        "--product", target,
    };

    process::Options build_options;
    build_options.working_directory = request.project_dir;
    build_options.stop = request.stop;
    build_options.on_line = [&](std::string_view line) {
        if (request.on_output) request.on_output(line);
        if (auto diagnostic = parse_diagnostic(line)) {
            if (request.on_diagnostic) request.on_diagnostic(*diagnostic);
            result.diagnostics.push_back(std::move(*diagnostic));
        }
    };
    const process::Result build = process::run(swift, arguments, build_options);
    result.exit_code = build.exit_code;
    result.cancelled = build.cancelled;
    if (!build.ok()) return result;

    // 4. Locate the product.
    arguments.emplace_back("--show-bin-path");
    process::Options path_options;
    path_options.working_directory = request.project_dir;
    const process::Result bin_path = process::run(swift, arguments, path_options);
    std::string bin = first_line(bin_path.output);
    if (!bin_path.ok() || bin.empty()) {
        throw BuildError("the build succeeded but `swift build --show-bin-path` failed");
    }
    result.bin_dir = to_wide(bin);
    result.executable = result.bin_dir / to_wide(target);
    if (!fs::is_regular_file(result.executable, ec)) {
        throw BuildError("the build succeeded but did not produce " +
                         to_utf8(result.executable.wstring()));
    }
    result.success = true;
    return result;
}

}  // namespace winx::build
