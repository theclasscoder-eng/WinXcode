#include "commands.hpp"

#include <windows.h>

#include <format>
#include <iostream>
#include <stop_token>

#include "winx/pipeline.hpp"
#include "winx/project.hpp"
#include "winx/sdk.hpp"
#include "winx/swiftpm.hpp"
#include "winx/text.hpp"

namespace winx::cli {
namespace {

std::stop_source g_stop;

BOOL WINAPI on_control(DWORD) {
    g_stop.request_stop();
    return TRUE;
}

const char* severity_name(build::Diagnostic::Severity severity) {
    switch (severity) {
        case build::Diagnostic::Severity::Error: return "error";
        case build::Diagnostic::Severity::Warning: return "warning";
        case build::Diagnostic::Severity::Note: return "note";
    }
    return "";
}

int run_pipeline_command(const BuildOptions& options, bool sign, bool install) {
    engine::PipelineOptions pipeline;
    pipeline.project_dir = std::filesystem::absolute(to_wide(options.project_dir));
    pipeline.udid = options.udid;
    pipeline.release = options.release;
    pipeline.sign = sign;
    pipeline.install = install;
    if (!options.swift_path.empty()) pipeline.swift = to_wide(options.swift_path);
    pipeline.stop = g_stop.get_token();
    SetConsoleCtrlHandler(on_control, TRUE);

    bool progress_line_open = false;
    const engine::PipelineResult result =
        engine::run_pipeline(pipeline, [&](const engine::Event& event) {
            if (progress_line_open && event.kind != engine::Event::Kind::Progress) {
                std::cout << '\n';
                progress_line_open = false;
            }
            switch (event.kind) {
                case engine::Event::Kind::Stage:
                    std::cout << "==> " << event.text << '\n';
                    break;
                case engine::Event::Kind::Log:
                    // Diagnostics are printed from their own event below.
                    if (!build::parse_diagnostic(event.text)) std::cout << event.text << '\n';
                    break;
                case engine::Event::Kind::Diagnostic:
                    std::cout << std::format("{}:{}:{}: {}: {}\n", event.diagnostic->file,
                                             event.diagnostic->line, event.diagnostic->column,
                                             severity_name(event.diagnostic->severity), event.text);
                    break;
                case engine::Event::Kind::Warning:
                    std::cout << "warning: " << event.text << '\n';
                    break;
                case engine::Event::Kind::Progress:
                    if (event.percent >= 0) {
                        std::cout << std::format("\r{} {:3}%   ", event.text, event.percent)
                                  << std::flush;
                        progress_line_open = true;
                    } else {
                        std::cout << event.text << '\n';
                    }
                    break;
            }
        });
    if (progress_line_open) std::cout << '\n';
    SetConsoleCtrlHandler(on_control, FALSE);

    if (!result.success) {
        std::cerr << "error: " << result.error << '\n';
        return result.cancelled ? 130 : 1;
    }
    std::cout << (install ? "Installed " : sign ? "Signed " : "Built ") << result.bundle_id << " at "
              << to_utf8(result.bundle.wstring()) << '\n';
    if (install) std::cout << "Tap the app on the device to launch it.\n";
    return 0;
}

}  // namespace

int run_build(const BuildOptions& options) { return run_pipeline_command(options, false, false); }

int run_dev(const BuildOptions& options) { return run_pipeline_command(options, true, true); }

int run_new(const NewOptions& options) {
    try {
        const std::filesystem::path directory = std::filesystem::absolute(to_wide(options.name));
        build::create_project(directory, options.name, options.org_id);
        std::cout << "Created " << to_utf8(directory.wstring()) << "\n"
                  << "Next: cd " << options.name << " && winx dev\n";
        return 0;
    } catch (const build::ProjectError& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}

int run_sdk(const SdkOptions& options) {
    try {
        if (options.action == "status") {
            if (const auto sdk = build::find_installed_sdk(build::default_sdk_dir())) {
                std::cout << sdk->sdk_name << " at " << to_utf8(sdk->bundle.wstring()) << '\n';
                return 0;
            }
            std::cout << "No iOS SDK is installed. Run `winx sdk install <Xcode.xip>`.\n";
            return 1;
        }

        std::cout
            << "The iOS SDK is taken from your own copy of Xcode. Apple's Xcode and Apple SDKs\n"
               "Agreement limits use of the SDK to Apple-branded computers; whether to use it on\n"
               "this PC is your decision.\n\n";
        if (!options.accept && !confirm("Continue?")) return 1;

        build::SdkInstallOptions install;
        install.xip = to_wide(options.xip);
        try {
            install.toolchain = build::find_toolchain();
        } catch (const build::BuildError& error) {
            std::cout << "warning: " << error.what() << '\n';
        }
        install.log = [](const std::string& line) { std::cout << line << '\n'; };
        int last = -1;
        install.progress = [&](std::uint64_t done, std::uint64_t total) {
            const int percent = total == 0 ? 0 : static_cast<int>(done * 100 / total);
            if (percent != last) std::cout << std::format("\r{:3}%", percent) << std::flush;
            last = percent;
        };
        g_stop = std::stop_source();
        install.stop = g_stop.get_token();
        SetConsoleCtrlHandler(on_control, TRUE);
        const build::SdkInstallReport report = build::install_sdk(install);
        SetConsoleCtrlHandler(on_control, FALSE);
        std::cout << '\n';

        std::cout << std::format("Links: {} created, {} replaced by copies\n", report.links_as_links,
                                 report.links_as_copies);
        if (!report.skipped.empty()) {
            std::cout << report.skipped.size()
                      << " path(s) could not be represented on Windows and were left out:\n";
            for (std::size_t i = 0; i < report.skipped.size() && i < 10; ++i) {
                std::cout << "  " << report.skipped[i] << '\n';
            }
            if (report.skipped.size() > 10) std::cout << "  ...\n";
        }
        for (const std::string& tool : report.missing_tools) {
            std::cout << "warning: not found, builds will fail until it is available: " << tool << '\n';
        }
        return report.missing_tools.empty() ? 0 : 1;
    } catch (const build::ArchiveError& error) {
        std::cerr << "\nerror: " << error.what() << '\n';
    }
    return 1;
}

int run_setup() {
    bool all_ready = true;
    for (const engine::Prerequisite& item : engine::check_prerequisites()) {
        std::cout << std::format("[{}] {:<28} {}\n", item.ready ? "ok" : "  ", item.name, item.detail);
        // A device is only needed at install time.
        if (!item.ready && item.name != "Device") all_ready = false;
    }
    return all_ready ? 0 : 1;
}

}  // namespace winx::cli
