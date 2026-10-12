#include "commands.hpp"

#include <windows.h>

#include <chrono>
#include <format>
#include <iostream>

#include "winx/codesign.hpp"
#include "winx/device_services.hpp"
#include "winx/lockdown.hpp"
#include "winx/text.hpp"

namespace winx::cli {
namespace {

HANDLE g_stop = nullptr;

BOOL WINAPI on_control(DWORD) {
    SetEvent(g_stop);
    return TRUE;
}

void warn_about_developer_mode(device::DeviceConnection& connection) {
    const auto enabled = device::developer_mode_enabled(connection);
    if (enabled && !*enabled) {
        std::cout << "Note: Developer Mode is off on this device, so the app will install but "
                     "not launch.\n"
                     "      Run `winx device devmode --reveal`, then turn it on under Settings > "
                     "Privacy & Security.\n";
    }
}

template <class Action>
int with_device(const DeviceOptions& options, Action action) {
    try {
        device::DeviceConnection connection = device::DeviceConnection::open(
            device::UsbmuxEndpoint{options.host, options.port}, options.udid);
        return action(connection);
    } catch (const net::SocketError& error) {
        std::cerr << "error: " << error.what() << '\n';
    } catch (const device::LockdownError& error) {
        std::cerr << "error: " << error.what() << '\n';
    } catch (const device::InstallError& error) {
        std::cerr << "error: " << error.what() << '\n';
    } catch (const device::AfcError& error) {
        std::cerr << "error: " << error.what() << '\n';
    }
    return 1;
}

}  // namespace

int run_install(const DeviceOptions& options) {
    const std::filesystem::path bundle = to_wide(options.target);
    if (!std::filesystem::is_directory(bundle)) {
        std::cerr << "error: " << options.target << " is not an .app bundle directory\n";
        return 1;
    }
    // Catch an unsigned or stale bundle here rather than as a terse device error.
    const auto problems = codesign::verify_bundle(bundle);
    if (!problems.empty()) {
        std::cerr << "error: the bundle's signature is not consistent; sign it again with "
                     "`winx sign`:\n";
        for (const std::string& problem : problems) std::cerr << "  " << problem << '\n';
        return 1;
    }

    return with_device(options, [&](device::DeviceConnection& connection) {
        std::cout << "Installing on " << connection.device().udid << '\n';
        std::string last_stage;
        device::install_app(connection, bundle, [&](const std::string& stage, int percent) {
            if (stage == "Uploading") {
                std::cout << std::format("\rUploading {:3}%", percent) << std::flush;
                if (percent == 100) std::cout << '\n';
            } else if (stage != last_stage) {
                std::cout << stage << (percent >= 0 ? std::format(" ({}%)", percent) : "") << '\n';
            }
            last_stage = stage;
        });
        std::cout << "Installed.\n";
        warn_about_developer_mode(connection);
        return 0;
    });
}

int run_uninstall(const DeviceOptions& options) {
    return with_device(options, [&](device::DeviceConnection& connection) {
        device::uninstall_app(connection, options.target);
        std::cout << "Removed " << options.target << '\n';
        return 0;
    });
}

int run_apps(const DeviceOptions& options) {
    return with_device(options, [&](device::DeviceConnection& connection) {
        for (const device::InstalledApp& app : device::list_apps(connection)) {
            std::cout << std::format("{}  {}  {}\n", app.bundle_id, app.version, app.name);
        }
        return 0;
    });
}

int run_devmode(const DeviceOptions& options) {
    return with_device(options, [&](device::DeviceConnection& connection) {
        const auto enabled = device::developer_mode_enabled(connection);
        if (!enabled) {
            std::cout << "This device does not have a Developer Mode setting (iOS 15 or earlier).\n";
            return 0;
        }
        std::cout << "Developer Mode is " << (*enabled ? "on" : "off") << ".\n";
        if (!*enabled && options.reveal) {
            device::reveal_developer_mode(connection);
            std::cout << "The switch is now visible under Settings > Privacy & Security > "
                         "Developer Mode. Turning it on restarts the device.\n";
        }
        return 0;
    });
}

int run_log(const DeviceOptions& options) {
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(on_control, TRUE);
    const int result = with_device(options, [&](device::DeviceConnection& connection) {
        device::SyslogStream log = device::SyslogStream::open(connection);
        while (WaitForSingleObject(g_stop, 0) != WAIT_OBJECT_0) {
            if (const auto line = log.read_line(std::chrono::milliseconds(250))) {
                std::cout << *line << '\n';
            }
        }
        return 0;
    });
    SetConsoleCtrlHandler(on_control, FALSE);
    CloseHandle(g_stop);
    return result;
}

}  // namespace winx::cli
