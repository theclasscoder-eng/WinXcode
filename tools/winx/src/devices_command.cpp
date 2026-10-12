#include "commands.hpp"

#include <windows.h>

#include <chrono>
#include <format>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <thread>

#include "winx/files.hpp"
#include "winx/lockdown.hpp"
#include "winx/pair_record.hpp"
#include "winx/socket.hpp"
#include "winx/text.hpp"
#include "winx/usbmux.hpp"

namespace winx::cli {
namespace {

using device::DeviceEvent;
using device::DeviceInfo;
using device::UsbmuxDevice;
using device::UsbmuxEndpoint;

HANDLE g_stop_event = nullptr;

BOOL WINAPI on_console_control(DWORD) {
    SetEvent(g_stop_event);
    return TRUE;
}

std::string_view os_name(std::string_view device_class) {
    if (device_class == "iPad") return "iPadOS";
    if (device_class == "AppleTV") return "tvOS";
    if (device_class == "Watch") return "watchOS";
    return "iOS";
}

// lockdownd can take a moment to come up after a device is plugged in.
std::optional<DeviceInfo> query_info(const UsbmuxEndpoint& endpoint, std::uint32_t device_id,
                                     int attempts, std::string& failure) {
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (attempt > 0) std::this_thread::sleep_for(std::chrono::milliseconds(400));
        try {
            return device::query_device_info(endpoint, device_id);
        } catch (const std::exception& error) {
            failure = error.what();
        }
    }
    return std::nullopt;
}

void print_pairing_details(const std::string& udid,
                           const std::optional<device::PairRecord>& record) {
    const auto path = device::lockdown_directory() / (to_wide(udid) + L".plist");
    if (!record) {
        std::cout << "    no pairing record at " << to_utf8(path.wstring()) << '\n';
        return;
    }
    std::cout << "    pairing record: " << to_utf8(path.wstring()) << '\n';
    std::cout << "    fields:";
    for (const std::string& field : record->present_fields()) std::cout << ' ' << field;
    std::cout << '\n';
    std::cout << "    usable for a lockdown session: "
              << (record->usable_for_session() ? "yes" : "no") << '\n';
    // Only the PEM label is shown, never the key itself.
    const std::string_view key_pem(reinterpret_cast<const char*>(record->host_private_key.data()),
                                   record->host_private_key.size());
    if (const auto blocks = pem_decode_all(key_pem); !blocks.empty()) {
        std::cout << "    host key encoding: " << blocks.front().label << '\n';
    }
    if (const auto host_buid = device::load_system_buid()) {
        std::cout << "    SystemBUID matches this PC: "
                  << (*host_buid == record->system_buid ? "yes" : "no") << '\n';
    }
}

void print_device(const UsbmuxDevice& dev, const UsbmuxEndpoint& endpoint, std::string_view prefix,
                  int attempts, bool verbose) {
    std::string failure;
    const std::optional<DeviceInfo> info = query_info(endpoint, dev.device_id, attempts, failure);

    std::optional<device::PairRecord> record;
    std::string record_error;
    try {
        record = device::load_pair_record(dev.udid);
    } catch (const std::exception& error) {
        record_error = error.what();
    }

    std::string line = std::format("{}{}", prefix, dev.udid);
    if (info) {
        const auto or_unknown = [](const std::string& text) { return text.empty() ? "?" : text; };
        line += std::format("  \"{}\"  {}  {} {}", or_unknown(info->name),
                            or_unknown(info->product_type), os_name(info->device_class),
                            or_unknown(info->product_version));
    }
    line += std::format("  {}  paired={}", device::to_string(dev.connection),
                        record ? "yes" : "no");
    std::cout << line << '\n';

    if (!info) std::cout << "    could not query lockdownd: " << failure << '\n';
    if (!record_error.empty()) {
        std::cout << "    pairing record unreadable: " << record_error << '\n';
    } else if (verbose) {
        print_pairing_details(dev.udid, record);
    }
    std::cout.flush();
}

int list_once(const DevicesOptions& options, const UsbmuxEndpoint& endpoint) {
    const std::vector<UsbmuxDevice> devices = device::UsbmuxClient(endpoint).list_devices();
    if (devices.empty()) {
        std::cout << "No devices attached.\n";
        return 0;
    }
    for (const UsbmuxDevice& dev : devices) print_device(dev, endpoint, "", 2, options.verbose);
    return 0;
}

int list_paired() {
    const std::vector<std::string> udids = device::list_paired_udids();
    if (udids.empty()) {
        std::cout << "No pairing records in " << to_utf8(device::lockdown_directory().wstring())
                  << '\n';
        return 0;
    }
    int failures = 0;
    for (const std::string& udid : udids) {
        std::cout << udid << '\n';
        try {
            print_pairing_details(udid, device::load_pair_record(udid));
        } catch (const std::exception& error) {
            std::cout << "    pairing record unreadable: " << error.what() << '\n';
            ++failures;
        }
    }
    return failures == 0 ? 0 : 1;
}

int watch(const DevicesOptions& options, const UsbmuxEndpoint& endpoint) {
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(on_console_control, TRUE);

    // Only touched from the listener thread.
    std::map<std::uint32_t, std::string> attached;
    std::string listener_error;

    device::UsbmuxListener listener(
        endpoint,
        [&](const DeviceEvent& event) {
            switch (event.kind) {
                case DeviceEvent::Kind::Attached:
                    attached[event.device_id] = event.device->udid;
                    print_device(*event.device, endpoint, "[attached] ", 4, options.verbose);
                    break;
                case DeviceEvent::Kind::Detached: {
                    const auto known = attached.find(event.device_id);
                    std::cout << "[detached] "
                              << (known != attached.end()
                                      ? known->second
                                      : std::format("DeviceID {}", event.device_id))
                              << std::endl;
                    if (known != attached.end()) attached.erase(known);
                    break;
                }
                case DeviceEvent::Kind::Paired: {
                    const auto known = attached.find(event.device_id);
                    std::cout << "[paired]   "
                              << (known != attached.end()
                                      ? known->second
                                      : std::format("DeviceID {}", event.device_id))
                              << std::endl;
                    break;
                }
            }
        },
        [&](const std::string& message) {
            listener_error = message;
            SetEvent(g_stop_event);
        });

    std::cout << "Watching for devices on " << endpoint.host << ':' << endpoint.port
              << " (Ctrl+C to stop)" << std::endl;
    WaitForSingleObject(g_stop_event, INFINITE);
    listener.stop();

    SetConsoleCtrlHandler(on_console_control, FALSE);
    CloseHandle(g_stop_event);
    if (!listener_error.empty()) {
        std::cerr << "error: lost connection to usbmux: " << listener_error << '\n';
        return 1;
    }
    return 0;
}

}  // namespace

int run_devices(const DevicesOptions& options) {
    if (options.paired) return list_paired();
    const UsbmuxEndpoint endpoint{options.host, options.port};
    try {
        return options.watch ? watch(options, endpoint) : list_once(options, endpoint);
    } catch (const net::SocketError& error) {
        std::cerr << "error: " << error.what() << '\n'
                  << "Apple Mobile Device Service does not appear to be reachable. It is "
                     "installed with Apple Devices or iTunes and must be running.\n";
        return 1;
    }
}

}  // namespace winx::cli
