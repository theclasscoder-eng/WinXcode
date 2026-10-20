#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "support.hpp"
#include "winx/identity.hpp"
#include "winx/pair_record.hpp"
#include "winx/plist.hpp"
#include "winx/socket.hpp"
#include "winx/tls.hpp"
#include "winx/usbmux.hpp"

namespace winx::test {

// An in-process iPhone: Apple Mobile Device Service's usbmux front end, plus
// lockdownd (with the StartSession TLS upgrade), AFC, installation_proxy,
// syslog_relay and the AMFI service behind it. It speaks real TLS with a
// certificate hierarchy shaped like a pairing record's.
class FakeDevice {
public:
    FakeDevice();
    ~FakeDevice();
    FakeDevice(const FakeDevice&) = delete;
    FakeDevice& operator=(const FakeDevice&) = delete;

    device::UsbmuxEndpoint endpoint() const { return {"127.0.0.1", listener_.port()}; }
    const std::string& udid() const { return udid_; }
    // The pairing record a PC would hold for this device.
    const device::PairRecord& pair_record() const { return pair_record_; }
    const crypto::Bytes& host_certificate() const { return host_certificate_; }

    // Behaviour switches and observations. Guard with `mutex` while the
    // device is serving.
    std::mutex mutex;
    // Whether Apple Mobile Device Service holds a pairing record for it.
    bool paired = true;
    bool locked = false;
    bool developer_mode = true;
    bool developer_mode_revealed = false;
    // lockdown's EnableWiFiConnections; nullopt until first set, as on a new phone.
    std::optional<bool> wifi_connections;
    // Also list the phone as a Wi-Fi attachment (device ID 2), ahead of USB.
    bool also_on_wifi = false;
    // DeviceID of every usbmux Connect request.
    std::vector<int> connected_device_ids;
    std::string install_error;
    std::vector<std::string> syslog_lines = {"first line", "second line"};
    std::set<std::string> directories;
    std::map<std::string, crypto::Bytes> files;
    // Snapshot of `files` at the moment installd was asked to install.
    std::map<std::string, crypto::Bytes> staged_at_install;
    std::vector<plist::Value> install_commands;
    std::vector<std::string> installed_bundle_ids = {"com.example.existing"};
    // Client certificates seen on TLS connections.
    std::vector<crypto::Bytes> client_certificates;
    std::vector<std::string> errors;

private:
    void accept_loop();
    void serve(net::Socket socket);
    void serve_lockdown(std::unique_ptr<net::Stream> stream);
    void serve_afc(net::Stream& stream);
    void serve_installation_proxy(net::Stream& stream);
    void serve_syslog(net::Stream& stream);
    void serve_amfi(net::Stream& stream);
    std::unique_ptr<net::Stream> secure(std::unique_ptr<net::Stream> stream);

    std::string udid_ = "00008110-001A2B3C4D5E6F78";
    std::wstring device_key_name_;
    crypto::Bytes device_certificate_;
    crypto::Bytes host_certificate_;
    device::PairRecord pair_record_;

    net::TcpListener listener_ = net::TcpListener::bind_loopback();
    std::atomic<bool> stopping_{false};
    std::vector<std::thread> workers_;
    std::mutex workers_mutex_;
    std::thread accept_thread_;
};

}  // namespace winx::test
