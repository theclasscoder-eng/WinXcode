#include "fake_device.hpp"

#include <array>
#include <chrono>

#include "winx/files.hpp"
#include "winx/lockdown.hpp"
#include "winx/text.hpp"

namespace winx::test {
namespace {

using namespace std::chrono_literals;
using plist::Dict;
using plist::Value;

constexpr std::uint16_t kAfcPort = 5001;
constexpr std::uint16_t kInstallPort = 5002;
constexpr std::uint16_t kSyslogPort = 5003;
constexpr std::uint16_t kAmfiPort = 5004;

crypto::Bytes pem_bytes(std::string_view label, const crypto::Bytes& der) {
    const std::string pem = pem_encode(label, der);
    return crypto::Bytes(pem.begin(), pem.end());
}

std::uint64_t le64(const std::uint8_t* data) {
    std::uint64_t value = 0;
    for (int i = 7; i >= 0; --i) value = (value << 8) | data[i];
    return value;
}

void put_le64(crypto::Bytes& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

void afc_reply(net::Stream& stream, std::uint64_t operation, const crypto::Bytes& payload) {
    crypto::Bytes packet = {'C', 'F', 'A', '6', 'L', 'P', 'A', 'A'};
    put_le64(packet, 40 + payload.size());
    put_le64(packet, 40 + payload.size());
    put_le64(packet, 0);
    put_le64(packet, operation);
    packet.insert(packet.end(), payload.begin(), payload.end());
    stream.send_all(packet);
}

void afc_status(net::Stream& stream, std::uint64_t code) {
    crypto::Bytes payload;
    put_le64(payload, code);
    afc_reply(stream, 1, payload);
}

std::string c_string(const crypto::Bytes& bytes, std::size_t offset) {
    std::string text;
    for (std::size_t i = offset; i < bytes.size() && bytes[i] != 0; ++i) {
        text += static_cast<char>(bytes[i]);
    }
    return text;
}

}  // namespace

FakeDevice::FakeDevice() {
    // Root that issues both the host and the device certificate, as lockdownd
    // pairing does.
    const auth::RsaKey root_key = auth::RsaKey::create();
    const crypto::Bytes root_certificate =
        auth::make_self_signed_certificate(root_key, "CN=Fake Pairing Root");

    const auth::RsaKey host_key = auth::RsaKey::create({}, true);
    host_certificate_ =
        issue_certificate(auth::make_csr_pem(host_key, "host"), root_key, "CN=Fake Host");

    device_key_name_ = to_wide("WinXcode Test Device " + crypto::to_hex(crypto::random_bytes(4)));
    const auth::RsaKey device_key = auth::RsaKey::create(device_key_name_);
    device_certificate_ =
        issue_certificate(auth::make_csr_pem(device_key, "device"), root_key, "CN=Fake Device");

    pair_record_.udid = udid_;
    pair_record_.host_id = "HOST-ID-1234";
    pair_record_.system_buid = "SYSTEM-BUID-5678";
    pair_record_.host_certificate = pem_bytes("CERTIFICATE", host_certificate_);
    const std::string key_pem = export_private_key_pem(host_key);
    pair_record_.host_private_key.assign(key_pem.begin(), key_pem.end());
    pair_record_.root_certificate = pem_bytes("CERTIFICATE", root_certificate);
    pair_record_.device_certificate = pem_bytes("CERTIFICATE", device_certificate_);

    accept_thread_ = std::thread([this] { accept_loop(); });
}

FakeDevice::~FakeDevice() {
    stopping_ = true;
    if (accept_thread_.joinable()) accept_thread_.join();
    for (std::thread& worker : workers_) {
        if (worker.joinable()) worker.join();
    }
    auth::RsaKey::remove(device_key_name_);
    device::remove_private_key(to_wide("WinXcode Pairing " + udid_));
}

void FakeDevice::accept_loop() {
    while (!stopping_) {
        try {
            net::Socket socket = listener_.accept(100ms);
            socket.set_timeouts(5s, 5s);
            const std::lock_guard lock(workers_mutex_);
            workers_.emplace_back([this, socket = std::move(socket)]() mutable {
                try {
                    serve(std::move(socket));
                } catch (const std::exception& error) {
                    // A client hanging up mid-read is how most sessions end.
                    const std::lock_guard guard(mutex);
                    errors.emplace_back(error.what());
                }
            });
        } catch (const net::SocketError&) {
            // accept timed out; check the stop flag again
        }
    }
}

std::unique_ptr<net::Stream> FakeDevice::secure(std::unique_ptr<net::Stream> stream) {
    device::TlsOptions options;
    options.server = true;
    options.identity = device::TlsIdentity{device_certificate_, device_key_name_};
    options.request_client_certificate = true;
    auto tls = device::TlsStream::handshake(std::move(stream), options);
    {
        const std::lock_guard lock(mutex);
        client_certificates.push_back(tls->peer_certificate());
    }
    return tls;
}

void FakeDevice::serve(net::Socket socket) {
    namespace wire = device::usbmux_wire;
    const wire::Packet request = wire::read_packet(socket);
    const std::string type = request.payload.string_at("MessageType").value_or("");
    const auto result = [&](int number) {
        wire::write_packet(socket, Dict{{"MessageType", "Result"}, {"Number", number}},
                           request.header.tag);
    };

    if (type == "ListDevices") {
        const Value reply = Dict{
            {"DeviceList",
             plist::Array{Dict{{"DeviceID", 1},
                               {"MessageType", "Attached"},
                               {"Properties", Dict{{"ConnectionType", "USB"},
                                                   {"DeviceID", 1},
                                                   {"ProductID", 4776},
                                                   {"SerialNumber", "00008110001A2B3C4D5E6F78"}}}}}}};
        wire::write_packet(socket, reply, request.header.tag);
        // The client may follow up with ReadPairRecord on the same connection,
        // which is how it finds the record when there is no file on disk.
        try {
            const wire::Packet next = wire::read_packet(socket);
            bool is_paired = false;
            {
                const std::lock_guard lock(mutex);
                is_paired = paired;
            }
            if (next.payload.string_at("MessageType") == "ReadPairRecord" && is_paired) {
                const Value record = Dict{
                    {"HostID", pair_record_.host_id},
                    {"SystemBUID", pair_record_.system_buid},
                    {"HostCertificate", plist::Data{pair_record_.host_certificate}},
                    {"HostPrivateKey", plist::Data{pair_record_.host_private_key}},
                    {"RootCertificate", plist::Data{pair_record_.root_certificate}},
                    {"DeviceCertificate", plist::Data{pair_record_.device_certificate}}};
                const std::string xml = plist::to_xml(record);
                wire::write_packet(
                    socket, Dict{{"PairRecordData", plist::Data{{xml.begin(), xml.end()}}}},
                    next.header.tag);
            } else {
                wire::write_packet(socket, Dict{{"MessageType", "Result"}, {"Number", 2}},
                                   next.header.tag);
            }
        } catch (const std::exception&) {
        }
        return;
    }
    if (type != "Connect") {
        result(1);
        return;
    }

    const auto network_port = static_cast<std::uint16_t>(request.payload.int_at("PortNumber").value_or(0));
    const auto port = static_cast<std::uint16_t>((network_port << 8) | (network_port >> 8));
    if (port != device::kLockdownPort && (port < kAfcPort || port > kAmfiPort)) {
        result(3);  // connection refused
        return;
    }
    result(0);

    std::unique_ptr<net::Stream> stream = std::make_unique<net::Socket>(std::move(socket));
    if (port == device::kLockdownPort) {
        serve_lockdown(std::move(stream));
        return;
    }
    // Every service was advertised with EnableServiceSSL.
    stream = secure(std::move(stream));
    if (port == kAfcPort) serve_afc(*stream);
    if (port == kInstallPort) serve_installation_proxy(*stream);
    if (port == kSyslogPort) serve_syslog(*stream);
    if (port == kAmfiPort) serve_amfi(*stream);
}

void FakeDevice::serve_lockdown(std::unique_ptr<net::Stream> stream) {
    namespace wire = device::lockdown_wire;
    bool in_session = false;
    for (;;) {
        const Value request = wire::read_message(*stream);
        const std::string kind = request.string_at("Request").value_or("");
        Dict reply{{"Request", kind}};

        if (kind == "QueryType") {
            reply.set("Type", "com.apple.mobile.lockdown");
        } else if (kind == "GetValue") {
            const std::string key = request.string_at("Key").value_or("");
            const std::string domain = request.string_at("Domain").value_or("");
            if (domain == "com.apple.security.mac.amfi" && key == "DeveloperModeStatus") {
                if (!in_session) {
                    reply.set("Error", "GetProhibited");
                } else {
                    const std::lock_guard lock(mutex);
                    reply.set("Value", developer_mode);
                }
            } else if (key == "DeviceName") {
                reply.set("Value", "Fake iPhone");
            } else if (key == "ProductVersion") {
                reply.set("Value", "18.1");
            } else {
                reply.set("Error", "MissingValue");
            }
        } else if (kind == "StartSession") {
            bool is_locked = false;
            {
                const std::lock_guard lock(mutex);
                is_locked = locked;
            }
            if (request.string_at("HostID") != pair_record_.host_id) {
                reply.set("Error", "InvalidHostID");
            } else if (is_locked) {
                reply.set("Error", "PasswordProtected");
            } else {
                reply.set("SessionID", "SESSION-1");
                reply.set("EnableSessionSSL", true);
                wire::write_message(*stream, Value(std::move(reply)));
                stream = secure(std::move(stream));
                in_session = true;
                continue;
            }
        } else if (kind == "StartService") {
            const std::string service = request.string_at("Service").value_or("");
            std::uint16_t port = 0;
            if (service == "com.apple.afc") port = kAfcPort;
            if (service == "com.apple.mobile.installation_proxy") port = kInstallPort;
            if (service == "com.apple.syslog_relay") port = kSyslogPort;
            if (service == "com.apple.amfi.lockdown") port = kAmfiPort;
            if (!in_session) {
                reply.set("Error", "SessionInactive");
            } else if (port == 0) {
                reply.set("Error", "InvalidService");
            } else {
                reply.set("Service", service);
                reply.set("Port", port);
                reply.set("EnableServiceSSL", true);
            }
        } else {
            reply.set("Error", "UnknownRequest");
        }
        wire::write_message(*stream, Value(std::move(reply)));
    }
}

void FakeDevice::serve_afc(net::Stream& stream) {
    std::map<std::uint64_t, std::string> handles;
    std::uint64_t next_handle = 1;
    for (;;) {
        std::array<std::uint8_t, 40> header{};
        stream.recv_exact(header);
        const std::uint64_t entire = le64(header.data() + 8);
        const std::uint64_t this_length = le64(header.data() + 16);
        const std::uint64_t operation = le64(header.data() + 32);
        crypto::Bytes head(static_cast<std::size_t>(this_length - 40));
        stream.recv_exact(head);
        crypto::Bytes data(static_cast<std::size_t>(entire - this_length));
        stream.recv_exact(data);

        const std::lock_guard lock(mutex);
        if (operation == 0x09) {  // make directory
            directories.insert(c_string(head, 0));
            afc_status(stream, 0);
        } else if (operation == 0x22) {  // remove path and contents
            const std::string path = c_string(head, 0);
            const std::string prefix = path + "/";
            std::size_t removed = directories.erase(path) + files.erase(path);
            for (auto it = files.begin(); it != files.end();) {
                if (it->first.starts_with(prefix)) {
                    it = files.erase(it);
                    ++removed;
                } else {
                    ++it;
                }
            }
            for (auto it = directories.begin(); it != directories.end();) {
                if (it->starts_with(prefix)) {
                    it = directories.erase(it);
                    ++removed;
                } else {
                    ++it;
                }
            }
            afc_status(stream, removed == 0 ? 8 : 0);
        } else if (operation == 0x0D) {  // open
            const std::string path = c_string(head, 8);
            const auto slash = path.rfind('/');
            if (slash != std::string::npos && !directories.contains(path.substr(0, slash))) {
                afc_status(stream, 8);  // parent directory missing
                continue;
            }
            files[path].clear();
            handles[next_handle] = path;
            crypto::Bytes payload;
            put_le64(payload, next_handle++);
            afc_reply(stream, 0x0E, payload);
        } else if (operation == 0x10) {  // write
            const auto handle = handles.find(le64(head.data()));
            if (handle == handles.end()) {
                afc_status(stream, 7);
                continue;
            }
            crypto::Bytes& file = files[handle->second];
            file.insert(file.end(), data.begin(), data.end());
            afc_status(stream, 0);
        } else if (operation == 0x14) {  // close
            handles.erase(le64(head.data()));
            afc_status(stream, 0);
        } else if (operation == 0x03) {  // read directory
            const std::string prefix = c_string(head, 0) + "/";
            std::set<std::string> names;
            const auto consider = [&](const std::string& path) {
                if (!path.starts_with(prefix)) return;
                const std::string rest = path.substr(prefix.size());
                names.insert(rest.substr(0, rest.find('/')));
            };
            for (const auto& [path, content] : files) consider(path);
            for (const std::string& path : directories) consider(path);
            crypto::Bytes payload = {'.', 0, '.', '.', 0};
            for (const std::string& name : names) {
                payload.insert(payload.end(), name.begin(), name.end());
                payload.push_back(0);
            }
            afc_reply(stream, 2, payload);
        } else {
            afc_status(stream, 7);
        }
    }
}

void FakeDevice::serve_installation_proxy(net::Stream& stream) {
    namespace wire = device::lockdown_wire;
    for (;;) {
        const Value request = wire::read_message(stream);
        const std::string command = request.string_at("Command").value_or("");
        std::unique_lock lock(mutex);
        install_commands.push_back(request);

        if (command == "Install" || command == "Upgrade") {
            const std::string path = request.string_at("PackagePath").value_or("");
            const auto info = files.find(path + "/Info.plist");
            if (!install_error.empty()) {
                const Value failure = Dict{{"Error", install_error},
                                           {"ErrorDescription", "the fake device said no"}};
                lock.unlock();
                wire::write_message(stream, failure);
                continue;
            }
            if (!directories.contains(path) || info == files.end()) {
                lock.unlock();
                wire::write_message(stream, Dict{{"Error", "PackageInspectionFailed"}});
                continue;
            }
            staged_at_install = files;
            const Value plist = plist::parse(info->second);
            installed_bundle_ids.push_back(plist.string_at("CFBundleIdentifier").value_or("?"));
            lock.unlock();
            wire::write_message(stream, Dict{{"Status", "CreatingStagingDirectory"},
                                             {"PercentComplete", 5}});
            wire::write_message(stream, Dict{{"Status", "VerifyingApplication"},
                                             {"PercentComplete", 40}});
            wire::write_message(stream, Dict{{"Status", "InstallingApplication"},
                                             {"PercentComplete", 80}});
            wire::write_message(stream, Dict{{"Status", "Complete"}});
        } else if (command == "Uninstall") {
            const std::string id = request.string_at("ApplicationIdentifier").value_or("");
            std::erase(installed_bundle_ids, id);
            lock.unlock();
            wire::write_message(stream, Dict{{"Status", "RemovingApplication"},
                                             {"PercentComplete", 50}});
            wire::write_message(stream, Dict{{"Status", "Complete"}});
        } else if (command == "Browse") {
            plist::Array list;
            for (const std::string& id : installed_bundle_ids) {
                list.emplace_back(Dict{{"CFBundleIdentifier", id},
                                       {"CFBundleDisplayName", "App " + id},
                                       {"CFBundleShortVersionString", "1.0"}});
            }
            lock.unlock();
            wire::write_message(stream, Dict{{"Status", "BrowsingApplications"},
                                             {"CurrentList", std::move(list)}});
            wire::write_message(stream, Dict{{"Status", "Complete"}});
        } else {
            lock.unlock();
            wire::write_message(stream, Dict{{"Error", "UnknownCommand"}});
        }
    }
}

void FakeDevice::serve_syslog(net::Stream& stream) {
    std::string text;
    {
        const std::lock_guard lock(mutex);
        for (const std::string& line : syslog_lines) {
            text += line;
            text += '\n';
            text += '\0';
        }
    }
    stream.send_all(crypto::as_bytes(text));
    // Hold the connection open until the client goes away.
    std::array<std::uint8_t, 1> byte{};
    stream.recv_some(byte);
}

void FakeDevice::serve_amfi(net::Stream& stream) {
    namespace wire = device::lockdown_wire;
    const Value request = wire::read_message(stream);
    {
        const std::lock_guard lock(mutex);
        developer_mode_revealed = request.int_at("action") == 0;
    }
    wire::write_message(stream, Dict{{"success", true}});
}

}  // namespace winx::test
