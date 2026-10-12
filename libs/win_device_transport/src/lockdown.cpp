#include "winx/lockdown.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <format>
#include <vector>

#include "winx/text.hpp"

namespace winx::device {
namespace {

constexpr std::uint32_t kMaxMessageSize = 64u * 1024 * 1024;
constexpr auto kIoTimeout = std::chrono::seconds(30);

std::string_view as_text(const std::vector<std::uint8_t>& bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

// What the user can do about lockdownd's terse error codes.
std::string explain(std::string_view code) {
    if (code == "PasswordProtected") {
        return "the device is locked; unlock it and try again";
    }
    if (code == "InvalidHostID" || code == "InvalidPairRecord") {
        return "the device no longer trusts this PC; reconnect it, tap Trust, and open Apple "
               "Devices or iTunes once so a new pairing record is written";
    }
    if (code == "UserDeniedPairing") return "pairing was declined on the device";
    if (code == "PairingDialogResponsePending") {
        return "the device is waiting for you to tap Trust";
    }
    if (code == "InvalidService") return "the device does not offer this service";
    if (code == "SessionInactive") return "the lockdown session has ended";
    return std::string(code);
}

std::unique_ptr<net::Stream> open_tunnel(const UsbmuxEndpoint& endpoint, std::uint32_t device_id,
                                         std::uint16_t port) {
    auto socket =
        std::make_unique<net::Socket>(UsbmuxClient(endpoint).connect(device_id, port));
    socket->set_timeouts(kIoTimeout, kIoTimeout);
    return socket;
}

}  // namespace

namespace lockdown_wire {

void write_message(net::Stream& stream, const plist::Value& message) {
    const std::string xml = plist::to_xml(message);
    const auto length = static_cast<std::uint32_t>(xml.size());
    std::vector<std::uint8_t> frame(4 + xml.size());
    frame[0] = static_cast<std::uint8_t>(length >> 24);
    frame[1] = static_cast<std::uint8_t>(length >> 16);
    frame[2] = static_cast<std::uint8_t>(length >> 8);
    frame[3] = static_cast<std::uint8_t>(length);
    std::copy(xml.begin(), xml.end(), frame.begin() + 4);
    stream.send_all(frame);
}

plist::Value read_message(net::Stream& stream) {
    std::array<std::uint8_t, 4> prefix{};
    stream.recv_exact(prefix);
    const std::uint32_t length = (static_cast<std::uint32_t>(prefix[0]) << 24) |
                                 (static_cast<std::uint32_t>(prefix[1]) << 16) |
                                 (static_cast<std::uint32_t>(prefix[2]) << 8) |
                                 static_cast<std::uint32_t>(prefix[3]);
    if (length == 0 || length > kMaxMessageSize) {
        throw LockdownError(std::format("the device sent a message with invalid length {}", length));
    }
    std::vector<std::uint8_t> body(length);
    stream.recv_exact(body);
    return plist::parse(body);
}

}  // namespace lockdown_wire

TlsOptions pairing_tls_options(const PairRecord& record) {
    if (!record.usable_for_session()) {
        throw LockdownError("the pairing record is incomplete; reconnect the device and tap Trust");
    }
    TlsOptions options;
    TlsIdentity identity;
    identity.certificate = certificate_from_pem(as_text(record.host_certificate));
    identity.key_name = to_wide("WinXcode Pairing " + record.udid);
    import_rsa_private_key(as_text(record.host_private_key), identity.key_name);
    options.identity = std::move(identity);
    if (!record.device_certificate.empty()) {
        options.accepted_peers.push_back(certificate_from_pem(as_text(record.device_certificate)));
    }
    options.accepted_issuers.push_back(certificate_from_pem(as_text(record.root_certificate)));
    return options;
}

LockdownClient::LockdownClient(std::unique_ptr<net::Stream> stream, std::string label)
    : stream_(std::move(stream)), label_(std::move(label)) {}

LockdownClient LockdownClient::connect(const UsbmuxEndpoint& endpoint, std::uint32_t device_id) {
    return LockdownClient(open_tunnel(endpoint, device_id, kLockdownPort));
}

plist::Value LockdownClient::request(plist::Dict message) {
    message.set("Label", label_);
    lockdown_wire::write_message(*stream_, plist::Value(std::move(message)));
    plist::Value reply = lockdown_wire::read_message(*stream_);
    if (const auto error = reply.string_at("Error")) {
        throw LockdownError(std::format("lockdown: {}", explain(*error)), *error);
    }
    return reply;
}

std::string LockdownClient::query_type() {
    return request({{"Request", "QueryType"}}).string_at("Type").value_or("");
}

plist::Value LockdownClient::get_value(std::string_view key, std::string_view domain) {
    plist::Dict message{{"Request", "GetValue"}};
    if (!key.empty()) message.set("Key", std::string(key));
    if (!domain.empty()) message.set("Domain", std::string(domain));
    const plist::Value reply = request(std::move(message));
    const plist::Value* value = reply.find("Value");
    return value ? *value : plist::Value{};
}

void LockdownClient::start_session(const PairRecord& record) {
    if (in_session()) return;
    // Prepare the TLS identity first so a bad pairing record fails before the
    // device has been told a session is starting.
    const TlsOptions tls = pairing_tls_options(record);
    const plist::Value reply = request({{"Request", "StartSession"},
                                        {"HostID", record.host_id},
                                        {"SystemBUID", record.system_buid}});
    session_id_ = reply.string_at("SessionID").value_or("");
    if (session_id_.empty()) throw LockdownError("the device did not start a session");
    if (reply.bool_at("EnableSessionSSL").value_or(false)) {
        try {
            stream_ = TlsStream::handshake(std::move(stream_), tls);
        } catch (const TlsError& error) {
            session_id_.clear();
            throw LockdownError(std::string("could not secure the lockdown session: ") +
                                error.what());
        }
    }
}

LockdownClient::Service LockdownClient::start_service(std::string_view name) {
    if (!in_session()) throw LockdownError("a lockdown session is required to start a service");
    const plist::Value reply =
        request({{"Request", "StartService"}, {"Service", std::string(name)}});
    Service service;
    service.port = static_cast<std::uint16_t>(reply.int_at("Port").value_or(0));
    service.tls = reply.bool_at("EnableServiceSSL").value_or(false);
    if (service.port == 0) {
        throw LockdownError(std::format("the device did not start {}", name));
    }
    return service;
}

DeviceInfo query_device_info(const UsbmuxEndpoint& endpoint, std::uint32_t device_id) {
    auto tunnel = std::make_unique<net::Socket>(
        UsbmuxClient(endpoint).connect(device_id, kLockdownPort));
    tunnel->set_timeouts(std::chrono::seconds(5), std::chrono::seconds(5));
    LockdownClient client(std::move(tunnel));
    const std::string type = client.query_type();
    if (type != "com.apple.mobile.lockdown") {
        throw LockdownError(std::format("unexpected lockdown service type '{}'", type));
    }

    const auto read = [&client](std::string_view key) -> std::string {
        try {
            const plist::Value value = client.get_value(key);
            if (const auto* text = value.get_if<std::string>()) return *text;
        } catch (const LockdownError&) {
            // The device withholds this key from unpaired hosts.
        }
        return {};
    };

    DeviceInfo info;
    info.name = read("DeviceName");
    info.product_version = read("ProductVersion");
    info.product_type = read("ProductType");
    info.device_class = read("DeviceClass");
    info.build_version = read("BuildVersion");
    return info;
}

DeviceConnection::DeviceConnection(UsbmuxEndpoint endpoint, UsbmuxDevice device, PairRecord record)
    : endpoint_(std::move(endpoint)), device_(std::move(device)), record_(std::move(record)) {}

DeviceConnection DeviceConnection::open(const UsbmuxEndpoint& endpoint, std::string_view udid) {
    UsbmuxClient client(endpoint);
    std::vector<UsbmuxDevice> devices = client.list_devices();
    if (devices.empty()) throw LockdownError("no device is attached");

    const UsbmuxDevice* chosen = nullptr;
    if (udid.empty()) {
        // The same phone can appear once per transport; prefer USB.
        std::stable_sort(devices.begin(), devices.end(), [](const auto& a, const auto& b) {
            return a.connection == ConnectionType::Usb && b.connection != ConnectionType::Usb;
        });
        const bool one_device = std::all_of(devices.begin(), devices.end(), [&](const auto& d) {
            return d.udid == devices.front().udid;
        });
        if (!one_device) {
            throw LockdownError("several devices are attached; choose one with --udid");
        }
        chosen = &devices.front();
    } else {
        for (const UsbmuxDevice& candidate : devices) {
            if (candidate.udid == udid) {
                chosen = &candidate;
                break;
            }
        }
        if (!chosen) throw LockdownError(std::format("device {} is not attached", udid));
    }

    std::optional<PairRecord> record;
    try {
        record = load_pair_record(chosen->udid);
    } catch (const std::exception&) {
        // Fall through to asking the service for it.
    }
    if (!record) {
        if (const auto from_service = client.read_pair_record(chosen->udid)) {
            record = parse_pair_record(*from_service, chosen->udid);
        }
    }
    if (!record) {
        throw LockdownError(
            "this PC is not paired with the device. Unlock it, tap Trust, and open Apple "
            "Devices or iTunes once so the pairing record is created",
            "NotPaired");
    }
    return DeviceConnection(endpoint, *chosen, std::move(*record));
}

LockdownClient& DeviceConnection::lockdown() {
    if (!lockdown_) {
        LockdownClient client = LockdownClient::connect(endpoint_, device_.device_id);
        client.start_session(record_);
        lockdown_.emplace(std::move(client));
    }
    return *lockdown_;
}

plist::Value DeviceConnection::get_value(std::string_view key, std::string_view domain) {
    return lockdown().get_value(key, domain);
}

std::unique_ptr<net::Stream> DeviceConnection::start_service(std::string_view name) {
    const LockdownClient::Service service = lockdown().start_service(name);
    std::unique_ptr<net::Stream> stream = open_tunnel(endpoint_, device_.device_id, service.port);
    if (!service.tls) return stream;
    if (!tls_) tls_ = pairing_tls_options(record_);
    try {
        return TlsStream::handshake(std::move(stream), *tls_);
    } catch (const TlsError& error) {
        throw LockdownError(std::format("could not secure the connection to {}: {}", name,
                                        error.what()));
    }
}

}  // namespace winx::device
