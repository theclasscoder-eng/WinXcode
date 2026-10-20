#include "winx/device_services.hpp"

#include <algorithm>
#include <array>
#include <format>
#include <fstream>

#include "winx/text.hpp"

namespace winx::device {
namespace {

namespace fs = std::filesystem;

constexpr std::array<std::uint8_t, 8> kAfcMagic = {'C', 'F', 'A', '6', 'L', 'P', 'A', 'A'};
constexpr std::size_t kAfcHeaderSize = 40;
constexpr std::uint64_t kAfcMaxPacket = 64ull * 1024 * 1024;
constexpr std::size_t kUploadChunk = 1024 * 1024;

constexpr std::uint64_t kAfcStatus = 0x01;
constexpr std::uint64_t kAfcData = 0x02;
constexpr std::uint64_t kAfcReadDirectory = 0x03;
constexpr std::uint64_t kAfcMakeDirectory = 0x09;
constexpr std::uint64_t kAfcFileOpen = 0x0D;
constexpr std::uint64_t kAfcFileOpenResult = 0x0E;
constexpr std::uint64_t kAfcFileWrite = 0x10;
constexpr std::uint64_t kAfcFileClose = 0x14;
constexpr std::uint64_t kAfcRemovePathAndContents = 0x22;
constexpr std::uint64_t kAfcModeWriteOnly = 3;  // create or truncate

void put_le64(crypto::Bytes& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

std::uint64_t get_le64(crypto::ByteView data, std::size_t offset) {
    std::uint64_t value = 0;
    for (int i = 7; i >= 0; --i) value = (value << 8) | data[offset + static_cast<std::size_t>(i)];
    return value;
}

crypto::Bytes path_payload(std::string_view path) {
    crypto::Bytes payload(path.begin(), path.end());
    payload.push_back(0);
    return payload;
}

std::string afc_status_text(std::uint64_t code) {
    switch (code) {
        case 0: return "success";
        case 7: return "invalid argument";
        case 8: return "no such file or directory";
        case 9: return "the path is a directory";
        case 10: return "permission denied";
        case 16: return "the object already exists";
        case 18: return "no space left on the device";
        case 19: return "operation would block";
        case 21: return "operation interrupted";
        default: return std::format("AFC error {}", code);
    }
}

}  // namespace

AfcClient::AfcClient(std::unique_ptr<net::Stream> stream) : stream_(std::move(stream)) {}

AfcClient::Reply AfcClient::request(std::uint64_t operation, crypto::ByteView header_payload,
                                    crypto::ByteView data) {
    crypto::Bytes packet;
    packet.reserve(kAfcHeaderSize + header_payload.size() + data.size());
    packet.insert(packet.end(), kAfcMagic.begin(), kAfcMagic.end());
    const std::uint64_t this_length = kAfcHeaderSize + header_payload.size();
    put_le64(packet, this_length + data.size());
    put_le64(packet, this_length);
    put_le64(packet, packet_number_++);
    put_le64(packet, operation);
    packet.insert(packet.end(), header_payload.begin(), header_payload.end());
    packet.insert(packet.end(), data.begin(), data.end());
    stream_->send_all(packet);

    std::array<std::uint8_t, kAfcHeaderSize> header{};
    stream_->recv_exact(header);
    if (!std::equal(kAfcMagic.begin(), kAfcMagic.end(), header.begin())) {
        throw AfcError("the device sent a malformed AFC reply", 0);
    }
    const std::uint64_t entire = get_le64(header, 8);
    if (entire < kAfcHeaderSize || entire > kAfcMaxPacket) {
        throw AfcError("the device sent an AFC reply with an invalid length", 0);
    }
    Reply reply;
    reply.operation = get_le64(header, 32);
    reply.payload.resize(static_cast<std::size_t>(entire - kAfcHeaderSize));
    stream_->recv_exact(reply.payload);
    return reply;
}

void AfcClient::expect_success(const Reply& reply, std::string_view what) {
    if (reply.operation != kAfcStatus || reply.payload.size() < 8) {
        throw AfcError(std::format("unexpected AFC reply while {}", what), 0);
    }
    const std::uint64_t code = get_le64(reply.payload, 0);
    if (code != 0) {
        throw AfcError(std::format("{} failed: {}", what, afc_status_text(code)), code);
    }
}

void AfcClient::make_directory(std::string_view path) {
    expect_success(request(kAfcMakeDirectory, path_payload(path)),
                   std::format("creating {}", path));
}

void AfcClient::remove_all(std::string_view path) {
    try {
        expect_success(request(kAfcRemovePathAndContents, path_payload(path)),
                       std::format("removing {}", path));
    } catch (const AfcError& error) {
        if (error.code() != kAfcObjectNotFound) throw;
    }
}

std::vector<std::string> AfcClient::read_directory(std::string_view path) {
    const Reply reply = request(kAfcReadDirectory, path_payload(path));
    if (reply.operation == kAfcStatus) expect_success(reply, std::format("listing {}", path));
    if (reply.operation != kAfcData) throw AfcError("unexpected AFC reply while listing", 0);
    std::vector<std::string> names;
    std::string current;
    for (const std::uint8_t byte : reply.payload) {
        if (byte != 0) {
            current += static_cast<char>(byte);
            continue;
        }
        if (!current.empty() && current != "." && current != "..") names.push_back(current);
        current.clear();
    }
    return names;
}

std::uint64_t AfcClient::open_for_writing(std::string_view path) {
    crypto::Bytes payload;
    put_le64(payload, kAfcModeWriteOnly);
    payload.insert(payload.end(), path.begin(), path.end());
    payload.push_back(0);
    const Reply reply = request(kAfcFileOpen, payload);
    if (reply.operation == kAfcStatus) expect_success(reply, std::format("opening {}", path));
    if (reply.operation != kAfcFileOpenResult || reply.payload.size() < 8) {
        throw AfcError(std::format("unexpected AFC reply while opening {}", path), 0);
    }
    return get_le64(reply.payload, 0);
}

void AfcClient::write_handle(std::uint64_t handle, crypto::ByteView data) {
    crypto::Bytes payload;
    put_le64(payload, handle);
    expect_success(request(kAfcFileWrite, payload, data), "writing to the device");
}

void AfcClient::close_handle(std::uint64_t handle) {
    crypto::Bytes payload;
    put_le64(payload, handle);
    expect_success(request(kAfcFileClose, payload), "closing a file on the device");
}

void AfcClient::write_file(std::string_view path, crypto::ByteView data) {
    const std::uint64_t handle = open_for_writing(path);
    while (!data.empty()) {
        const std::size_t chunk = std::min(data.size(), kUploadChunk);
        write_handle(handle, data.subspan(0, chunk));
        data = data.subspan(chunk);
    }
    close_handle(handle);
}

std::uint64_t AfcClient::upload_directory(const fs::path& local, std::string_view remote,
                                          const Progress& progress) {
    if (!fs::is_directory(local)) {
        throw AfcError("not a directory: " + to_utf8(local.wstring()), 0);
    }
    struct Item {
        fs::path path;
        std::string remote;
        bool directory = false;
        std::uint64_t size = 0;
    };
    std::vector<Item> items;
    std::uint64_t total = 0;
    for (const auto& entry : fs::recursive_directory_iterator(local)) {
        Item item;
        item.path = entry.path();
        item.remote = std::string(remote) + "/" +
                      to_utf8(fs::relative(entry.path(), local).generic_wstring());
        item.directory = entry.is_directory();
        if (entry.is_regular_file()) {
            item.size = entry.file_size();
            total += item.size;
        } else if (!item.directory) {
            continue;  // links and other special files are not transferred
        }
        items.push_back(std::move(item));
    }
    // Parents sort before their children.
    std::sort(items.begin(), items.end(),
              [](const Item& a, const Item& b) { return a.remote < b.remote; });

    make_directory(remote);
    std::uint64_t sent = 0;
    std::vector<std::uint8_t> buffer(kUploadChunk);
    for (const Item& item : items) {
        if (item.directory) {
            make_directory(item.remote);
            continue;
        }
        std::ifstream in(item.path, std::ios::binary);
        if (!in) throw AfcError("cannot read " + to_utf8(item.path.wstring()), 0);
        const std::uint64_t handle = open_for_writing(item.remote);
        for (;;) {
            in.read(reinterpret_cast<char*>(buffer.data()),
                    static_cast<std::streamsize>(buffer.size()));
            const auto count = static_cast<std::size_t>(in.gcount());
            if (count == 0) break;
            write_handle(handle, crypto::ByteView(buffer.data(), count));
            sent += count;
            if (progress) progress(sent, total);
        }
        close_handle(handle);
    }
    if (progress) progress(sent, total);
    return sent;
}

InstallationProxy::InstallationProxy(std::unique_ptr<net::Stream> stream)
    : stream_(std::move(stream)) {}

std::string explain_install_error(std::string_view code, std::string_view description) {
    std::string hint;
    if (code == "ApplicationVerificationFailed") {
        hint = "The device rejected the code signature or provisioning profile. Check that the "
               "profile includes this device and the signing certificate, that it has not "
               "expired, and that the bundle identifier matches the profile.";
    } else if (code == "MismatchedApplicationIdentifierEntitlement") {
        hint = "An app with this bundle identifier signed by a different team is already "
               "installed. Uninstall it first.";
    } else if (code == "DeviceOSVersionTooLow") {
        hint = "The app's MinimumOSVersion is newer than the iOS version on the device.";
    } else if (code == "IncorrectArchitecture") {
        hint = "The executable was not built for this device's CPU (arm64).";
    } else if (code == "PackageInspectionFailed" || code == "BundleValidationFailed") {
        hint = "The bundle is malformed: check Info.plist, CFBundleExecutable and that the "
               "executable exists.";
    } else if (code == "InstallProhibited") {
        hint = "App installation is disabled on the device by Screen Time or a management "
               "profile.";
    } else if (code == "APIInternalError" || code == "InternalError") {
        hint = "installd failed internally; the device log (`winx device log`) usually says why.";
    } else if (code == "ApplicationAlreadyInstalled") {
        hint = "The same build is already installed.";
    }
    std::string message = std::format("installation failed: {}", code);
    if (!description.empty()) message += std::format(" ({})", description);
    if (!hint.empty()) message += "\n" + hint;
    return message;
}

void InstallationProxy::run(const plist::Value& command, const Progress& progress,
                            const std::function<void(const plist::Value&)>& on_message) {
    lockdown_wire::write_message(*stream_, command);
    for (;;) {
        const plist::Value message = lockdown_wire::read_message(*stream_);
        if (const auto error = message.string_at("Error")) {
            const std::string description = message.string_at("ErrorDescription").value_or("");
            throw InstallError(explain_install_error(*error, description), *error);
        }
        if (on_message) on_message(message);
        const std::string status = message.string_at("Status").value_or("");
        if (progress && !status.empty()) {
            InstallProgress update;
            update.status = status;
            update.percent = static_cast<int>(message.int_at("PercentComplete").value_or(-1));
            progress(update);
        }
        if (status == "Complete") return;
    }
}

void InstallationProxy::install(std::string_view package_path, const Progress& progress) {
    run(plist::Dict{{"Command", "Install"},
                    {"PackagePath", std::string(package_path)},
                    {"ClientOptions", plist::Dict{{"PackageType", "Developer"}}}},
        progress);
}

void InstallationProxy::uninstall(std::string_view bundle_id, const Progress& progress) {
    run(plist::Dict{{"Command", "Uninstall"}, {"ApplicationIdentifier", std::string(bundle_id)}},
        progress);
}

std::vector<InstalledApp> InstallationProxy::list_user_apps() {
    std::vector<InstalledApp> apps;
    const plist::Value command = plist::Dict{
        {"Command", "Browse"},
        {"ClientOptions",
         plist::Dict{{"ApplicationType", "User"},
                     {"ReturnAttributes",
                      plist::Array{"CFBundleIdentifier", "CFBundleDisplayName", "CFBundleName",
                                   "CFBundleShortVersionString"}}}}};
    run(command, {}, [&](const plist::Value& message) {
        const plist::Value* list = message.find("CurrentList");
        if (!list || !list->is<plist::Array>()) return;
        for (const plist::Value& entry : list->as_array()) {
            InstalledApp app;
            app.bundle_id = entry.string_at("CFBundleIdentifier").value_or("");
            app.name = entry.string_at("CFBundleDisplayName")
                           .value_or(entry.string_at("CFBundleName").value_or(""));
            app.version = entry.string_at("CFBundleShortVersionString").value_or("");
            if (!app.bundle_id.empty()) apps.push_back(std::move(app));
        }
    });
    std::sort(apps.begin(), apps.end(),
              [](const InstalledApp& a, const InstalledApp& b) { return a.bundle_id < b.bundle_id; });
    return apps;
}

void install_app(DeviceConnection& device, const fs::path& bundle, const StageProgress& progress) {
    if (!fs::is_directory(bundle) || !fs::is_regular_file(bundle / L"Info.plist")) {
        throw InstallError("not an app bundle: " + to_utf8(bundle.wstring()), "NotABundle");
    }
    const std::string staging = "PublicStaging";
    const std::string remote = staging + "/" + to_utf8(bundle.filename().wstring());

    AfcClient afc(device.start_service("com.apple.afc"));
    afc.make_directory(staging);
    afc.remove_all(remote);
    int last_percent = -1;
    afc.upload_directory(bundle, remote, [&](std::uint64_t sent, std::uint64_t total) {
        const int percent = total == 0 ? 100 : static_cast<int>(sent * 100 / total);
        if (progress && percent != last_percent) progress("Uploading", percent);
        last_percent = percent;
    });

    InstallationProxy proxy(device.start_service("com.apple.mobile.installation_proxy"));
    try {
        proxy.install(remote, [&](const InstallProgress& update) {
            if (progress) progress(update.status, update.percent);
        });
    } catch (...) {
        try {
            afc.remove_all(remote);
        } catch (const std::exception&) {
        }
        throw;
    }
    // installd normally consumes the staged copy; clear anything it left.
    try {
        afc.remove_all(remote);
    } catch (const std::exception&) {
    }
}

void uninstall_app(DeviceConnection& device, std::string_view bundle_id) {
    InstallationProxy proxy(device.start_service("com.apple.mobile.installation_proxy"));
    proxy.uninstall(bundle_id);
}

std::vector<InstalledApp> list_apps(DeviceConnection& device) {
    InstallationProxy proxy(device.start_service("com.apple.mobile.installation_proxy"));
    return proxy.list_user_apps();
}

std::optional<bool> developer_mode_enabled(DeviceConnection& device) {
    try {
        const plist::Value value =
            device.get_value("DeveloperModeStatus", "com.apple.security.mac.amfi");
        if (const auto* flag = value.get_if<bool>()) return *flag;
    } catch (const LockdownError&) {
        // Before iOS 16 the domain does not exist.
    }
    return std::nullopt;
}

void reveal_developer_mode(DeviceConnection& device) {
    const std::unique_ptr<net::Stream> stream = device.start_service("com.apple.amfi.lockdown");
    lockdown_wire::write_message(*stream, plist::Dict{{"action", 0}});
    const plist::Value reply = lockdown_wire::read_message(*stream);
    if (const auto error = reply.string_at("Error")) {
        throw LockdownError("could not reveal Developer Mode: " + *error, *error);
    }
}

bool wifi_connections_enabled(DeviceConnection& device) {
    try {
        const plist::Value value =
            device.get_value("EnableWiFiConnections", "com.apple.mobile.wireless_lockdown");
        if (const auto* flag = value.get_if<bool>()) return *flag;
    } catch (const LockdownError& error) {
        // A device that was never switched has no value yet.
        if (error.code() != "MissingValue") throw;
    }
    return false;
}

void set_wifi_connections(DeviceConnection& device, bool enabled) {
    device.set_value("EnableWiFiConnections", enabled, "com.apple.mobile.wireless_lockdown");
}

SyslogStream::SyslogStream(std::unique_ptr<net::Stream> stream) : stream_(std::move(stream)) {}

SyslogStream SyslogStream::open(DeviceConnection& device) {
    return SyslogStream(device.start_service("com.apple.syslog_relay"));
}

std::optional<std::string> SyslogStream::read_line(std::chrono::milliseconds timeout) {
    for (;;) {
        // Lines end in a newline; records are additionally separated by NUL.
        const auto end = buffer_.find_first_of(std::string_view("\n\0", 2));
        if (end != std::string::npos) {
            std::string line = buffer_.substr(0, end);
            buffer_.erase(0, end + 1);
            while (!line.empty() && (line.back() == '\r' || line.back() == '\0')) line.pop_back();
            if (line.empty()) continue;
            return line;
        }
        if (!stream_->wait_readable(timeout)) return std::nullopt;
        std::array<std::uint8_t, 8192> chunk{};
        const std::size_t received = stream_->recv_some(chunk);
        if (received == 0) throw net::ConnectionClosed();
        buffer_.append(reinterpret_cast<const char*>(chunk.data()), received);
    }
}

}  // namespace winx::device
