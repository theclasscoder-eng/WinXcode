#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "winx/crypto.hpp"
#include "winx/lockdown.hpp"
#include "winx/plist.hpp"
#include "winx/socket.hpp"

// The device services needed to put an app on a phone and watch it run.
namespace winx::device {

// ---- AFC: file access to the device's media area --------------------------

class AfcError : public std::runtime_error {
public:
    AfcError(const std::string& message, std::uint64_t code)
        : std::runtime_error(message), code_(code) {}
    std::uint64_t code() const noexcept { return code_; }

private:
    std::uint64_t code_;
};

inline constexpr std::uint64_t kAfcObjectNotFound = 8;

class AfcClient {
public:
    explicit AfcClient(std::unique_ptr<net::Stream> stream);

    void make_directory(std::string_view path);
    // Removes a file or a whole directory tree. A path that does not exist is
    // not an error.
    void remove_all(std::string_view path);
    void write_file(std::string_view path, crypto::ByteView data);
    std::vector<std::string> read_directory(std::string_view path);

    using Progress = std::function<void(std::uint64_t sent, std::uint64_t total)>;
    // Copies a local directory tree to `remote`, creating directories as
    // needed. Returns the number of bytes sent.
    std::uint64_t upload_directory(const std::filesystem::path& local, std::string_view remote,
                                   const Progress& progress = {});

private:
    struct Reply {
        std::uint64_t operation = 0;
        crypto::Bytes payload;
    };
    Reply request(std::uint64_t operation, crypto::ByteView header_payload,
                  crypto::ByteView data = {});
    void expect_success(const Reply& reply, std::string_view what);
    std::uint64_t open_for_writing(std::string_view path);
    void write_handle(std::uint64_t handle, crypto::ByteView data);
    void close_handle(std::uint64_t handle);

    std::unique_ptr<net::Stream> stream_;
    std::uint64_t packet_number_ = 0;
};

// ---- installation_proxy ---------------------------------------------------

class InstallError : public std::runtime_error {
public:
    InstallError(const std::string& message, std::string code)
        : std::runtime_error(message), code_(std::move(code)) {}
    // The device's error name, e.g. "ApplicationVerificationFailed".
    const std::string& code() const noexcept { return code_; }

private:
    std::string code_;
};

struct InstallProgress {
    std::string status;
    int percent = -1;  // -1 when the device did not report one
};

struct InstalledApp {
    std::string bundle_id;
    std::string name;
    std::string version;
};

class InstallationProxy {
public:
    using Progress = std::function<void(const InstallProgress&)>;

    explicit InstallationProxy(std::unique_ptr<net::Stream> stream);

    // `package_path` is a path on the device, as uploaded over AFC. The
    // "Developer" package type lets installd take an unpacked .app directory.
    void install(std::string_view package_path, const Progress& progress = {});
    void uninstall(std::string_view bundle_id, const Progress& progress = {});
    std::vector<InstalledApp> list_user_apps();

private:
    void run(const plist::Value& command, const Progress& progress,
             const std::function<void(const plist::Value&)>& on_message = {});
    std::unique_ptr<net::Stream> stream_;
};

// Turns installd's error names into what went wrong and what to do about it.
std::string explain_install_error(std::string_view code, std::string_view description);

// ---- High-level operations ------------------------------------------------

using StageProgress = std::function<void(const std::string& stage, int percent)>;

// Uploads a signed .app bundle to the device's staging area and installs it.
void install_app(DeviceConnection& device, const std::filesystem::path& bundle,
                 const StageProgress& progress = {});
void uninstall_app(DeviceConnection& device, std::string_view bundle_id);
std::vector<InstalledApp> list_apps(DeviceConnection& device);

// iOS 16 and later refuse to launch development-signed apps until Developer
// Mode is on. Returns nullopt when the device predates the setting.
std::optional<bool> developer_mode_enabled(DeviceConnection& device);
// Makes the Developer Mode switch appear in Settings > Privacy & Security.
void reveal_developer_mode(DeviceConnection& device);

// Whether the device also offers itself over Wi-Fi to the hosts it is paired
// with, as Finder's and Apple Devices' "Show this iPhone when on Wi-Fi" does.
// Once on, Apple Mobile Device Service lists it with ConnectionType::Network
// while it is awake on the same network.
bool wifi_connections_enabled(DeviceConnection& device);
void set_wifi_connections(DeviceConnection& device, bool enabled);

// ---- Device log -----------------------------------------------------------

class SyslogStream {
public:
    explicit SyslogStream(std::unique_ptr<net::Stream> stream);
    static SyslogStream open(DeviceConnection& device);

    // The next log line, or nullopt if none arrived within `timeout`. Throws
    // net::ConnectionClosed when the device goes away.
    std::optional<std::string> read_line(std::chrono::milliseconds timeout);

private:
    std::unique_ptr<net::Stream> stream_;
    std::string buffer_;
};

}  // namespace winx::device
