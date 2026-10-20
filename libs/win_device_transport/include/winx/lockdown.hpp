#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include "winx/pair_record.hpp"
#include "winx/plist.hpp"
#include "winx/socket.hpp"
#include "winx/tls.hpp"
#include "winx/usbmux.hpp"

// Client for lockdownd, the device-side service on TCP port 62078.
namespace winx::device {

inline constexpr std::uint16_t kLockdownPort = 62078;

class LockdownError : public std::runtime_error {
public:
    explicit LockdownError(const std::string& message, std::string code = {})
        : std::runtime_error(message), code_(std::move(code)) {}
    // lockdownd's own error string, e.g. "PasswordProtected".
    const std::string& code() const noexcept { return code_; }

private:
    std::string code_;
};

// Wire format: a 4-byte big-endian length followed by a plist. The same
// framing is used by the plist-based services lockdownd starts.
namespace lockdown_wire {

void write_message(net::Stream& stream, const plist::Value& message);
plist::Value read_message(net::Stream& stream);

}  // namespace lockdown_wire

// TLS settings for talking to a paired device: this PC's host certificate as
// the client identity, and the device's certificate (or anything signed by
// the pairing root) as the only acceptable peer. Imports the host key into
// the user's CNG key store under a name derived from the UDID.
TlsOptions pairing_tls_options(const PairRecord& record);

class LockdownClient {
public:
    // Takes a tunnel obtained from UsbmuxClient::connect.
    explicit LockdownClient(std::unique_ptr<net::Stream> stream, std::string label = "winx");

    static LockdownClient connect(const UsbmuxEndpoint& endpoint, std::uint32_t device_id);

    // "com.apple.mobile.lockdown" for a healthy lockdownd.
    std::string query_type();
    // Throws LockdownError if the device refuses the key.
    plist::Value get_value(std::string_view key, std::string_view domain = {});
    // Requires a session.
    void set_value(std::string_view key, const plist::Value& value, std::string_view domain = {});

    // Authenticates as the paired host. When the device asks for it, which
    // every current iOS version does, the connection continues over TLS.
    void start_session(const PairRecord& record);
    bool in_session() const noexcept { return !session_id_.empty(); }

    struct Service {
        std::uint16_t port = 0;
        bool tls = false;
    };
    // Requires a session.
    Service start_service(std::string_view name);

private:
    plist::Value request(plist::Dict message);

    std::unique_ptr<net::Stream> stream_;
    std::string label_;
    std::string session_id_;
};

// Fields lockdownd discloses without a paired session. Any it withholds are
// left empty.
struct DeviceInfo {
    std::string name;
    std::string product_version;
    std::string product_type;
    std::string device_class;
    std::string build_version;
};

DeviceInfo query_device_info(const UsbmuxEndpoint& endpoint, std::uint32_t device_id);

// A paired, authenticated relationship with one attached device. Keeps a
// lockdown session open and hands out connections to the device's services.
class DeviceConnection {
public:
    DeviceConnection(UsbmuxEndpoint endpoint, UsbmuxDevice device, PairRecord record);

    // Picks the device with the given UDID, or the only attached device when
    // `udid` is empty, and loads its pairing record. A phone attached both by
    // USB and over Wi-Fi is reached through USB. Throws LockdownError with
    // an actionable message when there is no such device or it is not paired.
    static DeviceConnection open(const UsbmuxEndpoint& endpoint, std::string_view udid = {});

    const UsbmuxDevice& device() const noexcept { return device_; }

    plist::Value get_value(std::string_view key, std::string_view domain = {});
    void set_value(std::string_view key, const plist::Value& value, std::string_view domain = {});
    // A ready-to-use stream to the named service, already upgraded to TLS
    // when the device requires it.
    std::unique_ptr<net::Stream> start_service(std::string_view name);

private:
    LockdownClient& lockdown();

    UsbmuxEndpoint endpoint_;
    UsbmuxDevice device_;
    PairRecord record_;
    std::optional<TlsOptions> tls_;
    std::optional<LockdownClient> lockdown_;
};

}  // namespace winx::device
