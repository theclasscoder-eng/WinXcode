#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "winx/plist.hpp"
#include "winx/socket.hpp"

// Client for the usbmux protocol spoken by Apple Mobile Device Service, which
// listens on TCP 127.0.0.1:27015 on Windows.
namespace winx::device {

struct UsbmuxEndpoint {
    std::string host = "127.0.0.1";
    std::uint16_t port = 27015;
};

enum class ConnectionType { Unknown, Usb, Network };

struct UsbmuxDevice {
    // Handle assigned by usbmux for this attachment; changes on every replug.
    std::uint32_t device_id = 0;
    std::string udid;
    ConnectionType connection = ConnectionType::Unknown;
    std::uint32_t product_id = 0;
    std::uint32_t location_id = 0;
};

struct DeviceEvent {
    enum class Kind { Attached, Detached, Paired };
    Kind kind = Kind::Attached;
    std::uint32_t device_id = 0;
    // Set for Attached only.
    std::optional<UsbmuxDevice> device;
};

class UsbmuxError : public std::runtime_error {
public:
    UsbmuxError(const std::string& message, int code)
        : std::runtime_error(message), code_(code) {}
    // usbmux result number (2 = bad device, 3 = connection refused, 6 = bad
    // version), or -1 for a malformed reply.
    int code() const noexcept { return code_; }

private:
    int code_;
};

// Wire format: a 16-byte little-endian header followed by an XML plist.
namespace usbmux_wire {

inline constexpr std::size_t kHeaderSize = 16;
inline constexpr std::uint32_t kVersionPlist = 1;
inline constexpr std::uint32_t kMessagePlist = 8;

struct Header {
    std::uint32_t length = 0;  // header + payload
    std::uint32_t version = 0;
    std::uint32_t message = 0;
    std::uint32_t tag = 0;
};

struct Packet {
    Header header;
    plist::Value payload;
};

std::vector<std::uint8_t> encode_packet(const plist::Value& payload, std::uint32_t tag);
Header decode_header(std::span<const std::uint8_t, kHeaderSize> bytes);
void write_packet(net::Socket& socket, const plist::Value& payload, std::uint32_t tag);
Packet read_packet(net::Socket& socket);

}  // namespace usbmux_wire

// One request/response connection. usbmux allows a single mode per
// connection, so Listen and Connect each need a client of their own.
class UsbmuxClient {
public:
    explicit UsbmuxClient(const UsbmuxEndpoint& endpoint = {});

    std::vector<UsbmuxDevice> list_devices();
    // System BUID of this host, as stored by Apple Mobile Device Service.
    std::string read_buid();
    // Pairing record held by the service, or nullopt if the device is unpaired.
    std::optional<plist::Value> read_pair_record(std::string_view udid);

    // Opens a tunnel to a TCP port on the device. On success the connection
    // stops speaking usbmux and is returned as a raw byte stream.
    net::Socket connect(std::uint32_t device_id, std::uint16_t port) &&;

    // Switches the connection into event mode; follow with receive().
    void start_listen();
    bool wait_readable(std::chrono::milliseconds timeout);
    plist::Value receive();

private:
    plist::Value request(plist::Dict message);

    net::Socket socket_;
    std::uint32_t tag_ = 0;
};

// Reports attach/detach events from a background thread. Devices already
// attached are reported as Attached right after construction.
class UsbmuxListener {
public:
    using Callback = std::function<void(const DeviceEvent&)>;
    using ErrorCallback = std::function<void(const std::string&)>;

    // Connects and sends Listen synchronously, so an unreachable service
    // throws here. Callbacks run on the listener thread.
    UsbmuxListener(const UsbmuxEndpoint& endpoint, Callback on_event, ErrorCallback on_error = {});
    ~UsbmuxListener();
    UsbmuxListener(const UsbmuxListener&) = delete;
    UsbmuxListener& operator=(const UsbmuxListener&) = delete;

    void stop();
    // False once the connection has dropped or stop() was called.
    bool running() const noexcept { return running_.load(); }

private:
    std::atomic<bool> running_{true};
    std::jthread thread_;
};

std::string_view to_string(ConnectionType type);

}  // namespace winx::device
