#include "winx/usbmux.hpp"

#include <algorithm>
#include <array>
#include <format>

namespace winx::device {
namespace {

constexpr std::uint32_t kMaxPacketSize = 32u * 1024 * 1024;
constexpr auto kPollInterval = std::chrono::milliseconds(200);

void put_le32(std::uint8_t* out, std::uint32_t value) {
    out[0] = static_cast<std::uint8_t>(value);
    out[1] = static_cast<std::uint8_t>(value >> 8);
    out[2] = static_cast<std::uint8_t>(value >> 16);
    out[3] = static_cast<std::uint8_t>(value >> 24);
}

std::uint32_t get_le32(const std::uint8_t* in) {
    return static_cast<std::uint32_t>(in[0]) | (static_cast<std::uint32_t>(in[1]) << 8) |
           (static_cast<std::uint32_t>(in[2]) << 16) | (static_cast<std::uint32_t>(in[3]) << 24);
}

std::string_view result_text(std::int64_t code) {
    switch (code) {
        case 0: return "OK";
        case 1: return "bad command";
        case 2: return "bad device (no longer attached)";
        case 3: return "connection refused by the device";
        case 6: return "protocol version not supported";
        default: return "unknown error";
    }
}

// usbmux reports newer UDIDs without the dash that every other Apple tool,
// and the pairing record file name, uses: 00008110001A2B3C4D5E6F78.
std::string normalize_udid(std::string serial) {
    if (serial.size() == 24 && serial.find('-') == std::string::npos) serial.insert(8, 1, '-');
    return serial;
}

std::optional<UsbmuxDevice> parse_device(const plist::Value& entry) {
    const plist::Value* properties = entry.find("Properties");
    if (!properties) return std::nullopt;

    UsbmuxDevice device;
    auto id = entry.int_at("DeviceID");
    if (!id) id = properties->int_at("DeviceID");
    device.device_id = static_cast<std::uint32_t>(id.value_or(0));
    device.udid = normalize_udid(properties->string_at("SerialNumber").value_or(""));
    device.product_id = static_cast<std::uint32_t>(properties->int_at("ProductID").value_or(0));
    device.location_id = static_cast<std::uint32_t>(properties->int_at("LocationID").value_or(0));
    const std::string connection = properties->string_at("ConnectionType").value_or("");
    if (connection == "USB") {
        device.connection = ConnectionType::Usb;
    } else if (connection == "Network") {
        device.connection = ConnectionType::Network;
    }
    return device;
}

std::optional<DeviceEvent> parse_event(const plist::Value& message) {
    const std::string type = message.string_at("MessageType").value_or("");
    DeviceEvent event;
    event.device_id = static_cast<std::uint32_t>(message.int_at("DeviceID").value_or(0));
    if (type == "Attached") {
        event.kind = DeviceEvent::Kind::Attached;
        event.device = parse_device(message);
        if (!event.device) return std::nullopt;
        event.device_id = event.device->device_id;
    } else if (type == "Detached") {
        event.kind = DeviceEvent::Kind::Detached;
    } else if (type == "Paired") {
        event.kind = DeviceEvent::Kind::Paired;
    } else {
        return std::nullopt;
    }
    return event;
}

void expect_ok(const plist::Value& reply, std::string_view what) {
    if (reply.string_at("MessageType") != "Result") return;
    const std::int64_t code = reply.int_at("Number").value_or(-1);
    if (code != 0) {
        throw UsbmuxError(std::format("usbmux {} failed: {}", what, result_text(code)),
                          static_cast<int>(code));
    }
}

}  // namespace

namespace usbmux_wire {

std::vector<std::uint8_t> encode_packet(const plist::Value& payload, std::uint32_t tag) {
    const std::string xml = plist::to_xml(payload);
    std::vector<std::uint8_t> packet(kHeaderSize + xml.size());
    put_le32(packet.data(), static_cast<std::uint32_t>(packet.size()));
    put_le32(packet.data() + 4, kVersionPlist);
    put_le32(packet.data() + 8, kMessagePlist);
    put_le32(packet.data() + 12, tag);
    std::copy(xml.begin(), xml.end(), packet.begin() + kHeaderSize);
    return packet;
}

Header decode_header(std::span<const std::uint8_t, kHeaderSize> bytes) {
    return Header{get_le32(bytes.data()), get_le32(bytes.data() + 4), get_le32(bytes.data() + 8),
                  get_le32(bytes.data() + 12)};
}

void write_packet(net::Socket& socket, const plist::Value& payload, std::uint32_t tag) {
    socket.send_all(encode_packet(payload, tag));
}

Packet read_packet(net::Socket& socket) {
    std::array<std::uint8_t, kHeaderSize> raw{};
    socket.recv_exact(raw);
    Packet packet;
    packet.header = decode_header(raw);
    if (packet.header.length < kHeaderSize || packet.header.length > kMaxPacketSize) {
        throw UsbmuxError(std::format("usbmux packet has invalid length {}", packet.header.length),
                          -1);
    }
    if (packet.header.message != kMessagePlist) {
        throw UsbmuxError(
            std::format("usbmux packet has unsupported message type {}", packet.header.message),
            -1);
    }
    std::vector<std::uint8_t> body(packet.header.length - kHeaderSize);
    socket.recv_exact(body);
    packet.payload = plist::parse(body);
    return packet;
}

}  // namespace usbmux_wire

UsbmuxClient::UsbmuxClient(const UsbmuxEndpoint& endpoint)
    : socket_(net::Socket::connect_tcp(endpoint.host, endpoint.port)) {}

plist::Value UsbmuxClient::request(plist::Dict message) {
    message.set("BundleID", "dev.winxcode.winx");
    message.set("ClientVersionString", "winxcode-0.1.0");
    message.set("ProgName", "winx");
    message.set("kLibUSBMuxVersion", 3);
    usbmux_wire::write_packet(socket_, plist::Value(std::move(message)), ++tag_);
    return usbmux_wire::read_packet(socket_).payload;
}

std::vector<UsbmuxDevice> UsbmuxClient::list_devices() {
    const plist::Value reply = request({{"MessageType", "ListDevices"}});
    expect_ok(reply, "ListDevices");
    const plist::Value* list = reply.find("DeviceList");
    if (!list || !list->is<plist::Array>()) {
        throw UsbmuxError("usbmux ListDevices returned no DeviceList", -1);
    }
    std::vector<UsbmuxDevice> devices;
    for (const plist::Value& entry : list->as_array()) {
        if (auto device = parse_device(entry)) devices.push_back(std::move(*device));
    }
    return devices;
}

std::string UsbmuxClient::read_buid() {
    const plist::Value reply = request({{"MessageType", "ReadBUID"}});
    expect_ok(reply, "ReadBUID");
    return reply.string_at("BUID").value_or("");
}

std::optional<plist::Value> UsbmuxClient::read_pair_record(std::string_view udid) {
    const plist::Value reply =
        request({{"MessageType", "ReadPairRecord"}, {"PairRecordID", std::string(udid)}});
    const plist::Data* data = reply.data_at("PairRecordData");
    if (!data) return std::nullopt;
    return plist::parse(data->bytes);
}

net::Socket UsbmuxClient::connect(std::uint32_t device_id, std::uint16_t port) && {
    // usbmux expects the port in network byte order.
    const std::uint16_t network_port = static_cast<std::uint16_t>((port << 8) | (port >> 8));
    const plist::Value reply = request(
        {{"MessageType", "Connect"}, {"DeviceID", device_id}, {"PortNumber", network_port}});
    expect_ok(reply, "Connect");
    return std::move(socket_);
}

void UsbmuxClient::start_listen() {
    const plist::Value reply = request({{"MessageType", "Listen"}});
    expect_ok(reply, "Listen");
}

bool UsbmuxClient::wait_readable(std::chrono::milliseconds timeout) {
    return socket_.wait_readable(timeout);
}

plist::Value UsbmuxClient::receive() { return usbmux_wire::read_packet(socket_).payload; }

UsbmuxListener::UsbmuxListener(const UsbmuxEndpoint& endpoint, Callback on_event,
                               ErrorCallback on_error) {
    UsbmuxClient client(endpoint);
    client.start_listen();
    thread_ = std::jthread([this, client = std::move(client), on_event = std::move(on_event),
                            on_error = std::move(on_error)](std::stop_token stop) mutable {
        try {
            while (!stop.stop_requested()) {
                if (!client.wait_readable(kPollInterval)) continue;
                if (const auto event = parse_event(client.receive())) on_event(*event);
            }
        } catch (const std::exception& error) {
            if (!stop.stop_requested() && on_error) on_error(error.what());
        }
        running_ = false;
    });
}

UsbmuxListener::~UsbmuxListener() { stop(); }

void UsbmuxListener::stop() {
    if (thread_.joinable()) {
        thread_.request_stop();
        thread_.join();
    }
    running_ = false;
}

std::string_view to_string(ConnectionType type) {
    switch (type) {
        case ConnectionType::Usb: return "USB";
        case ConnectionType::Network: return "Wi-Fi";
        default: return "unknown";
    }
}

}  // namespace winx::device
