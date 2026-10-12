#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "winx/lockdown.hpp"
#include "winx/plist.hpp"
#include "winx/socket.hpp"
#include "winx/usbmux.hpp"

using namespace winx;
using namespace std::chrono_literals;
using device::DeviceEvent;
using device::UsbmuxEndpoint;
using plist::Array;
using plist::Dict;
using plist::Value;
namespace wire = device::usbmux_wire;

namespace {

// Stands in for Apple Mobile Device Service: accepts one connection on an
// ephemeral loopback port and hands it to `handler` on a background thread.
// Catch2 assertions are not thread-safe, so handlers record what they saw and
// the test body checks it after the server is destroyed.
class FakeServer {
public:
    explicit FakeServer(std::function<void(net::Socket&)> handler)
        : thread_([this, handler = std::move(handler)] {
              try {
                  net::Socket socket = listener_.accept();
                  socket.set_timeouts(5s, 5s);
                  handler(socket);
              } catch (const std::exception&) {
              }
          }) {}

    ~FakeServer() {
        if (thread_.joinable()) thread_.join();
    }

    UsbmuxEndpoint endpoint() const { return {"127.0.0.1", listener_.port()}; }

private:
    net::TcpListener listener_ = net::TcpListener::bind_loopback();
    std::thread thread_;
};

Value attached_message(std::uint32_t device_id, const std::string& serial) {
    return Dict{{"MessageType", "Attached"},
                {"DeviceID", device_id},
                {"Properties", Dict{{"ConnectionType", "USB"},
                                    {"DeviceID", device_id},
                                    {"LocationID", 1048576},
                                    {"ProductID", 4776},
                                    {"SerialNumber", serial}}}};
}

Value result_message(int number) { return Dict{{"MessageType", "Result"}, {"Number", number}}; }

void wait_for_close(net::Socket& socket) {
    std::array<std::uint8_t, 1> byte{};
    try {
        socket.recv_some(byte);
    } catch (const std::exception&) {
    }
}

}  // namespace

TEST_CASE("usbmux packets carry a 16-byte little-endian header", "[usbmux]") {
    const Value payload = Dict{{"MessageType", "Listen"}};
    const std::vector<std::uint8_t> packet = wire::encode_packet(payload, 0x01020304);
    REQUIRE(packet.size() > wire::kHeaderSize);

    const wire::Header header =
        wire::decode_header(std::span<const std::uint8_t, wire::kHeaderSize>(packet.data(), wire::kHeaderSize));
    CHECK(header.length == packet.size());
    CHECK(header.version == 1);
    CHECK(header.message == 8);
    CHECK(header.tag == 0x01020304);
    CHECK(packet[12] == 0x04);  // tag is little-endian on the wire
    CHECK(packet[15] == 0x01);

    const std::string body(packet.begin() + wire::kHeaderSize, packet.end());
    CHECK(plist::parse_xml(body) == payload);
}

TEST_CASE("ListDevices returns attached devices with normalized UDIDs", "[usbmux]") {
    std::string seen_type;
    std::int64_t seen_version = 0;
    std::vector<device::UsbmuxDevice> devices;
    {
        FakeServer server([&](net::Socket& socket) {
            const wire::Packet request = wire::read_packet(socket);
            seen_type = request.payload.string_at("MessageType").value_or("");
            seen_version = request.payload.int_at("kLibUSBMuxVersion").value_or(0);
            const Value reply =
                Dict{{"DeviceList", Array{attached_message(7, "00008110001A2B3C4D5E6F78"),
                                          attached_message(9, "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678")}}};
            wire::write_packet(socket, reply, request.header.tag);
        });
        devices = device::UsbmuxClient(server.endpoint()).list_devices();
    }

    CHECK(seen_type == "ListDevices");
    CHECK(seen_version == 3);
    REQUIRE(devices.size() == 2);
    CHECK(devices[0].device_id == 7);
    CHECK(devices[0].udid == "00008110-001A2B3C4D5E6F78");
    CHECK(devices[0].connection == device::ConnectionType::Usb);
    CHECK(devices[0].product_id == 4776);
    // 40-character UDIDs from older devices are left untouched.
    CHECK(devices[1].udid == "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678");
}

TEST_CASE("the listener reports attach and detach events", "[usbmux]") {
    std::mutex mutex;
    std::condition_variable changed;
    std::vector<DeviceEvent> events;
    std::string seen_type;
    {
        FakeServer server([&](net::Socket& socket) {
            const wire::Packet request = wire::read_packet(socket);
            seen_type = request.payload.string_at("MessageType").value_or("");
            wire::write_packet(socket, result_message(0), request.header.tag);
            wire::write_packet(socket, attached_message(7, "00008110001A2B3C4D5E6F78"), 0);
            wire::write_packet(socket, Dict{{"MessageType", "Paired"}, {"DeviceID", 7}}, 0);
            wire::write_packet(socket, Dict{{"MessageType", "Detached"}, {"DeviceID", 7}}, 0);
            wait_for_close(socket);
        });

        device::UsbmuxListener listener(server.endpoint(), [&](const DeviceEvent& event) {
            const std::lock_guard lock(mutex);
            events.push_back(event);
            changed.notify_all();
        });
        std::unique_lock lock(mutex);
        changed.wait_for(lock, 5s, [&] { return events.size() >= 3; });
        CHECK(listener.running());
    }

    CHECK(seen_type == "Listen");
    REQUIRE(events.size() == 3);
    CHECK(events[0].kind == DeviceEvent::Kind::Attached);
    REQUIRE(events[0].device.has_value());
    CHECK(events[0].device->udid == "00008110-001A2B3C4D5E6F78");
    CHECK(events[0].device_id == 7);
    CHECK(events[1].kind == DeviceEvent::Kind::Paired);
    CHECK(events[2].kind == DeviceEvent::Kind::Detached);
    CHECK(events[2].device_id == 7);
}

TEST_CASE("the listener reports a dropped connection", "[usbmux]") {
    std::mutex mutex;
    std::condition_variable changed;
    std::string error;
    {
        FakeServer server([&](net::Socket& socket) {
            const wire::Packet request = wire::read_packet(socket);
            wire::write_packet(socket, result_message(0), request.header.tag);
            socket.close();
        });

        device::UsbmuxListener listener(
            server.endpoint(), [](const DeviceEvent&) {},
            [&](const std::string& message) {
                const std::lock_guard lock(mutex);
                error = message;
                changed.notify_all();
            });
        std::unique_lock lock(mutex);
        changed.wait_for(lock, 5s, [&] { return !error.empty(); });
    }
    CHECK_FALSE(error.empty());
}

TEST_CASE("a refused Listen or Connect surfaces the usbmux result code", "[usbmux]") {
    SECTION("Connect to a detached device") {
        std::int64_t seen_port = 0;
        int code = 0;
        {
            FakeServer server([&](net::Socket& socket) {
                const wire::Packet request = wire::read_packet(socket);
                seen_port = request.payload.int_at("PortNumber").value_or(0);
                wire::write_packet(socket, result_message(2), request.header.tag);
            });
            try {
                device::UsbmuxClient(server.endpoint()).connect(7, device::kLockdownPort);
            } catch (const device::UsbmuxError& error) {
                code = error.code();
            }
        }
        CHECK(code == 2);
        CHECK(seen_port == 32498);  // 62078 in network byte order
    }
    SECTION("Listen rejected") {
        FakeServer server([&](net::Socket& socket) {
            const wire::Packet request = wire::read_packet(socket);
            wire::write_packet(socket, result_message(6), request.header.tag);
        });
        CHECK_THROWS_AS(device::UsbmuxListener(server.endpoint(), [](const DeviceEvent&) {}),
                        device::UsbmuxError);
    }
}

TEST_CASE("nothing listening gives a connection-refused socket error", "[usbmux]") {
    // Bind then release a port so that it is known to be closed.
    std::uint16_t port = 0;
    { port = net::TcpListener::bind_loopback().port(); }
    CHECK_THROWS_AS(device::UsbmuxClient(UsbmuxEndpoint{"127.0.0.1", port}), net::SocketError);
}

TEST_CASE("device info is read over a lockdown tunnel", "[lockdown]") {
    std::vector<std::string> requests;
    device::DeviceInfo info;
    {
        FakeServer server([&](net::Socket& socket) {
            const wire::Packet connect = wire::read_packet(socket);
            requests.push_back(connect.payload.string_at("MessageType").value_or(""));
            wire::write_packet(socket, result_message(0), connect.header.tag);

            // From here the socket is a raw tunnel to lockdownd.
            for (;;) {
                Value request;
                try {
                    request = device::lockdown_wire::read_message(socket);
                } catch (const std::exception&) {
                    return;
                }
                const std::string kind = request.string_at("Request").value_or("");
                const std::string key = request.string_at("Key").value_or("");
                requests.push_back(kind + (key.empty() ? "" : ":" + key));

                Dict reply{{"Request", kind}};
                if (kind == "QueryType") {
                    reply.set("Type", "com.apple.mobile.lockdown");
                } else if (key == "DeviceName") {
                    reply.set("Value", "Test \xE2\x80\x99s iPhone");
                } else if (key == "ProductVersion") {
                    reply.set("Value", "18.1");
                } else if (key == "ProductType") {
                    reply.set("Value", "iPhone14,5");
                } else if (key == "DeviceClass") {
                    reply.set("Value", "iPhone");
                } else {
                    reply.set("Error", "MissingValue");
                }
                device::lockdown_wire::write_message(socket, Value(std::move(reply)));
            }
        });
        info = device::query_device_info(server.endpoint(), 7);
    }

    CHECK(info.name == "Test \xE2\x80\x99s iPhone");
    CHECK(info.product_version == "18.1");
    CHECK(info.product_type == "iPhone14,5");
    CHECK(info.device_class == "iPhone");
    CHECK(info.build_version.empty());  // refused keys are left empty, not fatal
    REQUIRE(requests.size() >= 3);
    CHECK(requests[0] == "Connect");
    CHECK(requests[1] == "QueryType");
    CHECK(requests[2] == "GetValue:DeviceName");
}
