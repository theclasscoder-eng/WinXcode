#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "fake_device.hpp"
#include "support.hpp"
#include "winx/device_services.hpp"
#include "winx/files.hpp"
#include "winx/identity.hpp"
#include "winx/lockdown.hpp"
#include "winx/plist.hpp"
#include "winx/text.hpp"
#include "winx/tls.hpp"

using namespace winx;
using namespace std::chrono_literals;
using crypto::Bytes;

namespace {

// A named, self-signed TLS identity that removes its key when it goes away.
struct NamedIdentity {
    std::wstring key_name;
    Bytes certificate;

    explicit NamedIdentity(const std::string& subject) {
        key_name = to_wide("WinXcode Test TLS " + crypto::to_hex(crypto::random_bytes(4)));
        const auth::RsaKey key = auth::RsaKey::create(key_name);
        certificate = auth::make_self_signed_certificate(key, "CN=" + subject);
    }
    ~NamedIdentity() { auth::RsaKey::remove(key_name); }
    device::TlsIdentity identity() const { return {certificate, key_name}; }
};

std::filesystem::path make_bundle(const std::filesystem::path& root, const Bytes& payload) {
    const auto app = root / "Hello.app";
    const std::string info = plist::to_xml(plist::Dict{{"CFBundleIdentifier", "com.example.hello"},
                                                       {"CFBundleExecutable", "Hello"}});
    write_text_file(app / "Info.plist", info);
    write_file(app / "Hello", payload);
    write_text_file(app / "en.lproj" / "Localizable.strings", "\"a\" = \"b\";");
    write_text_file(app / "_CodeSignature" / "CodeResources", "<plist/>");
    return app;
}

}  // namespace

TEST_CASE("TLS streams authenticate both sides and carry data", "[tls]") {
    const NamedIdentity server_identity("Test Server");
    const NamedIdentity client_identity("Test Client");
    net::TcpListener listener = net::TcpListener::bind_loopback();

    // 300 KB crosses many TLS records in each direction.
    const Bytes large = crypto::random_bytes(300 * 1024);
    Bytes seen_client_certificate;
    std::string server_error;
    std::thread server([&] {
        try {
            auto socket = std::make_unique<net::Socket>(listener.accept());
            socket->set_timeouts(10s, 10s);
            device::TlsOptions options;
            options.server = true;
            options.identity = server_identity.identity();
            options.request_client_certificate = true;
            const auto tls = device::TlsStream::handshake(std::move(socket), options);
            seen_client_certificate = tls->peer_certificate();
            Bytes received(large.size());
            tls->recv_exact(received);
            std::reverse(received.begin(), received.end());
            tls->send_all(received);
        } catch (const std::exception& error) {
            server_error = error.what();
        }
    });

    SECTION("with the server certificate pinned") {
        auto socket = std::make_unique<net::Socket>(
            net::Socket::connect_tcp("127.0.0.1", listener.port()));
        socket->set_timeouts(10s, 10s);
        device::TlsOptions options;
        options.identity = client_identity.identity();
        options.accepted_peers = {server_identity.certificate};
        const auto tls = device::TlsStream::handshake(std::move(socket), options);
        CHECK(tls->peer_certificate() == server_identity.certificate);

        tls->send_all(large);
        Bytes echoed(large.size());
        tls->recv_exact(echoed);
        std::reverse(echoed.begin(), echoed.end());
        CHECK(echoed == large);
        server.join();
        CHECK(server_error.empty());
        CHECK(seen_client_certificate == client_identity.certificate);
    }
    SECTION("a certificate that is not pinned is refused") {
        auto socket = std::make_unique<net::Socket>(
            net::Socket::connect_tcp("127.0.0.1", listener.port()));
        socket->set_timeouts(10s, 10s);
        device::TlsOptions options;
        options.identity = client_identity.identity();
        options.accepted_peers = {client_identity.certificate};  // the wrong one
        CHECK_THROWS_AS(device::TlsStream::handshake(std::move(socket), options), device::TlsError);
        server.join();
    }
    SECTION("nothing is trusted by default") {
        auto socket = std::make_unique<net::Socket>(
            net::Socket::connect_tcp("127.0.0.1", listener.port()));
        socket->set_timeouts(10s, 10s);
        CHECK_THROWS_AS(device::TlsStream::handshake(std::move(socket), device::TlsOptions{}),
                        device::TlsError);
        server.join();
    }
}

TEST_CASE("PEM private keys import into CNG in both encodings", "[tls]") {
    const auth::RsaKey original = auth::RsaKey::create({}, true);
    const Bytes certificate = auth::make_self_signed_certificate(original, "CN=Imported");
    const std::string pkcs8 = test::export_private_key_pem(original);
    const std::string pkcs1 = test::to_pkcs1_pem(pkcs8);
    REQUIRE(pkcs1.starts_with("-----BEGIN RSA PRIVATE KEY-----"));

    const std::wstring name = to_wide("WinXcode Test Import " + crypto::to_hex(crypto::random_bytes(4)));
    for (const std::string& pem : {pkcs8, pkcs1}) {
        device::import_rsa_private_key(pem, name);
        const auth::RsaKey imported = auth::RsaKey::open(name);
        CHECK(auth::certificate_matches_key(certificate, imported));
    }
    CHECK(device::remove_private_key(name));
    CHECK_FALSE(device::remove_private_key(name));
    CHECK_THROWS_AS(device::import_rsa_private_key("no key here", name), device::TlsError);
    CHECK_THROWS_AS(device::certificate_from_pem("no certificate"), device::TlsError);
}

TEST_CASE("an app is uploaded and installed over a paired TLS session", "[device]") {
    test::FakeDevice fake;
    const test::TempDir dir("winx_install");
    const Bytes executable = crypto::random_bytes(2 * 1024 * 1024 + 123);  // spans upload chunks
    const std::filesystem::path bundle = make_bundle(dir.path(), executable);

    // No file exists on disk for the fake UDID, so the record comes from the
    // service through ReadPairRecord.
    device::DeviceConnection connection = device::DeviceConnection::open(fake.endpoint());
    CHECK(connection.device().udid == fake.udid());
    CHECK(connection.device().connection == device::ConnectionType::Usb);
    CHECK(device::developer_mode_enabled(connection) == true);

    std::vector<std::pair<std::string, int>> stages;
    device::install_app(connection, bundle,
                        [&](const std::string& stage, int percent) {
                            stages.emplace_back(stage, percent);
                        });

    const std::lock_guard lock(fake.mutex);
    // Every connection after StartSession presented this PC's host certificate.
    REQUIRE(fake.client_certificates.size() >= 3);  // lockdown, AFC, installation_proxy
    for (const Bytes& certificate : fake.client_certificates) {
        CHECK(certificate == fake.host_certificate());
    }

    REQUIRE(fake.install_commands.size() == 1);
    const plist::Value& command = fake.install_commands[0];
    CHECK(command.string_at("Command") == "Install");
    CHECK(command.string_at("PackagePath") == "PublicStaging/Hello.app");
    CHECK(command.find("ClientOptions")->string_at("PackageType") == "Developer");

    // What installd saw in the staging area matches the local bundle exactly.
    CHECK(fake.staged_at_install.at("PublicStaging/Hello.app/Hello") == executable);
    CHECK(fake.staged_at_install.contains("PublicStaging/Hello.app/Info.plist"));
    CHECK(fake.staged_at_install.contains("PublicStaging/Hello.app/en.lproj/Localizable.strings"));
    CHECK(fake.staged_at_install.contains("PublicStaging/Hello.app/_CodeSignature/CodeResources"));
    CHECK(fake.staged_at_install.size() == 4);
    CHECK(fake.installed_bundle_ids.back() == "com.example.hello");
    // The staging copy is cleaned up afterwards.
    CHECK(fake.files.empty());
    CHECK(fake.directories.contains("PublicStaging"));

    REQUIRE(stages.size() >= 5);
    CHECK(stages.front().first == "Uploading");
    CHECK(std::find(stages.begin(), stages.end(),
                    std::pair<std::string, int>{"Uploading", 100}) != stages.end());
    CHECK(stages.back() == std::pair<std::string, int>{"Complete", -1});
    CHECK(stages[stages.size() - 2] == std::pair<std::string, int>{"InstallingApplication", 80});
}

TEST_CASE("installation failures are explained and cleaned up", "[device]") {
    test::FakeDevice fake;
    const test::TempDir dir("winx_install_fail");
    const std::filesystem::path bundle = make_bundle(dir.path(), crypto::random_bytes(1000));
    device::DeviceConnection connection = device::DeviceConnection::open(fake.endpoint(), fake.udid());

    {
        const std::lock_guard lock(fake.mutex);
        fake.install_error = "ApplicationVerificationFailed";
    }
    try {
        device::install_app(connection, bundle);
        FAIL("expected InstallError");
    } catch (const device::InstallError& error) {
        CHECK(error.code() == "ApplicationVerificationFailed");
        const std::string message = error.what();
        CHECK(message.find("the fake device said no") != std::string::npos);
        CHECK(message.find("provisioning profile") != std::string::npos);
    }
    {
        const std::lock_guard lock(fake.mutex);
        CHECK(fake.files.empty());  // the staged upload was removed
    }
    CHECK_THROWS_AS(device::install_app(connection, dir.path() / "Missing.app"),
                    device::InstallError);
    CHECK(device::explain_install_error("SomethingNew", "detail") ==
          "installation failed: SomethingNew (detail)");
}

TEST_CASE("apps are listed and removed through installation_proxy", "[device]") {
    test::FakeDevice fake;
    device::DeviceConnection connection = device::DeviceConnection::open(fake.endpoint());

    const std::vector<device::InstalledApp> apps = device::list_apps(connection);
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].bundle_id == "com.example.existing");
    CHECK(apps[0].name == "App com.example.existing");
    CHECK(apps[0].version == "1.0");

    device::uninstall_app(connection, "com.example.existing");
    CHECK(device::list_apps(connection).empty());
}

TEST_CASE("lockdown session problems are reported in plain terms", "[device]") {
    test::FakeDevice fake;

    SECTION("a locked device") {
        {
            const std::lock_guard lock(fake.mutex);
            fake.locked = true;
        }
        device::DeviceConnection connection = device::DeviceConnection::open(fake.endpoint());
        try {
            device::list_apps(connection);
            FAIL("expected LockdownError");
        } catch (const device::LockdownError& error) {
            CHECK(error.code() == "PasswordProtected");
            CHECK(std::string(error.what()).find("unlock it") != std::string::npos);
        }
    }
    SECTION("a device that is not paired") {
        {
            const std::lock_guard lock(fake.mutex);
            fake.paired = false;
        }
        try {
            device::DeviceConnection::open(fake.endpoint());
            FAIL("expected LockdownError");
        } catch (const device::LockdownError& error) {
            CHECK(error.code() == "NotPaired");
        }
    }
    SECTION("a pairing record the device does not recognise") {
        device::PairRecord stale = fake.pair_record();
        stale.host_id = "SOME-OTHER-HOST";
        const auto devices = device::UsbmuxClient(fake.endpoint()).list_devices();
        device::DeviceConnection connection(fake.endpoint(), devices.front(), stale);
        try {
            device::list_apps(connection);
            FAIL("expected LockdownError");
        } catch (const device::LockdownError& error) {
            CHECK(error.code() == "InvalidHostID");
        }
    }
    SECTION("a device that is not attached") {
        CHECK_THROWS_AS(device::DeviceConnection::open(fake.endpoint(), "00000000-0000000000000000"),
                        device::LockdownError);
    }
    SECTION("a service the device does not offer") {
        device::DeviceConnection connection = device::DeviceConnection::open(fake.endpoint());
        try {
            connection.start_service("com.example.nothing");
            FAIL("expected LockdownError");
        } catch (const device::LockdownError& error) {
            CHECK(error.code() == "InvalidService");
        }
    }
}

TEST_CASE("Developer Mode status is read and its switch can be revealed", "[device]") {
    test::FakeDevice fake;
    {
        const std::lock_guard lock(fake.mutex);
        fake.developer_mode = false;
    }
    device::DeviceConnection connection = device::DeviceConnection::open(fake.endpoint());
    CHECK(device::developer_mode_enabled(connection) == false);
    device::reveal_developer_mode(connection);
    // The reply has been read, so the device has processed the request.
    const std::lock_guard lock(fake.mutex);
    CHECK(fake.developer_mode_revealed);
}

TEST_CASE("Wi-Fi connections are switched through lockdown", "[device][wifi]") {
    test::FakeDevice fake;
    device::DeviceConnection connection = device::DeviceConnection::open(fake.endpoint());
    // A phone that was never switched has no value; that reads as off.
    CHECK_FALSE(device::wifi_connections_enabled(connection));
    device::set_wifi_connections(connection, true);
    CHECK(device::wifi_connections_enabled(connection));
    {
        const std::lock_guard lock(fake.mutex);
        CHECK(fake.wifi_connections == true);
    }
    device::set_wifi_connections(connection, false);
    CHECK_FALSE(device::wifi_connections_enabled(connection));
}

TEST_CASE("a phone attached by USB and Wi-Fi is reached through USB", "[device][wifi]") {
    test::FakeDevice fake;
    {
        const std::lock_guard lock(fake.mutex);
        fake.also_on_wifi = true;
    }
    const auto devices = device::UsbmuxClient(fake.endpoint()).list_devices();
    REQUIRE(devices.size() == 2);
    CHECK(devices[0].connection == device::ConnectionType::Network);
    CHECK(devices[0].udid == devices[1].udid);

    // One phone twice is still one device, with or without --udid.
    for (const std::string& udid : {std::string(), fake.udid()}) {
        device::DeviceConnection connection = device::DeviceConnection::open(fake.endpoint(), udid);
        CHECK(connection.device().connection == device::ConnectionType::Usb);
        CHECK(connection.device().device_id == 1);
        CHECK(device::developer_mode_enabled(connection) == true);
    }
    const std::lock_guard lock(fake.mutex);
    CHECK(std::find(fake.connected_device_ids.begin(), fake.connected_device_ids.end(), 2) ==
          fake.connected_device_ids.end());
}

TEST_CASE("a Wi-Fi device that cannot be reached is explained", "[device][wifi]") {
    test::FakeDevice fake;
    device::UsbmuxDevice asleep;
    asleep.device_id = 2;
    asleep.udid = fake.udid();
    asleep.connection = device::ConnectionType::Network;
    // Nothing listens here, so the tunnel cannot be opened.
    device::DeviceConnection connection({"127.0.0.1", 1}, asleep, fake.pair_record());
    try {
        connection.get_value("DeviceName");
        FAIL("the connection unexpectedly succeeded");
    } catch (const device::LockdownError& error) {
        CHECK(std::string(error.what()).find("over Wi-Fi") != std::string::npos);
    }
}

TEST_CASE("the device log is delivered line by line", "[device]") {
    test::FakeDevice fake;
    device::DeviceConnection connection = device::DeviceConnection::open(fake.endpoint());
    device::SyslogStream log = device::SyslogStream::open(connection);
    CHECK(log.read_line(5s) == "first line");
    CHECK(log.read_line(5s) == "second line");
    CHECK_FALSE(log.read_line(200ms).has_value());  // nothing more, but still connected
}

TEST_CASE("AFC handles directories, listings and missing paths", "[device]") {
    test::FakeDevice fake;
    device::DeviceConnection connection = device::DeviceConnection::open(fake.endpoint());
    device::AfcClient afc(connection.start_service("com.apple.afc"));

    afc.make_directory("Dir");
    afc.write_file("Dir/a.txt", Bytes{'a'});
    afc.make_directory("Dir/Sub");
    afc.write_file("Dir/Sub/b.bin", crypto::random_bytes(10));
    CHECK(afc.read_directory("Dir") == std::vector<std::string>{"Sub", "a.txt"});

    try {
        afc.write_file("Nowhere/c.txt", Bytes{'c'});
        FAIL("expected AfcError");
    } catch (const device::AfcError& error) {
        CHECK(error.code() == device::kAfcObjectNotFound);
    }
    CHECK_NOTHROW(afc.remove_all("DoesNotExist"));
    afc.remove_all("Dir");
    CHECK(afc.read_directory("Dir").empty());
}

// Hidden: checks the SChannel client loops against a real TLS server.
TEST_CASE("live: TLS client interoperates with a public server", "[.live]") {
    auto socket =
        std::make_unique<net::Socket>(net::Socket::connect_tcp("www.apple.com", 443));
    socket->set_timeouts(15s, 15s);
    device::TlsOptions options;
    options.system_trust = true;
    options.server_name = L"www.apple.com";
    const auto tls = device::TlsStream::handshake(std::move(socket), options);
    CHECK_FALSE(tls->peer_certificate().empty());
    tls->send_all(crypto::as_bytes(
        "HEAD / HTTP/1.1\r\nHost: www.apple.com\r\nConnection: close\r\n\r\n"));
    std::array<std::uint8_t, 12> head{};
    tls->recv_exact(head);
    CHECK(std::string(head.begin(), head.begin() + 8) == "HTTP/1.1");
}
