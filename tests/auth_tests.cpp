#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "support.hpp"
#include "winx/auth_session.hpp"
#include "winx/base64.hpp"
#include "winx/developer_api.hpp"
#include "winx/files.hpp"
#include "winx/identity.hpp"
#include "winx/keys.hpp"
#include "winx/plist.hpp"
#include "winx/provisioner.hpp"
#include "winx/provisioning_profile.hpp"
#include "winx/text.hpp"

using namespace winx;
using auth::json;
using crypto::Bytes;

namespace {

const std::string kTeam = "TEAM123456";
const std::string kUdid = "00008110-001A2B3C4D5E6F78";

std::optional<std::string> query_value(const auth::Query& query, std::string_view name) {
    for (const auto& [key, value] : query) {
        if (key == name) return value;
    }
    return std::nullopt;
}

http::Response json_response(int status, const json& body) {
    http::Response response;
    response.status = status;
    response.body = body.dump();
    return response;
}

// An in-memory stand-in for Apple's developer resources API.
class FakePortal : public auth::Transport {
public:
    struct Call {
        std::string method;
        std::string path;
    };

    std::vector<Call> calls;
    json devices = json::array();
    json bundle_ids = json::array();
    json certificates = json::array();
    json profiles = json::array();
    auth::RsaKey ca_key = auth::RsaKey::create();
    int next_id = 1;

    int count(std::string_view method, std::string_view path) const {
        return static_cast<int>(std::count_if(calls.begin(), calls.end(), [&](const Call& call) {
            return call.method == method && call.path == path;
        }));
    }

    http::Response perform(std::string_view method, std::string_view path, const auth::Query& query,
                           const json* body) override {
        calls.push_back({std::string(method), std::string(path)});
        const auto attributes = [&]() -> const json& { return (*body)["data"]["attributes"]; };

        if (path == "/v1/devices") {
            if (method == "GET") {
                return list(devices, "udid", query_value(query, "filter[udid]"));
            }
            return create(devices, "devices",
                          {{"name", attributes()["name"]},
                           {"udid", attributes()["udid"]},
                           {"platform", "IOS"},
                           {"status", "ENABLED"}});
        }
        if (path == "/v1/bundleIds") {
            if (method == "GET") {
                // Apple's identifier filter is a prefix match.
                const auto wanted = query_value(query, "filter[identifier]");
                json data = json::array();
                for (const json& item : bundle_ids) {
                    const std::string id = item["attributes"]["identifier"];
                    if (!wanted || id.starts_with(*wanted)) data.push_back(item);
                }
                return json_response(200, {{"data", data}});
            }
            return create(bundle_ids, "bundleIds",
                          {{"identifier", attributes()["identifier"]},
                           {"name", attributes()["name"]},
                           {"platform", "IOS"},
                           {"seedId", kTeam}});
        }
        if (path == "/v1/certificates") {
            if (method == "GET") return list(certificates, "", std::nullopt);
            const std::string csr = attributes()["csrContent"];
            const Bytes der = test::issue_certificate(
                csr, ca_key, "CN=Apple Development: Test User, OU=" + kTeam + ", O=Test Org");
            return create(certificates, "certificates",
                          {{"certificateContent", base64_encode(der)},
                           {"certificateType", "DEVELOPMENT"},
                           {"serialNumber", auth::describe_certificate(der).serial_hex},
                           {"name", "Apple Development: Test User"}});
        }
        if (path == "/v1/profiles") {
            if (method == "GET") return list(profiles, "name", query_value(query, "filter[name]"));
            return create(profiles, "profiles", make_profile(*body));
        }
        if (path.starts_with("/v1/profiles/") && method == "DELETE") {
            const std::string id(path.substr(13));
            for (auto it = profiles.begin(); it != profiles.end(); ++it) {
                if ((*it)["id"] == id) {
                    profiles.erase(it);
                    break;
                }
            }
            return json_response(204, json::object());
        }
        return json_response(404, {{"errors", {{{"code", "NOT_FOUND"}, {"title", "no route"}}}}});
    }

private:
    http::Response list(const json& collection, const char* attribute,
                        const std::optional<std::string>& wanted) const {
        json data = json::array();
        for (const json& item : collection) {
            if (!wanted || item["attributes"][attribute] == *wanted) data.push_back(item);
        }
        return json_response(200, {{"data", data}});
    }

    http::Response create(json& collection, const char* type, json attributes) {
        const json resource = {{"type", type},
                               {"id", "ID" + std::to_string(next_id++)},
                               {"attributes", std::move(attributes)}};
        collection.push_back(resource);
        return json_response(201, {{"data", resource}});
    }

    static const json& find(const json& collection, const std::string& id) {
        for (const json& item : collection) {
            if (item["id"] == id) return item;
        }
        throw std::runtime_error("fake portal: unknown resource " + id);
    }

    json make_profile(const json& body) const {
        const json& data = body["data"];
        const json& relationships = data["relationships"];
        const std::string bundle =
            find(bundle_ids, relationships["bundleId"]["data"]["id"])["attributes"]["identifier"];

        plist::Array device_udids;
        for (const json& ref : relationships["devices"]["data"]) {
            device_udids.emplace_back(
                find(devices, ref["id"])["attributes"]["udid"].get<std::string>());
        }
        plist::Array certificate_data;
        for (const json& ref : relationships["certificates"]["data"]) {
            const std::string content =
                find(certificates, ref["id"])["attributes"]["certificateContent"];
            certificate_data.emplace_back(plist::Data{base64_decode(content).value()});
        }

        const double now = static_cast<double>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count() -
            978307200);
        const std::string name = data["attributes"]["name"];
        const plist::Value payload = plist::Dict{
            {"Name", name},
            {"UUID", "11111111-2222-3333-4444-" + std::to_string(100000000000 + next_id)},
            {"TeamName", "Test Org"},
            {"TeamIdentifier", plist::Array{kTeam}},
            {"AppIDName", "WinXcode Test"},
            {"CreationDate", plist::Date{now}},
            {"ExpirationDate", plist::Date{now + 365.0 * 86400}},
            {"ProvisionedDevices", std::move(device_udids)},
            {"DeveloperCertificates", std::move(certificate_data)},
            {"Entitlements",
             plist::Dict{{"application-identifier", kTeam + "." + bundle},
                         {"com.apple.developer.team-identifier", kTeam},
                         {"get-task-allow", true},
                         {"keychain-access-groups", plist::Array{kTeam + ".*"}}}}};
        const std::string xml = plist::to_xml(payload);
        return {{"name", name},
                {"profileType", "IOS_APP_DEVELOPMENT"},
                {"profileState", "ACTIVE"},
                {"uuid", "uuid-" + std::to_string(next_id)},
                {"profileContent", base64_encode(test::wrap_in_cms(crypto::as_bytes(xml)))}};
    }
};

}  // namespace

TEST_CASE("a .p8 key imports into CNG and signs ES256", "[auth][keys]") {
    const std::string p8 = test::generate_p8();
    const auth::EcSigningKey key = auth::EcSigningKey::import_p8(p8);

    const Bytes message{'h', 'e', 'l', 'l', 'o'};
    const Bytes signature = key.sign(message);
    CHECK(signature.size() == 64);  // raw r || s, the JWS format
    CHECK(key.verify(message, signature));
    Bytes tampered = message;
    tampered[0] ^= 1;
    CHECK_FALSE(key.verify(tampered, signature));

    CHECK_THROWS_AS(auth::EcSigningKey::import_p8("not a key"), auth::KeyError);
    CHECK_THROWS_AS(
        auth::EcSigningKey::import_p8(pem_encode("PRIVATE KEY", crypto::random_bytes(40))),
        auth::KeyError);
}

TEST_CASE("an imported .p8 key persists under a name and can be removed", "[auth][keys]") {
    const std::wstring name =
        to_wide("WinXcode Test Key " + crypto::to_hex(crypto::random_bytes(4)));
    const Bytes message{'x'};
    Bytes signature;
    {
        const auth::EcSigningKey key = auth::EcSigningKey::import_p8(test::generate_p8(), name);
        signature = key.sign(message);
    }
    {
        const auth::EcSigningKey reopened = auth::EcSigningKey::open(name);
        CHECK(reopened.verify(message, signature));
    }
    CHECK(auth::EcSigningKey::remove(name));
    CHECK_FALSE(auth::EcSigningKey::remove(name));
    CHECK_THROWS_AS(auth::EcSigningKey::open(name), auth::KeyError);
}

TEST_CASE("App Store Connect tokens are well-formed ES256 JWTs", "[auth][jwt]") {
    const auth::EcSigningKey key = auth::EcSigningKey::import_p8(test::generate_p8());
    const auto now = std::chrono::system_clock::time_point(std::chrono::seconds(1700000000));
    const std::string token =
        auth::make_asc_token(key, "KEYID12345", "issuer-uuid", now, std::chrono::minutes(10));

    const auto first = token.find('.');
    const auto second = token.find('.', first + 1);
    REQUIRE(first != std::string::npos);
    REQUIRE(second != std::string::npos);
    CHECK(token.find_first_of("+/=") == std::string::npos);  // base64url, unpadded

    const Bytes header_raw = auth::base64url_decode(token.substr(0, first)).value();
    const Bytes claims_raw =
        auth::base64url_decode(token.substr(first + 1, second - first - 1)).value();
    const json header = json::parse(header_raw.begin(), header_raw.end());
    const json claims = json::parse(claims_raw.begin(), claims_raw.end());
    CHECK(header["alg"] == "ES256");
    CHECK(header["kid"] == "KEYID12345");
    CHECK(header["typ"] == "JWT");
    CHECK(claims["iss"] == "issuer-uuid");
    CHECK(claims["aud"] == "appstoreconnect-v1");
    CHECK(claims["iat"] == 1700000000);
    CHECK(claims["exp"] == 1700000600);

    const Bytes signature = auth::base64url_decode(token.substr(second + 1)).value();
    CHECK(signature.size() == 64);
    CHECK(key.verify(crypto::as_bytes(std::string_view(token).substr(0, second)), signature));
}

TEST_CASE("RSA keys produce valid certificate requests", "[auth][identity]") {
    const auth::RsaKey key = auth::RsaKey::create();
    const std::string csr = auth::make_csr_pem(key, "WinXcode \"quoted\" name");
    CHECK(csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    CHECK(test::csr_signature_valid(csr));

    const Bytes certificate =
        auth::make_self_signed_certificate(key, "CN=Apple Development: Someone, OU=" + kTeam);
    const auth::CertificateInfo info = auth::describe_certificate(certificate);
    CHECK(info.common_name == "Apple Development: Someone");
    CHECK(info.organizational_unit == kTeam);
    CHECK(info.sha1_hex == crypto::to_hex(crypto::sha1(certificate), true));
    CHECK(info.not_after > std::chrono::system_clock::now());
    CHECK_FALSE(info.serial_hex.empty());

    CHECK(auth::certificate_matches_key(certificate, key));
    const auth::RsaKey other = auth::RsaKey::create();
    CHECK_FALSE(auth::certificate_matches_key(certificate, other));
    CHECK_THROWS_AS(auth::SigningIdentity(certificate, auth::RsaKey::create()), auth::KeyError);
    CHECK_THROWS_AS(auth::describe_certificate(crypto::random_bytes(64)), auth::KeyError);
}

TEST_CASE("the identity store keeps a certificate with its CNG key", "[auth][identity]") {
    const test::TempDir dir("winx_identity");
    auth::IdentityStore store(dir.path());
    const std::string account = "test-" + crypto::to_hex(crypto::random_bytes(4));

    CHECK_FALSE(store.load(account).has_value());
    const auth::IdentityStore::Pending pending = store.begin(account);
    CHECK(test::csr_signature_valid(pending.csr_pem));

    const auth::RsaKey ca = auth::RsaKey::create();
    const Bytes certificate =
        test::issue_certificate(pending.csr_pem, ca, "CN=Apple Development: T, OU=" + kTeam);
    {
        const auth::SigningIdentity identity =
            store.complete(account, pending, certificate, "CERT42");
        CHECK(identity.info().organizational_unit == kTeam);
    }

    const auto loaded = store.load(account);
    REQUIRE(loaded.has_value());
    CHECK(loaded->remote_id == "CERT42");
    CHECK(loaded->identity.certificate() == certificate);
    CHECK(loaded->identity.key().name() == pending.key_name);

    // A certificate for some other key must be refused.
    const auth::IdentityStore::Pending second = store.begin(account);
    const auth::RsaKey unrelated = auth::RsaKey::create();
    const Bytes wrong = auth::make_self_signed_certificate(unrelated, "CN=Wrong");
    CHECK_THROWS_AS(store.complete(account, second, wrong, "X"), auth::KeyError);
    auth::RsaKey::remove(second.key_name);

    store.remove(account);
    CHECK_FALSE(store.load(account).has_value());
    CHECK_THROWS_AS(auth::RsaKey::open(pending.key_name), auth::KeyError);
}

TEST_CASE("provisioning profiles are parsed out of their CMS envelope", "[auth][profile]") {
    const Bytes certificate = crypto::random_bytes(32);
    const plist::Value payload = plist::Dict{
        {"Name", "Dev Profile"},
        {"UUID", "ABCDEF00-0000-0000-0000-000000000001"},
        {"TeamName", "Test Org"},
        {"TeamIdentifier", plist::Array{kTeam}},
        {"ExpirationDate", plist::Date{800000000.0}},
        {"ProvisionedDevices", plist::Array{kUdid}},
        {"DeveloperCertificates", plist::Array{plist::Data{certificate}}},
        {"Entitlements",
         plist::Dict{{"application-identifier", kTeam + ".*"},
                     {"get-task-allow", true},
                     {"keychain-access-groups", plist::Array{kTeam + ".*"}}}}};
    const Bytes raw = test::wrap_in_cms(crypto::as_bytes(plist::to_xml(payload)));

    const auth::ProvisioningProfile profile = auth::ProvisioningProfile::parse(raw);
    CHECK(profile.name == "Dev Profile");
    CHECK(profile.team_id == kTeam);
    CHECK(profile.raw == raw);
    CHECK(profile.includes_device(kUdid));
    CHECK(profile.includes_device("00008110-001a2b3c4d5e6f78"));  // case-insensitive
    CHECK_FALSE(profile.includes_device("00008110-FFFFFFFFFFFFFFFF"));
    CHECK(profile.includes_certificate(certificate));
    CHECK_FALSE(profile.includes_certificate(crypto::random_bytes(32)));
    CHECK(profile.covers_bundle_id("com.example.app"));
    CHECK(profile.expired(std::chrono::system_clock::now()) ==
          (std::chrono::system_clock::now() >=
           std::chrono::system_clock::time_point(std::chrono::seconds(800000000 + 978307200))));

    const plist::Value entitlements = auth::make_entitlements(profile, "com.example.app");
    CHECK(entitlements.string_at("application-identifier") == kTeam + ".com.example.app");
    CHECK(entitlements.bool_at("get-task-allow") == true);
    CHECK(entitlements.find("keychain-access-groups")->as_array().front() ==
          plist::Value(kTeam + ".com.example.app"));

    CHECK_THROWS_AS(auth::ProvisioningProfile::parse(crypto::random_bytes(64)), auth::ProfileError);
    CHECK_THROWS_AS(auth::ProvisioningProfile::parse(test::wrap_in_cms(crypto::as_bytes("junk"))),
                    auth::ProfileError);
}

TEST_CASE("an explicit profile only covers its own bundle ID", "[auth][profile]") {
    const plist::Value payload = plist::Dict{
        {"Name", "Explicit"},
        {"TeamIdentifier", plist::Array{kTeam}},
        {"ProvisionsAllDevices", true},
        {"Entitlements", plist::Dict{{"application-identifier", kTeam + ".com.example.app"}}}};
    const auth::ProvisioningProfile profile = auth::ProvisioningProfile::parse(
        test::wrap_in_cms(crypto::as_bytes(plist::to_xml(payload))));
    CHECK(profile.includes_device("anything"));
    CHECK(profile.covers_bundle_id("com.example.app"));
    CHECK_FALSE(profile.covers_bundle_id("com.example.other"));
    CHECK_THROWS_AS(auth::make_entitlements(profile, "com.example.other"), auth::ProfileError);
}

TEST_CASE("the API-key transport builds authenticated requests", "[auth][api]") {
    std::vector<http::Request> seen;
    const http::Sender sender = [&](const http::Request& request) {
        seen.push_back(request);
        return json_response(200, {{"data", json::array()}});
    };
    auth::AscKeyTransport transport(auth::EcSigningKey::import_p8(test::generate_p8()), "KEYID",
                                    "ISSUER", sender, "https://api.example.test");

    transport.perform("GET", "/v1/devices", {{"filter[udid]", "A B"}, {"limit", "200"}}, nullptr);
    const json body = {{"data", {{"type", "devices"}}}};
    transport.perform("POST", "/v1/devices", {}, &body);

    REQUIRE(seen.size() == 2);
    CHECK(seen[0].method == "GET");
    CHECK(seen[0].url == "https://api.example.test/v1/devices?filter%5Budid%5D=A%20B&limit=200");
    const auto authorization = std::find_if(
        seen[0].headers.begin(), seen[0].headers.end(),
        [](const auto& header) { return header.first == "Authorization"; });
    REQUIRE(authorization != seen[0].headers.end());
    CHECK(authorization->second.starts_with("Bearer "));
    CHECK(std::count(authorization->second.begin(), authorization->second.end(), '.') == 2);
    CHECK(seen[0].body.empty());
    CHECK(seen[1].method == "POST");
    CHECK(seen[1].url == "https://api.example.test/v1/devices");
    CHECK(json::parse(seen[1].body) == body);
    // The token is reused while it is still fresh.
    CHECK(seen[1].headers.front().second == authorization->second);
}

TEST_CASE("the developer API follows pagination and maps errors", "[auth][api]") {
    class Scripted : public auth::Transport {
    public:
        std::vector<auth::Query> queries;
        http::Response perform(std::string_view, std::string_view path, const auth::Query& query,
                               const json*) override {
            queries.push_back(query);
            if (path == "/v1/certificates") {
                return json_response(
                    409, {{"errors",
                           {{{"status", "409"},
                             {"code", "ENTITY_ERROR"},
                             {"title", "There is a problem with the request entity"},
                             {"detail", "You already have a current Development certificate"}}}}});
            }
            const auto cursor = query_value(query, "cursor");
            if (!cursor) {
                return json_response(
                    200, {{"data", {{{"id", "D1"}, {"attributes", {{"udid", "U1"}}}}}},
                          {"links",
                           {{"next", "https://api.example.test/v1/devices?cursor=abc%3D&limit=1"}}}});
            }
            return json_response(
                200, {{"data", {{{"id", "D2"}, {"attributes", {{"udid", "U2"}, {"name", "Two"}}}}}},
                      {"links", json::object()}});
        }
    };
    const auto transport = std::make_shared<Scripted>();
    auth::DeveloperApi api(transport);

    const std::vector<auth::Device> devices = api.list_devices();
    REQUIRE(devices.size() == 2);
    CHECK(devices[0].id == "D1");
    CHECK(devices[1].udid == "U2");
    CHECK(devices[1].name == "Two");
    REQUIRE(transport->queries.size() == 2);
    CHECK(query_value(transport->queries[0], "limit") == "200");
    CHECK(query_value(transport->queries[1], "cursor") == "abc=");  // percent-decoded
    CHECK(query_value(transport->queries[1], "limit") == "200");

    try {
        api.create_certificate("csr");
        FAIL("expected an ApiError");
    } catch (const auth::ApiError& error) {
        CHECK(error.status() == 409);
        CHECK(error.code() == "ENTITY_ERROR");
        CHECK(std::string(error.what()).find("already have a current Development certificate") !=
              std::string::npos);
    }
}

TEST_CASE("the provisioner creates what is missing and reuses what exists", "[auth][provision]") {
    const test::TempDir dir("winx_provision");
    auth::IdentityStore identities(dir.path());
    const auto portal = std::make_shared<FakePortal>();
    auth::DeveloperApi api(portal);
    std::vector<std::string> log;
    auth::Provisioner provisioner(api, identities,
                                  [&](const std::string& line) { log.push_back(line); });

    auth::ProvisionRequest request;
    request.bundle_id = "com.example.hello";
    request.device_udid = kUdid;
    request.device_name = "Test iPhone";
    request.account = "acct-" + crypto::to_hex(crypto::random_bytes(4));

    // A similarly named bundle ID must not be mistaken for ours.
    portal->bundle_ids.push_back({{"type", "bundleIds"},
                                  {"id", "OTHER"},
                                  {"attributes", {{"identifier", "com.example.hello.widget"}}}});

    {
        const auth::ProvisionResult first = provisioner.provision(request);
        CHECK(portal->count("POST", "/v1/devices") == 1);
        CHECK(portal->count("POST", "/v1/bundleIds") == 1);
        CHECK(portal->count("POST", "/v1/certificates") == 1);
        CHECK(portal->count("POST", "/v1/profiles") == 1);
        CHECK(first.profile.includes_device(kUdid));
        CHECK(first.profile.includes_certificate(first.identity.certificate()));
        CHECK(first.identity.info().organizational_unit == kTeam);
        CHECK(first.entitlements.string_at("application-identifier") ==
              kTeam + ".com.example.hello");
        CHECK(first.entitlements.bool_at("get-task-allow") == true);
        CHECK(first.profile.name == auth::Provisioner::profile_name_for("com.example.hello"));
        CHECK_FALSE(log.empty());
    }

    SECTION("a second run reuses everything") {
        const auth::ProvisionResult second = provisioner.provision(request);
        CHECK(portal->count("POST", "/v1/devices") == 1);
        CHECK(portal->count("POST", "/v1/bundleIds") == 1);
        CHECK(portal->count("POST", "/v1/certificates") == 1);
        CHECK(portal->count("POST", "/v1/profiles") == 1);
        CHECK(second.profile.includes_device(kUdid));
    }
    SECTION("a new device replaces the profile but keeps the certificate") {
        request.device_udid = "00008120-00AABBCCDDEEFF00";
        const auth::ProvisionResult second = provisioner.provision(request);
        CHECK(portal->count("POST", "/v1/devices") == 2);
        CHECK(portal->count("POST", "/v1/certificates") == 1);
        CHECK(portal->count("POST", "/v1/profiles") == 2);
        CHECK(portal->profiles.size() == 1);
        CHECK(second.profile.includes_device(request.device_udid));
    }
    SECTION("a certificate revoked on Apple's side is replaced") {
        portal->certificates.clear();
        const auth::ProvisionResult second = provisioner.provision(request);
        CHECK(portal->count("POST", "/v1/certificates") == 2);
        CHECK(portal->count("POST", "/v1/profiles") == 2);
        CHECK(second.profile.includes_certificate(second.identity.certificate()));
    }
    SECTION("a disabled device is reported rather than re-registered") {
        portal->devices[0]["attributes"]["status"] = "DISABLED";
        CHECK_THROWS_AS(provisioner.provision(request), auth::ApiError);
    }

    identities.remove(request.account);
}

TEST_CASE("sign-in state round-trips through the encrypted store", "[auth][store]") {
    const test::TempDir dir("winx_authstore");
    const auth::AuthStore store(dir.path());
    CHECK(store.load().mode == auth::AuthState::Mode::None);

    auth::AuthState state;
    state.mode = auth::AuthState::Mode::AppleId;
    state.apple_id = "user@example.com";
    state.adsid = "000123-08-abcdef";
    state.xcode_token = "secret-token";
    state.token_expiry_ms = 1234567890123;
    state.team_id = kTeam;
    store.save(state);

    const auto raw = read_text_file(dir.path() / "auth.bin");
    REQUIRE(raw.has_value());
    CHECK(raw->find("secret-token") == std::string::npos);  // not stored in the clear

    const auth::AuthState loaded = store.load();
    CHECK(loaded.mode == auth::AuthState::Mode::AppleId);
    CHECK(loaded.xcode_token == "secret-token");
    CHECK(loaded.token_expiry_ms == 1234567890123);
    CHECK(loaded.account() == kTeam);

    store.clear();
    CHECK(store.load().mode == auth::AuthState::Mode::None);
    const http::Client client;
    CHECK_THROWS_AS(auth::make_transport(store.load(), store, client), auth::NotSignedIn);
}
