#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <deque>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "support.hpp"
#include "winx/apple_id.hpp"
#include "winx/base64.hpp"
#include "winx/identity.hpp"
#include "winx/plist.hpp"
#include "winx/srp.hpp"

using namespace winx;
using auth::BigUInt;
using auth::json;
using crypto::Bytes;
using crypto::HashAlgorithm;
using crypto::Hasher;

namespace {

BigUInt random_big(std::size_t bytes) { return BigUInt::from_bytes(crypto::random_bytes(bytes)); }

std::optional<std::string> header_value(const http::Request& request, std::string_view name) {
    for (const auto& [key, value] : request.headers) {
        if (key == name) return value;
    }
    return std::nullopt;
}

http::Response plist_response(const plist::Value& value, int status = 200) {
    http::Response response;
    response.status = status;
    response.body = plist::to_xml(value);
    return response;
}

http::Response json_response(const json& value, int status = 200) {
    http::Response response;
    response.status = status;
    response.body = value.dump();
    return response;
}

class FixedAnisette : public auth::AnisetteProvider {
public:
    int fetches = 0;
    auth::AnisetteData fetch() override {
        ++fetches;
        auth::AnisetteData data;
        data.one_time_password = "OTP";
        data.machine_id = "MACHINE";
        data.routing_info = "17106176";
        data.local_user_id = "LOCALUSER";
        data.device_id = "DEVICE-ID";
        data.client_info = "<MacBookPro13,2> <macOS;13.1;22C65> <test>";
        data.user_agent = "akd/1.0";
        data.client_time = "2026-01-01T00:00:00Z";
        return data;
    }
};

// The server half of SRP-6a and of the GrandSlam envelope, written from the
// server's point of view (S = (A * v^u)^b) so that it checks the client's
// arithmetic rather than repeating it.
class FakeGrandSlam {
public:
    std::string apple_id = "user@example.com";
    std::string password = "correct horse battery";
    bool hex_protocol = true;
    std::string second_factor;  // value for Status.au, empty for none
    std::string adsid = "000123-08-0a1b2c3d";
    std::string idms_token = "IDMS-TOKEN";
    Bytes session_key = crypto::random_bytes(32);
    Bytes cookie = {'c', 'o', 'o', 'k', 'i', 'e'};
    std::vector<std::string> operations;
    std::vector<http::Request> other_requests;

    http::Response handle(const http::Request& request) {
        if (!request.url.ends_with("/grandslam/GsService2")) {
            other_requests.push_back(request);
            if (request.url.ends_with("/validate")) {
                const bool ok = header_value(request, "security-code") == "123456";
                return plist_response(plist::Dict{{"ec", ok ? 0 : -21669},
                                                  {"em", ok ? "" : "Incorrect verification code"}});
            }
            return plist_response(plist::Dict{});
        }
        const plist::Value body = plist::parse(crypto::as_bytes(request.body));
        const plist::Value& parameters = *body.find("Request");
        const std::string operation = parameters.string_at("o").value_or("");
        operations.push_back(operation);
        saw_cpd = parameters.find("cpd") != nullptr &&
                  parameters.find("cpd")->string_at("X-Apple-I-MD") == "OTP";

        if (operation == "init") return init(parameters);
        if (operation == "complete") return complete(parameters);
        if (operation == "apptokens") return app_tokens(parameters);
        return status(-1, "unknown operation");
    }

    bool saw_cpd = false;

private:
    static http::Response status(std::int64_t code, const std::string& message) {
        return plist_response(plist::Dict{
            {"Response", plist::Dict{{"Status", plist::Dict{{"ec", code}, {"em", message}}}}}});
    }

    http::Response init(const plist::Value& parameters) {
        const auth::SrpGroup& group = auth::srp_group_2048();
        client_public_ = parameters.data_at("A2k")->bytes;
        // The client hashes the salt without leading zero bytes (as existing
        // clients do); keep the two sides unambiguous.
        salt_[0] |= 0x80;

        const Bytes key = auth::derive_gsa_password(password, salt_, iterations_, hex_protocol);
        const Bytes inner =
            Hasher(HashAlgorithm::Sha256).update(std::string_view(":")).update(key).finish();
        const BigUInt x = BigUInt::from_bytes(
            Hasher(HashAlgorithm::Sha256).update(salt_).update(inner).finish());
        verifier_ = group.generator.mod_pow(x, group.modulus);

        const BigUInt k = BigUInt::from_bytes(Hasher(HashAlgorithm::Sha256)
                                                  .update(group.modulus.to_bytes())
                                                  .update(group.generator.to_bytes(group.width))
                                                  .finish());
        private_ = random_big(32);
        server_public_ =
            ((k * verifier_) + group.generator.mod_pow(private_, group.modulus)) % group.modulus;

        return plist_response(plist::Dict{
            {"Response",
             plist::Dict{{"Status", plist::Dict{{"ec", 0}}},
                         {"sp", hex_protocol ? "s2k_fo" : "s2k"},
                         {"s", plist::Data{salt_}},
                         {"i", iterations_},
                         {"B", plist::Data{server_public_.to_bytes()}},
                         {"c", "init-cookie"}}}});
    }

    http::Response complete(const plist::Value& parameters) {
        const auth::SrpGroup& group = auth::srp_group_2048();
        if (parameters.string_at("c") != "init-cookie") return status(-1, "bad cookie");

        const BigUInt A = BigUInt::from_bytes(client_public_);
        const BigUInt u = BigUInt::from_bytes(Hasher(HashAlgorithm::Sha256)
                                                  .update(A.to_bytes(group.width))
                                                  .update(server_public_.to_bytes(group.width))
                                                  .finish());
        const BigUInt S =
            ((A * verifier_.mod_pow(u, group.modulus)) % group.modulus)
                .mod_pow(private_, group.modulus);
        const Bytes K = crypto::sha256(S.to_bytes());

        Bytes mask = crypto::sha256(group.modulus.to_bytes());
        const Bytes hg = crypto::sha256(group.generator.to_bytes(group.width));
        for (std::size_t i = 0; i < mask.size(); ++i) mask[i] ^= hg[i];
        const Bytes expected = Hasher(HashAlgorithm::Sha256)
                                   .update(mask)
                                   .update(crypto::sha256(crypto::as_bytes(apple_id)))
                                   .update(salt_)
                                   .update(A.to_bytes())
                                   .update(server_public_.to_bytes())
                                   .update(K)
                                   .finish();
        const plist::Data* proof = parameters.data_at("M1");
        if (!proof || proof->bytes != expected) {
            return status(-22406, "Your Apple ID or password was incorrect.");
        }
        const Bytes server_proof =
            Hasher(HashAlgorithm::Sha256).update(A.to_bytes()).update(expected).update(K).finish();

        const plist::Value spd = plist::Dict{{"adsid", adsid},
                                             {"GsIdmsToken", idms_token},
                                             {"sk", plist::Data{session_key}},
                                             {"c", plist::Data{cookie}}};
        const Bytes key = crypto::hmac_sha256(K, crypto::as_bytes("extra data key:"));
        Bytes iv = crypto::hmac_sha256(K, crypto::as_bytes("extra data iv:"));
        iv.resize(16);
        const Bytes encrypted =
            crypto::aes_cbc_encrypt(key, iv, crypto::as_bytes(plist::to_xml(spd)));

        plist::Dict state{{"ec", 0}};
        if (!second_factor.empty()) state.set("au", second_factor);
        return plist_response(plist::Dict{
            {"Response", plist::Dict{{"Status", std::move(state)},
                                     {"M2", plist::Data{server_proof}},
                                     {"spd", plist::Data{encrypted}}}}});
    }

    http::Response app_tokens(const plist::Value& parameters) {
        const std::string app = "com.apple.gs.xcode.auth";
        const Bytes checksum =
            crypto::hmac_sha256(session_key, crypto::as_bytes("apptokens" + adsid + app));
        const plist::Data* sent = parameters.data_at("checksum");
        if (!sent || sent->bytes != checksum || parameters.string_at("u") != adsid ||
            parameters.string_at("t") != idms_token) {
            return status(-1, "bad checksum");
        }
        const plist::Value tokens = plist::Dict{
            {"t", plist::Dict{{app, plist::Dict{{"token", "XCODE-TOKEN"},
                                               {"expiry", 1999999999000},
                                               {"duration", 3600}}}}}};
        const Bytes iv = crypto::random_bytes(16);
        const Bytes version{'X', 'Y', 'Z'};
        const crypto::GcmSealed sealed = crypto::aes_gcm_encrypt(
            session_key, iv, crypto::as_bytes(plist::to_xml(tokens)), version);
        Bytes envelope = version;
        envelope.insert(envelope.end(), iv.begin(), iv.end());
        envelope.insert(envelope.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
        envelope.insert(envelope.end(), sealed.tag.begin(), sealed.tag.end());
        return plist_response(plist::Dict{
            {"Response",
             plist::Dict{{"Status", plist::Dict{{"ec", 0}}}, {"et", plist::Data{envelope}}}}});
    }

    Bytes salt_ = crypto::random_bytes(16);
    std::int64_t iterations_ = 1000;
    Bytes client_public_;
    BigUInt verifier_;
    BigUInt private_;
    BigUInt server_public_;
};

class ScriptedChannel : public auth::TextChannel {
public:
    ScriptedChannel(std::deque<std::string> incoming, std::vector<std::string>* sent)
        : incoming_(std::move(incoming)), sent_(sent) {}
    void send(std::string_view text) override { sent_->emplace_back(text); }
    std::string receive() override {
        if (incoming_.empty()) throw http::HttpError("script exhausted");
        std::string next = std::move(incoming_.front());
        incoming_.pop_front();
        return next;
    }

private:
    std::deque<std::string> incoming_;
    std::vector<std::string>* sent_;
};

}  // namespace

TEST_CASE("BigUInt converts to and from bytes and hex", "[bigint]") {
    CHECK(BigUInt().is_zero());
    CHECK(BigUInt(0).to_bytes().empty());
    CHECK(BigUInt(0x0102030405ULL).to_bytes() == Bytes{1, 2, 3, 4, 5});
    CHECK(BigUInt(1).to_bytes(4) == Bytes{0, 0, 0, 1});
    CHECK(BigUInt::from_bytes(Bytes{0, 0, 1, 0}) == BigUInt(256));
    CHECK(BigUInt::from_hex("ff FF") == BigUInt(65535));
    CHECK(BigUInt::from_hex("123") == BigUInt(0x123));
    CHECK(BigUInt(1ULL << 32).bit_length() == 33);
    CHECK(BigUInt(5).bit(0));
    CHECK_FALSE(BigUInt(5).bit(1));
    CHECK(BigUInt(5).bit(2));
    CHECK_THROWS_AS(BigUInt::from_hex("xyz"), std::invalid_argument);
    CHECK(BigUInt(3) < BigUInt(1ULL << 40));
    CHECK(BigUInt(1ULL << 40) > BigUInt(0xFFFFFFFFULL));
}

TEST_CASE("BigUInt arithmetic satisfies the division identity", "[bigint]") {
    CHECK(BigUInt(0xFFFFFFFFULL) + BigUInt(1) == BigUInt(1ULL << 32));
    CHECK(BigUInt(1ULL << 32) - BigUInt(1) == BigUInt(0xFFFFFFFFULL));
    CHECK(BigUInt(0xFFFFFFFFULL) * BigUInt(0xFFFFFFFFULL) == BigUInt(0xFFFFFFFE00000001ULL));
    CHECK_THROWS_AS(BigUInt(1) - BigUInt(2), std::domain_error);
    CHECK_THROWS_AS(BigUInt(1) / BigUInt(0), std::domain_error);
    CHECK(BigUInt(4).mod_pow(BigUInt(13), BigUInt(497)) == BigUInt(445));
    CHECK(BigUInt(7).mod_pow(BigUInt(0), BigUInt(13)) == BigUInt(1));

    // a == q * b + r and r < b, across operand sizes that exercise the
    // single-limb path, the Knuth D path and its rare add-back correction.
    for (int round = 0; round < 400; ++round) {
        const BigUInt a = random_big(1 + static_cast<std::size_t>(round % 70));
        BigUInt b = random_big(1 + static_cast<std::size_t>((round * 7) % 40));
        if (b.is_zero()) b = BigUInt(3);
        const auto [q, r] = BigUInt::divmod(a, b);
        REQUIRE(q * b + r == a);
        REQUIRE(r < b);
    }
    // Divisors with a saturated top limb stress the quotient estimate.
    const BigUInt dividend = BigUInt::from_hex("7fffffff 80000000 00000000 00000000");
    const BigUInt divisor = BigUInt::from_hex("7fffffff 80000000 00000001");
    const auto [q, r] = BigUInt::divmod(dividend, divisor);
    CHECK(q * divisor + r == dividend);
    CHECK(r < divisor);
}

TEST_CASE("the SRP group is the RFC 5054 2048-bit safe prime", "[srp]") {
    const auth::SrpGroup& group = auth::srp_group_2048();
    const BigUInt& N = group.modulus;
    CHECK(N.bit_length() == 2048);
    CHECK(N.to_bytes().size() == group.width);
    // Fermat checks for N and for (N-1)/2; a mistyped constant would fail both.
    const BigUInt one(1);
    CHECK(BigUInt(2).mod_pow(N - one, N) == one);
    CHECK(BigUInt(3).mod_pow(N - one, N) == one);
    const BigUInt half = (N - one) / BigUInt(2);
    CHECK(BigUInt(3).mod_pow(half - one, half) == one);
}

TEST_CASE("GrandSlam password derivation follows the selected protocol", "[srp]") {
    const Bytes salt = crypto::from_hex("000102030405060708090a0b0c0d0e0f").value();
    const Bytes digest = crypto::sha256(crypto::as_bytes("hunter2"));
    CHECK(auth::derive_gsa_password("hunter2", salt, 50, false) ==
          crypto::pbkdf2_hmac_sha256(digest, salt, 50, 32));
    const std::string hex = crypto::to_hex(digest);
    CHECK(auth::derive_gsa_password("hunter2", salt, 50, true) ==
          crypto::pbkdf2_hmac_sha256(crypto::as_bytes(hex), salt, 50, 32));
}

TEST_CASE("GrandSlam sign-in completes SRP and decrypts the session", "[grandslam]") {
    FakeGrandSlam server;
    const auto anisette = std::make_shared<FixedAnisette>();
    std::vector<http::Request> requests;
    auth::GrandSlamClient client(
        [&](const http::Request& request) {
            requests.push_back(request);
            return server.handle(request);
        },
        anisette, {Bytes{1, 2, 3}}, "https://gsa.example.test");

    SECTION("with the s2k_fo protocol, then fetching an Xcode token") {
        const auto result = client.login(server.apple_id, server.password);
        CHECK(result.second_factor == auth::SecondFactor::None);
        CHECK(result.session.adsid == server.adsid);
        CHECK(result.session.idms_token == server.idms_token);
        CHECK(result.session.session_key == server.session_key);
        CHECK(result.session.cookie == server.cookie);
        CHECK(server.operations == std::vector<std::string>{"init", "complete"});
        CHECK(server.saw_cpd);

        REQUIRE(requests.size() == 2);
        CHECK(requests[0].url == "https://gsa.example.test/grandslam/GsService2");
        CHECK(requests[0].pinned_roots.size() == 1);
        // The password must never appear on the wire.
        for (const http::Request& request : requests) {
            CHECK(request.body.find(server.password) == std::string::npos);
        }

        const auth::XcodeToken token = client.fetch_xcode_token(result.session);
        CHECK(token.token == "XCODE-TOKEN");
        CHECK(token.expiry_ms == 1999999999000);
    }
    SECTION("with the s2k protocol") {
        server.hex_protocol = false;
        const auto result = client.login(server.apple_id, server.password);
        CHECK(result.session.adsid == server.adsid);
    }
    SECTION("a wrong password is rejected with Apple's error") {
        try {
            client.login(server.apple_id, "not the password");
            FAIL("expected AppleIdError");
        } catch (const auth::AppleIdError& error) {
            CHECK(error.code() == -22406);
            CHECK(std::string(error.what()).find("incorrect") != std::string::npos);
        }
    }
    SECTION("a trusted-device code is requested and validated") {
        server.second_factor = "trustedDeviceSecondaryAuth";
        const auto result = client.login(server.apple_id, server.password);
        CHECK(result.second_factor == auth::SecondFactor::TrustedDevice);

        client.request_trusted_device_code(result.session);
        REQUIRE(server.other_requests.size() == 1);
        CHECK(server.other_requests[0].url == "https://gsa.example.test/auth/verify/trusteddevice");
        const std::string identity = server.adsid + ":" + server.idms_token;
        CHECK(header_value(server.other_requests[0], "X-Apple-Identity-Token") ==
              base64_encode(crypto::as_bytes(identity)));
        CHECK(header_value(server.other_requests[0], "X-Apple-I-MD") == "OTP");

        CHECK_THROWS_AS(client.submit_trusted_device_code(result.session, "000000"),
                        auth::AppleIdError);
        CHECK_NOTHROW(client.submit_trusted_device_code(result.session, "123456"));
    }
    SECTION("an SMS code is requested and submitted") {
        server.second_factor = "secondaryAuth";
        const auto result = client.login(server.apple_id, server.password);
        CHECK(result.second_factor == auth::SecondFactor::Sms);

        client.request_sms_code(result.session);
        client.submit_sms_code(result.session, "654321");
        REQUIRE(server.other_requests.size() == 2);
        CHECK(server.other_requests[0].method == "PUT");
        CHECK(json::parse(server.other_requests[0].body)["mode"] == "sms");
        CHECK(server.other_requests[1].method == "POST");
        CHECK(json::parse(server.other_requests[1].body)["securityCode"]["code"] == "654321");
    }
}

TEST_CASE("remote anisette provisions once and then reuses the identity", "[anisette]") {
    const test::TempDir dir("winx_anisette");
    std::vector<http::Request> requests;
    std::vector<std::string> sent;
    std::string channel_url;
    std::string finish_body;
    int sessions = 0;
    bool reject_headers_once = false;

    const http::Sender sender = [&](const http::Request& request) -> http::Response {
        requests.push_back(request);
        if (request.url == "https://ani.example.test/v3/client_info") {
            return json_response(
                {{"client_info", "<Mac> <test>"}, {"user_agent", "akd/1.0 CFNetwork/808.1.4"}});
        }
        if (request.url.ends_with("/GsService2/lookup")) {
            return plist_response(plist::Dict{
                {"urls",
                 plist::Dict{{"midStartProvisioning", "https://gsa.example.test/start"},
                             {"midFinishProvisioning", "https://gsa.example.test/finish"}}}});
        }
        if (request.url == "https://gsa.example.test/start") {
            return plist_response(plist::Dict{{"Response", plist::Dict{{"spim", "SPIM"}}}});
        }
        if (request.url == "https://gsa.example.test/finish") {
            finish_body = request.body;
            return plist_response(
                plist::Dict{{"Response", plist::Dict{{"ptm", "PTM"}, {"tk", "TK"}}}});
        }
        if (request.url == "https://ani.example.test/v3/get_headers") {
            if (reject_headers_once) {
                reject_headers_once = false;
                return json_response({{"result", "GetHeadersError"}, {"message", "stale"}});
            }
            return json_response({{"result", "Headers"},
                                  {"X-Apple-I-MD", "OTP1"},
                                  {"X-Apple-I-MD-M", "MID1"},
                                  {"X-Apple-I-MD-RINFO", "17106176"}});
        }
        return json_response(json::object(), 404);
    };
    const auth::ChannelFactory channels =
        [&](const std::string& url) -> std::unique_ptr<auth::TextChannel> {
        ++sessions;
        channel_url = url;
        return std::make_unique<ScriptedChannel>(
            std::deque<std::string>{
                R"({"result":"GiveIdentifier"})", R"({"result":"GiveStartProvisioningData"})",
                R"({"result":"GiveEndProvisioningData","cpim":"CPIM"})",
                R"({"result":"ProvisioningSuccess","adi_pb":"QURJLVBC"})"},
            &sent);
    };

    auth::RemoteAnisetteProvider::Options options;
    options.server_url = "https://ani.example.test/";
    options.state_file = dir.path() / "anisette.bin";
    options.apple_roots = {Bytes{9}};

    auth::AnisetteData first;
    {
        auth::RemoteAnisetteProvider provider(options, sender, channels);
        first = provider.fetch();
    }
    CHECK(sessions == 1);
    CHECK(channel_url == "wss://ani.example.test/v3/provisioning_session");
    CHECK(first.one_time_password == "OTP1");
    CHECK(first.machine_id == "MID1");
    CHECK(first.routing_info == "17106176");
    CHECK(first.client_info == "<Mac> <test>");
    CHECK(first.device_id.size() == 36);
    CHECK(finish_body.find("<string>CPIM</string>") != std::string::npos);

    REQUIRE(sent.size() == 3);
    const Bytes identifier =
        base64_decode(json::parse(sent[0])["identifier"].get<std::string>()).value();
    CHECK(identifier.size() == 16);
    CHECK(json::parse(sent[1])["spim"] == "SPIM");
    CHECK(json::parse(sent[2])["ptm"] == "PTM");
    CHECK(json::parse(sent[2])["tk"] == "TK");
    CHECK(first.local_user_id ==
          base64_encode(crypto::as_bytes(crypto::to_hex(crypto::sha256(identifier), true))));

    // Requests to Apple are pinned to Apple's root; requests to the anisette
    // server use ordinary Windows trust.
    for (const http::Request& request : requests) {
        const bool to_apple = request.url.find("gsa.") != std::string::npos;
        CHECK(request.pinned_roots.size() == (to_apple ? 1u : 0u));
    }
    const auto headers = first.headers();
    CHECK(std::find(headers.begin(), headers.end(),
                    std::pair<std::string, std::string>{"X-Apple-I-MD-M", "MID1"}) != headers.end());

    SECTION("a new provider instance reuses the stored identity") {
        auth::RemoteAnisetteProvider provider(options, sender, channels);
        const auth::AnisetteData second = provider.fetch();
        CHECK(sessions == 1);
        CHECK(second.device_id == first.device_id);
        CHECK(second.local_user_id == first.local_user_id);
    }
    SECTION("an identity the server rejects is provisioned again") {
        reject_headers_once = true;
        auth::RemoteAnisetteProvider provider(options, sender, channels);
        const auth::AnisetteData second = provider.fetch();
        CHECK(sessions == 2);
        CHECK(second.device_id == first.device_id);  // same identifier, new machine data
        CHECK(second.one_time_password == "OTP1");
    }
    SECTION("reset forgets the identity") {
        auth::RemoteAnisetteProvider provider(options, sender, channels);
        provider.reset();
        const auth::AnisetteData second = provider.fetch();
        CHECK(sessions == 2);
        CHECK(second.device_id != first.device_id);
    }
}

TEST_CASE("the Xcode transport tunnels requests the way Xcode does", "[xcode]") {
    const auto anisette = std::make_shared<FixedAnisette>();
    std::vector<http::Request> requests;
    const http::Sender sender = [&](const http::Request& request) {
        requests.push_back(request);
        return json_response({{"data", json::array()}});
    };
    auth::XcodeTransport transport({"ADSID", "TOKEN", "TEAM123456"}, anisette, sender,
                                   "https://ds.example.test/services");

    transport.perform("GET", "/v1/devices", {{"filter[udid]", "A B"}}, nullptr);
    const json body = {
        {"data", {{"type", "devices"}, {"attributes", {{"name", "Phone"}, {"udid", "U"}}}}}};
    transport.perform("POST", "/v1/devices", {}, &body);
    transport.perform("DELETE", "/v1/profiles/P1", {}, nullptr);

    REQUIRE(requests.size() == 3);
    CHECK(requests[0].method == "POST");
    CHECK(requests[0].url == "https://ds.example.test/services/v1/devices");
    CHECK(header_value(requests[0], "X-HTTP-Method-Override") == "GET");
    CHECK(header_value(requests[0], "X-Apple-GS-Token") == "TOKEN");
    CHECK(header_value(requests[0], "X-Apple-I-Identity-Id") == "ADSID");
    CHECK(header_value(requests[0], "X-Apple-I-MD") == "OTP");
    CHECK(header_value(requests[0], "Content-Type") == "application/vnd.api+json");
    CHECK(json::parse(requests[0].body)["urlEncodedQueryParams"] ==
          "filter%5Budid%5D=A%20B&teamId=TEAM123456");

    CHECK_FALSE(header_value(requests[1], "X-HTTP-Method-Override").has_value());
    const json sent = json::parse(requests[1].body);
    CHECK(sent["data"]["attributes"]["teamId"] == "TEAM123456");
    CHECK(sent["data"]["attributes"]["name"] == "Phone");

    CHECK(header_value(requests[2], "X-HTTP-Method-Override") == "DELETE");
    CHECK(json::parse(requests[2].body)["urlEncodedQueryParams"] == "teamId=TEAM123456");
}

TEST_CASE("developer teams are listed for an Apple ID session", "[xcode]") {
    FixedAnisette anisette;
    http::Request seen;
    const http::Sender sender = [&](const http::Request& request) {
        seen = request;
        return plist_response(plist::Dict{
            {"resultCode", 0},
            {"teams",
             plist::Array{plist::Dict{{"teamId", "TEAM123456"},
                                      {"name", "Jane Doe (Personal Team)"},
                                      {"type", "Individual"},
                                      {"xcodeFreeOnly", true}},
                          plist::Dict{{"teamId", "ORG9876543"},
                                      {"name", "Example Org"},
                                      {"type", "Company/Organization"}}}}});
    };
    const std::vector<auth::Team> teams = auth::XcodeTransport::list_teams(
        {"ADSID", "TOKEN", ""}, anisette, sender, "https://ds.example.test/services");

    REQUIRE(teams.size() == 2);
    CHECK(teams[0].id == "TEAM123456");
    CHECK(teams[0].free);
    CHECK(teams[1].name == "Example Org");
    CHECK_FALSE(teams[1].free);
    CHECK(seen.url == "https://ds.example.test/services/QH65B2/listTeams.action?clientId=XABBG36SBA");
    CHECK(seen.body.find("<key>protocolVersion</key>") != std::string::npos);
    CHECK(header_value(seen, "X-Apple-GS-Token") == "TOKEN");
}

// The two cases below talk to real servers and are hidden from normal runs.
// Run them with: winx_tests "[live]"
TEST_CASE("live: gsa.apple.com is reachable only with Apple's root pinned", "[.live]") {
    const test::TempDir dir("winx_live_certs");
    const http::Client client;
    const auth::AppleCertificates certificates =
        auth::load_apple_certificates(client.sender(), dir.path());
    CHECK(auth::is_apple_root_ca(certificates.root));
    CHECK(auth::describe_certificate(certificates.wwdr_g3).common_name ==
          "Apple Worldwide Developer Relations Certification Authority");

    http::Request request;
    request.url = "https://gsa.apple.com/grandslam/GsService2/lookup";
    // The endpoint answers 404 without a client-info header.
    request.headers = {{"X-MMe-Client-Info",
                        "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 "
                        "(com.apple.akd/1.0)>"}};

    // Windows does not trust Apple's private root on its own.
    CHECK_THROWS_AS(client.send(request), http::HttpError);

    request.pinned_roots = {certificates.root};
    const http::Response response = client.send(request);
    CHECK(response.status == 200);
    const plist::Value lookup = plist::parse(crypto::as_bytes(response.body));
    REQUIRE(lookup.find("urls") != nullptr);
    CHECK(lookup.find("urls")->string_at("midStartProvisioning").has_value());
    CHECK(lookup.find("urls")->string_at("midFinishProvisioning").has_value());

    // Pinning some other root must fail before anything is sent.
    const auth::RsaKey key = auth::RsaKey::create();
    request.pinned_roots = {auth::make_self_signed_certificate(key, "CN=Not Apple")};
    CHECK_THROWS_AS(client.send(request), http::HttpError);
}

TEST_CASE("live: the default anisette server speaks the expected protocol", "[.live]") {
    const http::Client client;
    http::Request info;
    info.url = "https://ani.sidestore.io/v3/client_info";
    const json client_info = json::parse(client.send(info).body);
    CHECK(client_info.contains("client_info"));
    CHECK(client_info.contains("user_agent"));

    http::WebSocket socket =
        http::WebSocket::connect(client, "wss://ani.sidestore.io/v3/provisioning_session");
    const json first = json::parse(socket.receive_text());
    CHECK(first["result"] == "GiveIdentifier");
}

TEST_CASE("Apple's root certificate is recognised by fingerprint only", "[apple]") {
    CHECK_FALSE(auth::is_apple_root_ca(crypto::random_bytes(1215)));
    CHECK(auth::apple_id_warning().find("does not document or sanction") != std::string_view::npos);
    CHECK(auth::api_key_warning().find("device slots") != std::string_view::npos);

    // A download that does not match the pinned fingerprint is rejected and
    // nothing is cached.
    const test::TempDir dir("winx_applecerts");
    const http::Sender forged = [](const http::Request&) {
        http::Response response;
        response.status = 200;
        response.body = "not apple's certificate";
        return response;
    };
    CHECK_THROWS_AS(auth::load_apple_certificates(forged, dir.path()), auth::AppleIdError);
    CHECK(std::filesystem::is_empty(dir.path()));
}
