#include "winx/apple_id.hpp"

#include <algorithm>
#include <format>

#include "winx/base64.hpp"
#include "winx/srp.hpp"

namespace winx::auth {
namespace {

constexpr const char* kXcodeApp = "com.apple.gs.xcode.auth";
constexpr const char* kXcodeVersion = "11.2 (11B41)";

crypto::Bytes data_or_empty(const plist::Value& dict, std::string_view key) {
    const plist::Data* data = dict.data_at(key);
    return data ? data->bytes : crypto::Bytes{};
}

// Raises on a non-zero "ec" in a Status dictionary.
void check_status(const plist::Value& status) {
    const std::int64_t code = status.int_at("ec").value_or(0);
    if (code == 0) return;
    const std::string message = status.string_at("em").value_or("unknown error");
    throw AppleIdError(std::format("Apple rejected the request: {} ({})", message, code), code);
}

}  // namespace

GrandSlamClient::GrandSlamClient(http::Sender sender, std::shared_ptr<AnisetteProvider> anisette,
                                 std::vector<crypto::Bytes> apple_roots, std::string base_url)
    : sender_(std::move(sender)),
      anisette_(std::move(anisette)),
      apple_roots_(std::move(apple_roots)),
      base_url_(std::move(base_url)) {}

http::Response GrandSlamClient::send(http::Request request) {
    request.pinned_roots = apple_roots_;
    return sender_(request);
}

plist::Value GrandSlamClient::service_request(plist::Dict parameters) {
    const AnisetteData anisette = anisette_->fetch();

    plist::Dict cpd{{"bootstrap", true},
                    {"icscrec", true},
                    {"pbe", false},
                    {"prkgen", true},
                    {"svct", "iCloud"},
                    {"loc", anisette.locale}};
    for (const auto& [name, value] : anisette.headers()) {
        if (name != "X-MMe-Client-Info") cpd.set(name, value);
    }

    plist::Dict request_dict{{"cpd", std::move(cpd)}};
    for (const auto& [key, value] : parameters.items()) request_dict.set(key, value);
    const plist::Value body = plist::Dict{{"Header", plist::Dict{{"Version", "1.0.1"}}},
                                          {"Request", std::move(request_dict)}};

    http::Request request;
    request.method = "POST";
    request.url = base_url_ + "/grandslam/GsService2";
    request.headers = {{"Content-Type", "text/x-xml-plist"},
                       {"Accept", "*/*"},
                       {"User-Agent", anisette.user_agent.empty() ? "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
                                                                   : anisette.user_agent},
                       {"X-MMe-Client-Info", anisette.client_info}};
    request.body = plist::to_xml(body);

    const http::Response response = send(std::move(request));
    if (!response.ok()) {
        throw AppleIdError(std::format("Apple sign-in service returned HTTP {}", response.status));
    }
    const plist::Value reply = plist::parse(crypto::as_bytes(response.body));
    const plist::Value* payload = reply.find("Response");
    if (!payload || !payload->is<plist::Dict>()) {
        throw AppleIdError("Apple sign-in service returned an unexpected reply");
    }
    if (const plist::Value* status = payload->find("Status")) check_status(*status);
    return *payload;
}

GrandSlamClient::LoginResult GrandSlamClient::login(std::string_view apple_id,
                                                    std::string_view password) {
    SrpClient srp{std::string(apple_id)};

    const plist::Value init = service_request(
        {{"A2k", plist::Data{srp.public_value()}},
         {"ps", plist::Array{"s2k", "s2k_fo"}},
         {"u", std::string(apple_id)},
         {"o", "init"}});

    const std::string protocol = init.string_at("sp").value_or("");
    if (protocol != "s2k" && protocol != "s2k_fo") {
        throw AppleIdError("Apple selected an unsupported password protocol: " + protocol);
    }
    const crypto::Bytes salt = data_or_empty(init, "s");
    const crypto::Bytes server_public = data_or_empty(init, "B");
    const std::int64_t iterations = init.int_at("i").value_or(0);
    const plist::Value* cookie = init.find("c");
    if (salt.empty() || server_public.empty() || iterations <= 0 || !cookie) {
        throw AppleIdError("Apple's sign-in challenge was incomplete");
    }

    crypto::Bytes password_key = derive_gsa_password(
        password, salt, static_cast<std::uint64_t>(iterations), protocol == "s2k_fo");
    crypto::Bytes proof;
    try {
        proof = srp.process_challenge(password_key, salt, server_public);
    } catch (const SrpError& error) {
        throw AppleIdError(error.what());
    }
    std::fill(password_key.begin(), password_key.end(), std::uint8_t{0});

    const plist::Value complete = service_request(
        {{"c", *cookie}, {"M1", plist::Data{proof}}, {"u", std::string(apple_id)}, {"o", "complete"}});

    if (!srp.verify_server(data_or_empty(complete, "M2"))) {
        throw AppleIdError("the sign-in server failed to prove it knows the password");
    }

    const crypto::Bytes encrypted = data_or_empty(complete, "spd");
    if (encrypted.empty()) throw AppleIdError("Apple's sign-in reply had no session data");
    const crypto::Bytes& K = srp.session_key();
    const crypto::Bytes key = crypto::hmac_sha256(K, crypto::as_bytes("extra data key:"));
    crypto::Bytes iv = crypto::hmac_sha256(K, crypto::as_bytes("extra data iv:"));
    iv.resize(16);
    const plist::Value spd = plist::parse(crypto::aes_cbc_decrypt(key, iv, encrypted));

    LoginResult result;
    result.session.adsid = spd.string_at("adsid").value_or("");
    result.session.idms_token = spd.string_at("GsIdmsToken").value_or("");
    result.session.session_key = data_or_empty(spd, "sk");
    result.session.cookie = data_or_empty(spd, "c");
    if (result.session.adsid.empty() || result.session.idms_token.empty()) {
        throw AppleIdError("Apple's sign-in reply did not contain a session");
    }

    if (const plist::Value* status = complete.find("Status")) {
        const std::string action = status->string_at("au").value_or("");
        if (action == "trustedDeviceSecondaryAuth") {
            result.second_factor = SecondFactor::TrustedDevice;
        } else if (action == "secondaryAuth") {
            result.second_factor = SecondFactor::Sms;
        } else if (!action.empty()) {
            throw AppleIdError("Apple requires an unsupported additional step: " + action);
        }
    }
    return result;
}

http::Headers GrandSlamClient::second_factor_headers(const GsaSession& session) {
    const AnisetteData anisette = anisette_->fetch();
    const std::string identity = session.adsid + ":" + session.idms_token;
    http::Headers headers = {{"Content-Type", "text/x-xml-plist"},
                             {"User-Agent", "Xcode"},
                             {"Accept", "text/x-xml-plist"},
                             {"Accept-Language", "en-us"},
                             {"X-Apple-Identity-Token", base64_encode(crypto::as_bytes(identity))},
                             {"X-Apple-App-Info", kXcodeApp},
                             {"X-Xcode-Version", kXcodeVersion}};
    for (auto& header : anisette.headers()) headers.push_back(std::move(header));
    return headers;
}

void GrandSlamClient::request_trusted_device_code(const GsaSession& session) {
    http::Request request;
    request.url = base_url_ + "/auth/verify/trusteddevice";
    request.headers = second_factor_headers(session);
    const http::Response response = send(std::move(request));
    if (!response.ok()) {
        throw AppleIdError(std::format("could not request a verification code (HTTP {})",
                                       response.status));
    }
}

void GrandSlamClient::submit_trusted_device_code(const GsaSession& session, std::string_view code) {
    http::Request request;
    request.url = base_url_ + "/grandslam/GsService2/validate";
    request.headers = second_factor_headers(session);
    request.headers.emplace_back("security-code", std::string(code));
    const http::Response response = send(std::move(request));
    if (!response.ok()) {
        throw AppleIdError(std::format("verification failed (HTTP {})", response.status));
    }
    const plist::Value reply = plist::parse(crypto::as_bytes(response.body));
    check_status(reply);
}

void GrandSlamClient::request_sms_code(const GsaSession& session, int phone_id) {
    http::Request request;
    request.method = "PUT";
    request.url = base_url_ + "/auth/verify/phone/";
    request.headers = second_factor_headers(session);
    request.headers.emplace_back("Content-Type", "application/json");
    request.headers.emplace_back("Accept", "application/json");
    request.body = json{{"phoneNumber", {{"id", phone_id}}}, {"mode", "sms"}}.dump();
    const http::Response response = send(std::move(request));
    if (!response.ok()) {
        throw AppleIdError(std::format("could not request an SMS code (HTTP {})", response.status));
    }
}

void GrandSlamClient::submit_sms_code(const GsaSession& session, std::string_view code,
                                      int phone_id) {
    http::Request request;
    request.method = "POST";
    request.url = base_url_ + "/auth/verify/phone/securitycode";
    request.headers = second_factor_headers(session);
    request.headers.emplace_back("Content-Type", "application/json");
    request.headers.emplace_back("Accept", "application/json");
    request.body = json{{"phoneNumber", {{"id", phone_id}}},
                        {"securityCode", {{"code", code}}},
                        {"mode", "sms"}}
                       .dump();
    const http::Response response = send(std::move(request));
    if (!response.ok()) {
        throw AppleIdError(std::format("the SMS code was not accepted (HTTP {})", response.status));
    }
}

XcodeToken GrandSlamClient::fetch_xcode_token(const GsaSession& session) {
    if (session.session_key.empty() || session.cookie.empty()) {
        throw AppleIdError("the sign-in session cannot request app tokens");
    }
    const std::string checksum_input = std::string("apptokens") + session.adsid + kXcodeApp;
    const crypto::Bytes checksum =
        crypto::hmac_sha256(session.session_key, crypto::as_bytes(checksum_input));

    const plist::Value reply = service_request({{"app", plist::Array{kXcodeApp}},
                                                {"c", plist::Data{session.cookie}},
                                                {"checksum", plist::Data{checksum}},
                                                {"o", "apptokens"},
                                                {"t", session.idms_token},
                                                {"u", session.adsid}});

    // "XYZ" | 16-byte IV | ciphertext | 16-byte tag, AES-256-GCM with the
    // session key and the three version bytes as associated data.
    const crypto::Bytes encrypted = data_or_empty(reply, "et");
    if (encrypted.size() < 3 + 16 + 16) throw AppleIdError("Apple returned no Xcode token");
    const crypto::ByteView all(encrypted);
    const crypto::ByteView version = all.subspan(0, 3);
    if (version[0] != 'X' || version[1] != 'Y' || version[2] != 'Z') {
        throw AppleIdError("Apple returned an Xcode token in an unknown format");
    }
    const crypto::ByteView iv = all.subspan(3, 16);
    const crypto::ByteView ciphertext = all.subspan(19, all.size() - 19 - 16);
    const crypto::ByteView tag = all.subspan(all.size() - 16);
    crypto::Bytes plain;
    try {
        plain = crypto::aes_gcm_decrypt(session.session_key, iv, ciphertext, tag, version);
    } catch (const crypto::CryptoError&) {
        throw AppleIdError("could not decrypt the Xcode token");
    }

    const plist::Value tokens = plist::parse(plain);
    const plist::Value* by_app = tokens.find("t");
    const plist::Value* entry = by_app ? by_app->find(kXcodeApp) : nullptr;
    if (!entry) throw AppleIdError("Apple did not issue an Xcode token for this account");
    XcodeToken token;
    token.token = entry->string_at("token").value_or("");
    token.expiry_ms = entry->int_at("expiry").value_or(0);
    if (token.token.empty()) throw AppleIdError("Apple issued an empty Xcode token");
    return token;
}

}  // namespace winx::auth
