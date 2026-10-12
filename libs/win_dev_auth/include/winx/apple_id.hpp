#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "winx/crypto.hpp"
#include "winx/developer_api.hpp"
#include "winx/http.hpp"
#include "winx/plist.hpp"

// Apple ID sign-in, as xtool does it. Everything in this header speaks
// protocols Apple has not published: GrandSlam (gsa.apple.com), anisette
// machine provisioning, and the Xcode flavour of the developer services API.
// They were reconstructed from open-source clients and can change or be
// blocked by Apple without notice.
namespace winx::auth {

class AppleIdError : public std::runtime_error {
public:
    AppleIdError(const std::string& message, std::int64_t code = 0)
        : std::runtime_error(message), code_(code) {}
    // Apple's "ec" status code when one was returned.
    std::int64_t code() const noexcept { return code_; }

private:
    std::int64_t code_;
};

// Shown before any Apple ID sign-in; the user must accept it.
std::string_view apple_id_warning();
// Shown when an API key is stored.
std::string_view api_key_warning();

// ---- Apple's own certificates -------------------------------------------

struct AppleCertificates {
    crypto::Bytes root;     // Apple Root CA
    crypto::Bytes wwdr_g3;  // Worldwide Developer Relations G3 intermediate
};

// Downloads both from apple.com on first use and caches them in `cache_dir`.
// The root must match a SHA-256 fingerprint compiled into this library and the
// intermediate must be signed by it, so a tampered download is rejected.
AppleCertificates load_apple_certificates(const http::Sender& sender,
                                          const std::filesystem::path& cache_dir);
bool is_apple_root_ca(crypto::ByteView der);

// ---- Anisette ------------------------------------------------------------

// Per-machine one-time-password headers that Apple's auth servers require.
struct AnisetteData {
    std::string one_time_password;  // X-Apple-I-MD
    std::string machine_id;         // X-Apple-I-MD-M
    std::string routing_info;       // X-Apple-I-MD-RINFO
    std::string local_user_id;      // X-Apple-I-MD-LU
    std::string device_id;          // X-Mme-Device-Id
    std::string client_info;        // X-MMe-Client-Info
    std::string user_agent;
    std::string client_time;        // X-Apple-I-Client-Time, ISO 8601
    std::string time_zone = "UTC";
    std::string locale = "en_US";

    http::Headers headers() const;
};

class AnisetteProvider {
public:
    virtual ~AnisetteProvider() = default;
    virtual AnisetteData fetch() = 0;
};

// Bidirectional text channel; a WebSocket in production, scripted in tests.
class TextChannel {
public:
    virtual ~TextChannel() = default;
    virtual void send(std::string_view text) = 0;
    virtual std::string receive() = 0;
};
using ChannelFactory = std::function<std::unique_ptr<TextChannel>(const std::string& url)>;
ChannelFactory websocket_channel_factory(const http::Client& client);

// Anisette from a remote "anisette-v3" server. The server runs Apple's
// provisioning library; this client relays the provisioning exchange with
// Apple and keeps the resulting machine identity locally (DPAPI-encrypted).
// The Apple ID and password never go to the server, but it does see the
// machine identity it issues headers for.
class RemoteAnisetteProvider : public AnisetteProvider {
public:
    struct Options {
        std::string server_url = "https://ani.sidestore.io";
        std::filesystem::path state_file;
        std::vector<crypto::Bytes> apple_roots;
    };

    RemoteAnisetteProvider(Options options, http::Sender sender, ChannelFactory channels);

    AnisetteData fetch() override;
    // Forgets the provisioned machine identity.
    void reset();

private:
    struct State {
        crypto::Bytes identifier;
        std::string adi_pb;
    };
    State load_state() const;
    void save_state(const State& state) const;
    void fetch_client_info();
    std::string provision(const State& state);
    AnisetteData base_data(const State& state) const;

    Options options_;
    http::Sender sender_;
    ChannelFactory channels_;
    std::string client_info_;
    std::string user_agent_;
};

// ---- GrandSlam -----------------------------------------------------------

struct GsaSession {
    std::string adsid;
    std::string idms_token;
    crypto::Bytes session_key;
    crypto::Bytes cookie;
};

enum class SecondFactor { None, TrustedDevice, Sms };

struct XcodeToken {
    std::string token;
    std::int64_t expiry_ms = 0;
};

class GrandSlamClient {
public:
    GrandSlamClient(http::Sender sender, std::shared_ptr<AnisetteProvider> anisette,
                    std::vector<crypto::Bytes> apple_roots,
                    std::string base_url = "https://gsa.apple.com");

    struct LoginResult {
        GsaSession session;
        SecondFactor second_factor = SecondFactor::None;
    };
    // SRP sign-in. The password is used for key derivation only and is not
    // sent or stored. When a second factor is required, complete it and then
    // call login() again.
    LoginResult login(std::string_view apple_id, std::string_view password);

    void request_trusted_device_code(const GsaSession& session);
    void submit_trusted_device_code(const GsaSession& session, std::string_view code);
    void request_sms_code(const GsaSession& session, int phone_id = 1);
    void submit_sms_code(const GsaSession& session, std::string_view code, int phone_id = 1);

    XcodeToken fetch_xcode_token(const GsaSession& session);

private:
    plist::Value service_request(plist::Dict parameters);
    http::Headers second_factor_headers(const GsaSession& session);
    http::Response send(http::Request request);

    http::Sender sender_;
    std::shared_ptr<AnisetteProvider> anisette_;
    std::vector<crypto::Bytes> apple_roots_;
    std::string base_url_;
};

// ---- Developer services with an Apple ID session --------------------------

struct XcodeCredentials {
    std::string adsid;
    std::string token;
    std::string team_id;
};

struct Team {
    std::string id;
    std::string name;
    std::string type;  // "Individual", "Company/Organization", ...
    bool free = false;
};

// Sends DeveloperApi requests to developerservices2.apple.com the way Xcode
// does: GET/DELETE become POST with X-HTTP-Method-Override and the query in
// the body, and the team ID is added to every request.
class XcodeTransport : public Transport {
public:
    XcodeTransport(XcodeCredentials credentials, std::shared_ptr<AnisetteProvider> anisette,
                   http::Sender sender,
                   std::string base_url = "https://developerservices2.apple.com/services");

    http::Response perform(std::string_view method, std::string_view path, const Query& query,
                           const json* body) override;

    // Teams the signed-in Apple ID belongs to. `credentials.team_id` may be empty.
    static std::vector<Team> list_teams(const XcodeCredentials& credentials,
                                        AnisetteProvider& anisette, const http::Sender& sender,
                                        std::string_view base_url =
                                            "https://developerservices2.apple.com/services");

private:
    XcodeCredentials credentials_;
    std::shared_ptr<AnisetteProvider> anisette_;
    http::Sender sender_;
    std::string base_url_;
};

}  // namespace winx::auth
