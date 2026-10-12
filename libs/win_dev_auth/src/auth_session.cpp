#include "winx/auth_session.hpp"

#include "winx/files.hpp"
#include "winx/text.hpp"

namespace winx::auth {
namespace {

constexpr const wchar_t* kStateFile = L"auth.bin";

}  // namespace

std::string AuthState::account() const {
    switch (mode) {
        case Mode::ApiKey: return issuer_id;
        case Mode::AppleId: return team_id;
        case Mode::None: break;
    }
    return {};
}

AuthStore::AuthStore(std::filesystem::path directory) : directory_(std::move(directory)) {}

std::filesystem::path AuthStore::anisette_state_file() const { return directory_ / L"anisette.bin"; }

AuthState AuthStore::load() const {
    AuthState state;
    std::optional<std::vector<std::uint8_t>> raw;
    try {
        raw = secure::read_file(directory_ / kStateFile);
    } catch (const std::exception&) {
        return state;  // written by another Windows user or corrupted
    }
    if (!raw) return state;
    const json record = json::parse(raw->begin(), raw->end(), nullptr, false);
    if (!record.is_object()) return state;

    const std::string mode = record.value("mode", std::string{});
    state.mode = mode == "apiKey"    ? AuthState::Mode::ApiKey
                 : mode == "appleId" ? AuthState::Mode::AppleId
                                     : AuthState::Mode::None;
    state.key_id = record.value("keyId", std::string{});
    state.issuer_id = record.value("issuerId", std::string{});
    state.key_name = record.value("keyName", std::string{});
    state.apple_id = record.value("appleId", std::string{});
    state.adsid = record.value("adsid", std::string{});
    state.xcode_token = record.value("xcodeToken", std::string{});
    state.token_expiry_ms = record.value("tokenExpiryMs", std::int64_t{0});
    state.team_id = record.value("teamId", std::string{});
    state.team_name = record.value("teamName", std::string{});
    state.anisette_url = record.value("anisetteUrl", std::string{});
    return state;
}

void AuthStore::save(const AuthState& state) const {
    const char* mode = state.mode == AuthState::Mode::ApiKey    ? "apiKey"
                       : state.mode == AuthState::Mode::AppleId ? "appleId"
                                                                : "none";
    const json record = {{"mode", mode},
                         {"keyId", state.key_id},
                         {"issuerId", state.issuer_id},
                         {"keyName", state.key_name},
                         {"appleId", state.apple_id},
                         {"adsid", state.adsid},
                         {"xcodeToken", state.xcode_token},
                         {"tokenExpiryMs", state.token_expiry_ms},
                         {"teamId", state.team_id},
                         {"teamName", state.team_name},
                         {"anisetteUrl", state.anisette_url}};
    const std::string text = record.dump();
    secure::write_file(directory_ / kStateFile, crypto::as_bytes(text));
}

void AuthStore::clear() const {
    const AuthState state = load();
    if (!state.key_name.empty()) EcSigningKey::remove(to_wide(state.key_name));
    std::error_code ec;
    std::filesystem::remove(directory_ / kStateFile, ec);
}

std::shared_ptr<RemoteAnisetteProvider> make_anisette(const AuthStore& store,
                                                      const http::Client& client,
                                                      const std::string& server_url) {
    RemoteAnisetteProvider::Options options;
    if (!server_url.empty()) options.server_url = server_url;
    options.state_file = store.anisette_state_file();
    options.apple_roots = {load_apple_certificates(client.sender(), store.directory()).root};
    return std::make_shared<RemoteAnisetteProvider>(std::move(options), client.sender(),
                                                    websocket_channel_factory(client));
}

std::shared_ptr<Transport> make_transport(const AuthState& state, const AuthStore& store,
                                          const http::Client& client) {
    switch (state.mode) {
        case AuthState::Mode::ApiKey:
            return std::make_shared<AscKeyTransport>(EcSigningKey::open(to_wide(state.key_name)),
                                                     state.key_id, state.issuer_id,
                                                     client.sender());
        case AuthState::Mode::AppleId: {
            if (state.team_id.empty()) throw NotSignedIn();
            return std::make_shared<XcodeTransport>(
                XcodeCredentials{state.adsid, state.xcode_token, state.team_id},
                make_anisette(store, client, state.anisette_url), client.sender());
        }
        case AuthState::Mode::None: break;
    }
    throw NotSignedIn();
}

}  // namespace winx::auth
