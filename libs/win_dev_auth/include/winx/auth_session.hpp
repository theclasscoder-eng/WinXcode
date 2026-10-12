#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>

#include "winx/apple_id.hpp"
#include "winx/developer_api.hpp"
#include "winx/http.hpp"

namespace winx::auth {

class NotSignedIn : public std::runtime_error {
public:
    NotSignedIn() : std::runtime_error("not signed in; run `winx auth login` first") {}
};

// Everything needed to talk to Apple again in a later run. No password is
// ever part of it.
struct AuthState {
    enum class Mode { None, ApiKey, AppleId };
    Mode mode = Mode::None;

    // API key mode. The key itself lives in CNG under `key_name`.
    std::string key_id;
    std::string issuer_id;
    std::string key_name;

    // Apple ID mode.
    std::string apple_id;
    std::string adsid;
    std::string xcode_token;
    std::int64_t token_expiry_ms = 0;
    std::string team_id;
    std::string team_name;
    std::string anisette_url;

    // Name under which the signing identity for these credentials is stored.
    std::string account() const;
};

// Stores AuthState as DPAPI-encrypted JSON in `directory`.
class AuthStore {
public:
    explicit AuthStore(std::filesystem::path directory);

    AuthState load() const;
    void save(const AuthState& state) const;
    // Also removes the imported API key from CNG.
    void clear() const;

    const std::filesystem::path& directory() const noexcept { return directory_; }
    std::filesystem::path anisette_state_file() const;

private:
    std::filesystem::path directory_;
};

std::shared_ptr<RemoteAnisetteProvider> make_anisette(const AuthStore& store,
                                                      const http::Client& client,
                                                      const std::string& server_url);

// Transport for the stored credentials. Throws NotSignedIn when there are none.
std::shared_ptr<Transport> make_transport(const AuthState& state, const AuthStore& store,
                                          const http::Client& client);

}  // namespace winx::auth
