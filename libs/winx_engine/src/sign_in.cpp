#include "winx/sign_in.hpp"

#include <windows.h>

#include <memory>

#include "winx/developer_api.hpp"
#include "winx/files.hpp"
#include "winx/keys.hpp"
#include "winx/text.hpp"

namespace winx::engine {
namespace {

void say(const AppleIdPrompts& prompts, const std::string& message) {
    if (prompts.status) prompts.status(message);
}

}  // namespace

auth::AuthState sign_in_with_api_key(const ApiKeyLogin& login) {
    if (login.key_id.empty() || login.issuer_id.empty() || login.p8_pem.empty()) {
        throw auth::KeyError("the key ID, issuer ID and .p8 key file are all required");
    }
    const auth::AuthStore store(app_data_dir());

    // Prove the credentials with an in-memory copy of the key first.
    const http::Client client;
    auth::DeveloperApi api(std::make_shared<auth::AscKeyTransport>(
        auth::EcSigningKey::import_p8(login.p8_pem), login.key_id, login.issuer_id,
        client.sender()));
    api.list_devices();

    store.clear();
    const std::string key_name = "WinXcode ASC " + login.key_id;
    auth::EcSigningKey::import_p8(login.p8_pem, to_wide(key_name));
    auth::AuthState state;
    state.mode = auth::AuthState::Mode::ApiKey;
    state.key_id = login.key_id;
    state.issuer_id = login.issuer_id;
    state.key_name = key_name;
    store.save(state);
    return state;
}

auth::AuthState sign_in_with_apple_id(const std::string& apple_id, std::string password,
                                      const std::string& anisette_url,
                                      const std::string& preferred_team,
                                      const AppleIdPrompts& prompts) {
    struct Wipe {
        std::string& secret;
        ~Wipe() { SecureZeroMemory(secret.data(), secret.size()); }
    } wipe{password};

    if (apple_id.empty() || password.empty()) {
        throw auth::AppleIdError("an Apple ID and password are required");
    }
    const auth::AuthStore store(app_data_dir());
    const http::Client client;
    const auth::AppleCertificates certificates =
        auth::load_apple_certificates(client.sender(), store.directory());
    say(prompts, "Preparing this PC's machine identity...");
    const auto anisette = auth::make_anisette(store, client, anisette_url);
    auth::GrandSlamClient grandslam(client.sender(), anisette, {certificates.root});

    say(prompts, "Signing in...");
    auth::GrandSlamClient::LoginResult login = grandslam.login(apple_id, password);
    if (login.second_factor != auth::SecondFactor::None) {
        const auto ask = [&](bool sms) {
            if (!prompts.verification_code) {
                throw auth::AppleIdError("Apple requires a verification code");
            }
            const std::string code = prompts.verification_code(sms);
            if (code.empty()) throw auth::AppleIdError("sign-in was cancelled");
            return code;
        };
        if (login.second_factor == auth::SecondFactor::TrustedDevice) {
            grandslam.request_trusted_device_code(login.session);
            std::string code = ask(false);
            if (code == "sms") {
                grandslam.request_sms_code(login.session);
                grandslam.submit_sms_code(login.session, ask(true));
            } else {
                grandslam.submit_trusted_device_code(login.session, code);
            }
        } else {
            grandslam.request_sms_code(login.session);
            grandslam.submit_sms_code(login.session, ask(true));
        }
        // A verified session is only issued by signing in again.
        say(prompts, "Verifying...");
        login = grandslam.login(apple_id, password);
        if (login.second_factor != auth::SecondFactor::None) {
            throw auth::AppleIdError("Apple still requires verification; the code was not accepted");
        }
    }

    say(prompts, "Fetching developer teams...");
    const auth::XcodeToken token = grandslam.fetch_xcode_token(login.session);
    const std::vector<auth::Team> teams = auth::XcodeTransport::list_teams(
        {login.session.adsid, token.token, ""}, *anisette, client.sender());
    if (teams.empty()) {
        throw auth::AppleIdError(
            "this Apple ID is not a member of any developer team. Open "
            "https://developer.apple.com/account once to accept the agreement");
    }

    std::size_t chosen = teams.size();
    if (!preferred_team.empty()) {
        for (std::size_t i = 0; i < teams.size(); ++i) {
            if (teams[i].id == preferred_team) chosen = i;
        }
        if (chosen == teams.size()) {
            throw auth::AppleIdError("the account is not a member of team " + preferred_team);
        }
    } else if (teams.size() == 1) {
        chosen = 0;
    } else if (prompts.choose_team) {
        chosen = prompts.choose_team(teams);
    }
    if (chosen >= teams.size()) throw auth::AppleIdError("no team was chosen");

    store.clear();
    auth::AuthState state;
    state.mode = auth::AuthState::Mode::AppleId;
    state.apple_id = apple_id;
    state.adsid = login.session.adsid;
    state.xcode_token = token.token;
    state.token_expiry_ms = token.expiry_ms;
    state.team_id = teams[chosen].id;
    state.team_name = teams[chosen].name + (teams[chosen].free ? " (free)" : "");
    state.anisette_url = anisette_url;
    store.save(state);
    return state;
}

void sign_out() {
    const auth::AuthStore store(app_data_dir());
    store.clear();
    std::error_code ec;
    std::filesystem::remove(store.anisette_state_file(), ec);
}

}  // namespace winx::engine
