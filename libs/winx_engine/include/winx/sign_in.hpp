#pragma once

#include <functional>
#include <string>
#include <vector>

#include "winx/apple_id.hpp"
#include "winx/auth_session.hpp"

// Sign-in flows shared by `winx auth login` and the IDE's account dialog.
// Both front ends are responsible for showing auth::api_key_warning() or
// auth::apple_id_warning() and getting the user's agreement first.
namespace winx::engine {

struct ApiKeyLogin {
    std::string key_id;
    std::string issuer_id;
    std::string p8_pem;  // contents of the AuthKey_XXXX.p8 file
};

// Checks the key against Apple before anything is stored, then imports it
// into the Windows key store as non-exportable. Returns the stored state.
// Throws auth::ApiError when Apple rejects the key and auth::KeyError when
// the file is not a valid key.
auth::AuthState sign_in_with_api_key(const ApiKeyLogin& login);

struct AppleIdPrompts {
    // Called when Apple asks for a second factor. `sms` is false for a code
    // shown on a trusted device. Return the code, or "sms" to switch from a
    // trusted-device code to a text message. An empty string cancels.
    std::function<std::string(bool sms)> verification_code;
    // Called when the account belongs to several teams; return an index into
    // `teams`, or a value out of range to cancel.
    std::function<std::size_t(const std::vector<auth::Team>& teams)> choose_team;
    std::function<void(const std::string&)> status;
};

// The password is used for one SRP exchange and never stored. Throws
// auth::AppleIdError on failure or cancellation.
auth::AuthState sign_in_with_apple_id(const std::string& apple_id, std::string password,
                                      const std::string& anisette_url,
                                      const std::string& preferred_team,
                                      const AppleIdPrompts& prompts);

// Removes stored credentials and the anisette identity; signing certificates stay.
void sign_out();

}  // namespace winx::engine
