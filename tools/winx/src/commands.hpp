#pragma once

#include <cstdint>
#include <string>

#include "winx/codesign.hpp"
#include "winx/identity.hpp"

namespace winx::cli {

struct DevicesOptions {
    bool watch = false;
    bool verbose = false;
    // List pairing records on disk instead of attached devices.
    bool paired = false;
    std::string host = "127.0.0.1";
    std::uint16_t port = 27015;
};

struct AuthLoginOptions {
    std::string mode;  // "key" or "password"
    // API key mode.
    std::string key_id;
    std::string issuer_id;
    std::string key_path;
    // Apple ID mode.
    std::string apple_id;
    std::string team_id;
    std::string anisette_url;
    // Skip the interactive confirmation of the warning text.
    bool accept_warning = false;
};

struct DsOptions {
    std::string action;  // teams, devices, identifiers, certificates, profiles, provision
    std::string bundle_id;
    std::string udid;
    std::string device_name;
    std::string output_dir = ".";
};

struct SignOptions {
    std::string target;  // .app bundle or a single Mach-O file
    std::string profile_path;
    std::string entitlements_path;
    std::string identifier;  // for a bare Mach-O; defaults to the file stem
    bool ad_hoc = false;
    bool verify = false;
};

// The stored signing identity with Apple's intermediate and root, ready to
// hand to the signer. `credentials` refers to the key held by `identity`.
struct SigningContext {
    auth::SigningIdentity identity;
    codesign::SigningCredentials credentials;
};
// Throws when not signed in or when no certificate has been provisioned yet.
SigningContext load_signing_context();

// Options for commands that act on one paired device.
struct DeviceOptions {
    std::string target;  // bundle path or bundle identifier, depending on the command
    std::string udid;    // empty: the only attached device
    bool reveal = false;
    // `winx device wifi`: switch Wi-Fi connections on or off; neither shows the state.
    bool wifi_on = false;
    bool wifi_off = false;
    std::string host = "127.0.0.1";
    std::uint16_t port = 27015;
};

struct BuildOptions {
    std::string project_dir = ".";
    std::string udid;
    std::string swift_path;
    bool release = false;
    // `winx export` only.
    std::string ipa_path;  // empty: <project>/<Product>.ipa
    bool unsigned_ipa = false;
};

struct NewOptions {
    std::string name;
    std::string org_id = "com.example";
};

struct SdkOptions {
    std::string action;  // install, status
    std::string xip;
    bool accept = false;
};

// Each returns the process exit code.
int run_build(const BuildOptions& options);
int run_dev(const BuildOptions& options);
int run_export(const BuildOptions& options);
int run_new(const NewOptions& options);
int run_sdk(const SdkOptions& options);
int run_setup();
int run_install(const DeviceOptions& options);
int run_uninstall(const DeviceOptions& options);
int run_apps(const DeviceOptions& options);
int run_devmode(const DeviceOptions& options);
int run_wifi(const DeviceOptions& options);
int run_log(const DeviceOptions& options);
int run_sign(const SignOptions& options);
int run_devices(const DevicesOptions& options);
int run_auth_login(const AuthLoginOptions& options);
int run_auth_status();
int run_auth_logout();
int run_ds(const DsOptions& options);

// Console helpers shared by the commands.
std::string prompt_line(const std::string& label);
std::string prompt_secret(const std::string& label);
bool confirm(const std::string& question);

}  // namespace winx::cli
