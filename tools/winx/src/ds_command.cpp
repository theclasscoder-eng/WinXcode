#include "commands.hpp"

#include <chrono>
#include <format>
#include <iostream>

#include "winx/apple_id.hpp"
#include "winx/auth_session.hpp"
#include "winx/files.hpp"
#include "winx/identity.hpp"
#include "winx/lockdown.hpp"
#include "winx/plist.hpp"
#include "winx/provisioner.hpp"
#include "winx/text.hpp"
#include "winx/usbmux.hpp"

namespace winx::cli {
namespace {

// The single attached device, when the user did not name one.
bool resolve_device(DsOptions& options) {
    if (!options.udid.empty()) return true;
    std::vector<device::UsbmuxDevice> devices;
    try {
        devices = device::UsbmuxClient().list_devices();
    } catch (const std::exception&) {
    }
    if (devices.size() != 1) {
        std::cerr << "error: pass --udid, or attach exactly one device ("
                  << devices.size() << " attached)\n";
        return false;
    }
    options.udid = devices.front().udid;
    if (options.device_name.empty()) {
        try {
            options.device_name =
                device::query_device_info({}, devices.front().device_id).name;
        } catch (const std::exception&) {
        }
    }
    return true;
}

int provision(DsOptions options, const auth::AuthState& state, auth::DeveloperApi& api) {
    if (options.bundle_id.empty()) {
        std::cerr << "error: --bundle-id is required\n";
        return 2;
    }
    if (!resolve_device(options)) return 1;

    auth::IdentityStore identities(app_data_dir());
    auth::Provisioner provisioner(api, identities,
                                  [](const std::string& line) { std::cout << line << '\n'; });
    auth::ProvisionRequest request;
    request.bundle_id = options.bundle_id;
    request.device_udid = options.udid;
    if (!options.device_name.empty()) request.device_name = options.device_name;
    request.account = state.account();
    const auth::ProvisionResult result = provisioner.provision(request);

    const std::filesystem::path out = to_wide(options.output_dir);
    write_file(out / L"embedded.mobileprovision", result.profile.raw);
    write_text_file(out / L"Entitlements.plist", plist::to_xml(result.entitlements));

    const auth::CertificateInfo& certificate = result.identity.info();
    std::cout << std::format("Signing identity: {} (team {})\n", certificate.common_name,
                             certificate.organizational_unit)
              << std::format("Profile:          {} [{}]\n", result.profile.name, result.profile.uuid)
              << "Wrote embedded.mobileprovision and Entitlements.plist to "
              << to_utf8(std::filesystem::absolute(out).wstring()) << '\n';
    return 0;
}

}  // namespace

int run_ds(const DsOptions& options) {
    const auth::AuthStore store(app_data_dir());
    const auth::AuthState state = store.load();
    try {
        const http::Client client;
        if (options.action == "teams") {
            if (state.mode != auth::AuthState::Mode::AppleId) {
                std::cout << "An API key belongs to exactly one team; there is nothing to list.\n";
                return 0;
            }
            const auto anisette = auth::make_anisette(store, client, state.anisette_url);
            for (const auth::Team& team : auth::XcodeTransport::list_teams(
                     {state.adsid, state.xcode_token, ""}, *anisette, client.sender())) {
                std::cout << std::format("{}  {}  {}{}\n", team.id, team.name, team.type,
                                         team.free ? "  [free]" : "");
            }
            return 0;
        }

        auth::DeveloperApi api(auth::make_transport(state, store, client));
        if (options.action == "devices") {
            for (const auth::Device& device : api.list_devices()) {
                std::cout << std::format("{}  {}  {}  {}  {}\n", device.udid, device.name,
                                         device.platform, device.model, device.status);
            }
        } else if (options.action == "identifiers") {
            for (const auth::BundleId& bundle : api.list_bundle_ids()) {
                std::cout << std::format("{}  {}  {}\n", bundle.identifier, bundle.name,
                                         bundle.platform);
            }
        } else if (options.action == "certificates") {
            for (const auth::Certificate& certificate : api.list_certificates()) {
                std::cout << std::format("{}  {}  {}  expires {}\n", certificate.serial_number,
                                         certificate.type, certificate.name,
                                         certificate.expiration);
            }
        } else if (options.action == "profiles") {
            for (const auth::Profile& profile : api.list_profiles()) {
                std::cout << std::format("{}  {}  {}  {}  expires {}\n", profile.uuid, profile.type,
                                         profile.state, profile.name, profile.expiration);
            }
        } else if (options.action == "provision") {
            return provision(options, state, api);
        } else {
            std::cerr << "error: unknown action " << options.action << '\n';
            return 2;
        }
        return 0;
    } catch (const auth::NotSignedIn& error) {
        std::cerr << "error: " << error.what() << '\n';
    } catch (const auth::ApiError& error) {
        std::cerr << "error: " << error.what() << '\n';
        if (error.status() == 401) {
            std::cerr << "The stored credentials were rejected. Run `winx auth login` again.\n";
        }
    } catch (const auth::AppleIdError& error) {
        std::cerr << "error: " << error.what() << '\n';
    }
    return 1;
}

}  // namespace winx::cli
