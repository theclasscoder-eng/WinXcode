#include "commands.hpp"

#include <chrono>
#include <format>
#include <iostream>

#include "winx/apple_id.hpp"
#include "winx/auth_session.hpp"
#include "winx/codesign.hpp"
#include "winx/files.hpp"
#include "winx/identity.hpp"
#include "winx/plist.hpp"
#include "winx/provisioning_profile.hpp"
#include "winx/text.hpp"

namespace winx::cli {
namespace {

namespace fs = std::filesystem;

int verify(const fs::path& target) {
    std::vector<std::string> problems;
    if (fs::is_directory(target)) {
        problems = codesign::verify_bundle(target);
    } else {
        const auto content = read_file(target);
        if (!content) {
            std::cerr << "error: cannot read " << to_utf8(target.wstring()) << '\n';
            return 1;
        }
        problems = codesign::verify_macho(*content);
    }
    if (problems.empty()) {
        std::cout << "The signature is internally consistent: page hashes, sealed resources and "
                     "the CMS signature all match.\n"
                     "This does not check Apple's trust chain or the provisioning profile; the "
                     "device does that at install time.\n";
        return 0;
    }
    for (const std::string& problem : problems) std::cout << problem << '\n';
    return 1;
}

}  // namespace

SigningContext load_signing_context() {
    const auth::AuthStore store(app_data_dir());
    const auth::AuthState state = store.load();
    if (state.mode == auth::AuthState::Mode::None) throw auth::NotSignedIn();

    auth::IdentityStore identities(app_data_dir());
    auto stored = identities.load(state.account());
    if (!stored) {
        throw std::runtime_error(
            "no signing certificate is stored for this account; run `winx ds provision` first");
    }
    const http::Client client;
    const auth::AppleCertificates apple =
        auth::load_apple_certificates(client.sender(), store.directory());

    SigningContext context{std::move(stored->identity), {}};
    const auth::SigningIdentity& identity = context.identity;
    context.credentials.certificate = identity.certificate();
    context.credentials.private_key = identity.key().handle();
    context.credentials.chain = {apple.wwdr_g3, apple.root};
    context.credentials.common_name = identity.info().common_name;
    context.credentials.team_id = identity.info().organizational_unit;
    return context;
}

int run_sign(const SignOptions& options) {
    const fs::path target = to_wide(options.target);
    if (!fs::exists(target)) {
        std::cerr << "error: " << options.target << " does not exist\n";
        return 1;
    }
    if (options.verify) return verify(target);

    try {
        std::optional<SigningContext> context;
        codesign::SigningCredentials credentials;  // ad hoc unless replaced below
        if (!options.ad_hoc) {
            context.emplace(load_signing_context());
            credentials = context->credentials;
            std::cout << "Signing as " << credentials.common_name << '\n';
        }

        // Entitlements: an explicit file wins; otherwise they come from the profile.
        std::optional<plist::Value> entitlements;
        if (!options.entitlements_path.empty()) {
            entitlements = plist::load_file(to_wide(options.entitlements_path));
        }

        if (!fs::is_directory(target)) {
            const auto content = read_file(target);
            if (!content || !codesign::is_macho(*content)) {
                std::cerr << "error: " << options.target << " is not a Mach-O file or a bundle\n";
                return 1;
            }
            codesign::MachOSignOptions sign_options;
            sign_options.identifier = options.identifier.empty()
                                          ? to_utf8(target.stem().wstring())
                                          : options.identifier;
            sign_options.entitlements = entitlements;
            write_file(target, codesign::sign_macho(*content, sign_options, credentials));
            std::cout << "Signed " << options.target << '\n';
            return 0;
        }

        codesign::BundleSignOptions bundle_options;
        bundle_options.log = [](const std::string& line) { std::cout << line << '\n'; };
        const codesign::BundleInfo info = codesign::read_bundle_info(target);

        std::optional<std::vector<std::uint8_t>> profile_bytes;
        if (!options.profile_path.empty()) {
            profile_bytes = read_file(to_wide(options.profile_path));
            if (!profile_bytes) {
                std::cerr << "error: cannot read " << options.profile_path << '\n';
                return 1;
            }
        } else {
            profile_bytes = read_file(target / L"embedded.mobileprovision");
        }
        if (profile_bytes) {
            const auth::ProvisioningProfile profile = auth::ProvisioningProfile::parse(*profile_bytes);
            if (profile.expired(std::chrono::system_clock::now())) {
                std::cerr << "error: the provisioning profile '" << profile.name
                          << "' has expired\n";
                return 1;
            }
            if (!options.ad_hoc && !profile.includes_certificate(credentials.certificate)) {
                std::cerr << "error: the provisioning profile '" << profile.name
                          << "' does not include the signing certificate; run `winx ds "
                             "provision` to refresh it\n";
                return 1;
            }
            if (!entitlements) entitlements = auth::make_entitlements(profile, info.identifier);
            bundle_options.provisioning_profile = *profile_bytes;
        } else if (!options.ad_hoc) {
            std::cerr << "error: no provisioning profile; pass --profile or run `winx ds "
                         "provision`\n";
            return 1;
        }
        bundle_options.entitlements = entitlements;

        codesign::sign_bundle(target, credentials, bundle_options);
        const auto problems = codesign::verify_bundle(target);
        for (const std::string& problem : problems) std::cerr << "warning: " << problem << '\n';
        return problems.empty() ? 0 : 1;
    } catch (const auth::NotSignedIn& error) {
        std::cerr << "error: " << error.what() << '\n';
    } catch (const auth::ProfileError& error) {
        std::cerr << "error: " << error.what() << '\n';
    } catch (const codesign::SignError& error) {
        std::cerr << "error: " << error.what() << '\n';
    } catch (const codesign::MachOError& error) {
        std::cerr << "error: " << error.what() << '\n';
    }
    return 1;
}

}  // namespace winx::cli
