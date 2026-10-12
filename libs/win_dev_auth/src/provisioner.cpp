#include "winx/provisioner.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <format>

namespace winx::auth {
namespace {

bool equals_ignore_case(std::string_view a, std::string_view b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return std::tolower(static_cast<unsigned char>(x)) ==
                      std::tolower(static_cast<unsigned char>(y));
           });
}

// Apple restricts resource names to letters, digits and spaces.
std::string portal_safe(std::string_view text) {
    std::string out;
    for (const char c : text) {
        out += std::isalnum(static_cast<unsigned char>(c)) ? c : ' ';
    }
    return out;
}

}  // namespace

Provisioner::Provisioner(DeveloperApi& api, IdentityStore& identities, Log log)
    : api_(api), identities_(identities), log_(std::move(log)) {}

void Provisioner::say(const std::string& message) const {
    if (log_) log_(message);
}

std::string Provisioner::profile_name_for(std::string_view bundle_id) {
    return "WinXcode " + portal_safe(bundle_id);
}

Device Provisioner::ensure_device(const ProvisionRequest& request) {
    for (Device& device : api_.list_devices(request.device_udid)) {
        if (equals_ignore_case(device.udid, request.device_udid)) {
            if (device.status == "DISABLED") {
                throw ApiError(409, "DEVICE_DISABLED",
                               "the device is registered but disabled in the developer account; "
                               "re-enable it in the developer portal");
            }
            return std::move(device);
        }
    }
    say(std::format("Registering device {}", request.device_udid));
    return api_.register_device(request.device_name, request.device_udid);
}

BundleId Provisioner::ensure_bundle_id(const ProvisionRequest& request) {
    // The filter is a prefix match on Apple's side, so compare exactly.
    for (BundleId& bundle : api_.list_bundle_ids(request.bundle_id)) {
        if (bundle.identifier == request.bundle_id) return std::move(bundle);
    }
    say(std::format("Registering bundle ID {}", request.bundle_id));
    return api_.create_bundle_id(request.bundle_id, "WinXcode " + portal_safe(request.bundle_id));
}

IdentityStore::Stored Provisioner::ensure_identity(const ProvisionRequest& request) {
    const auto now = std::chrono::system_clock::now();
    if (auto stored = identities_.load(request.account)) {
        // Reuse it only while Apple still lists the certificate.
        const bool current = stored->identity.info().not_after > now + std::chrono::hours(24);
        if (current) {
            const auto certificates = api_.list_certificates();
            const bool listed =
                std::any_of(certificates.begin(), certificates.end(), [&](const Certificate& c) {
                    return c.id == stored->remote_id ||
                           equals_ignore_case(c.serial_number, stored->identity.info().serial_hex);
                });
            if (listed) return std::move(*stored);
        }
        say("The stored signing certificate is expired or was revoked; requesting a new one");
    }

    say("Requesting an Apple Development certificate");
    const IdentityStore::Pending pending = identities_.begin(request.account);
    Certificate issued;
    try {
        issued = api_.create_certificate(pending.csr_pem);
    } catch (const ApiError&) {
        RsaKey::remove(pending.key_name);
        throw;
    }
    if (issued.content.empty()) {
        RsaKey::remove(pending.key_name);
        throw ApiError(200, "", "Apple issued a certificate without content");
    }
    SigningIdentity identity =
        identities_.complete(request.account, pending, issued.content, issued.id);
    return IdentityStore::Stored{std::move(identity), issued.id};
}

ProvisionResult Provisioner::provision(const ProvisionRequest& request) {
    const Device device = ensure_device(request);
    const BundleId bundle = ensure_bundle_id(request);
    IdentityStore::Stored stored = ensure_identity(request);

    const std::string name = profile_name_for(request.bundle_id);
    const auto now = std::chrono::system_clock::now();
    for (const Profile& candidate : api_.list_profiles(name)) {
        if (candidate.name != name) continue;
        bool reusable = false;
        if (candidate.state == "ACTIVE" && !candidate.content.empty()) {
            try {
                ProvisioningProfile parsed = ProvisioningProfile::parse(candidate.content);
                reusable = !parsed.expired(now + std::chrono::hours(1)) &&
                           parsed.includes_device(request.device_udid) &&
                           parsed.includes_certificate(stored.identity.certificate()) &&
                           parsed.covers_bundle_id(request.bundle_id);
                if (reusable) {
                    plist::Value entitlements = make_entitlements(parsed, request.bundle_id);
                    return ProvisionResult{std::move(stored.identity), std::move(parsed),
                                           std::move(entitlements)};
                }
            } catch (const ProfileError&) {
                // Fall through and replace it.
            }
        }
        say(std::format("Replacing outdated provisioning profile '{}'", name));
        api_.delete_profile(candidate.id);
    }

    say(std::format("Creating provisioning profile '{}'", name));
    const Profile created =
        api_.create_profile(name, bundle.id, {stored.remote_id}, {device.id});
    ProvisioningProfile profile = ProvisioningProfile::parse(created.content);
    if (!profile.includes_device(request.device_udid)) {
        throw ProfileError("Apple returned a profile that does not include the device");
    }
    plist::Value entitlements = make_entitlements(profile, request.bundle_id);
    return ProvisionResult{std::move(stored.identity), std::move(profile), std::move(entitlements)};
}

}  // namespace winx::auth
