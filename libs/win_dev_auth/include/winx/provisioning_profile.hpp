#pragma once

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

#include "winx/crypto.hpp"
#include "winx/plist.hpp"

namespace winx::auth {

class ProfileError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// A .mobileprovision file: a CMS SignedData envelope around an XML plist.
struct ProvisioningProfile {
    std::string name;
    std::string uuid;
    std::string team_id;
    std::string team_name;
    std::string app_id_name;
    std::vector<std::string> provisioned_devices;
    bool provisions_all_devices = false;
    plist::Value entitlements;
    // DER certificates allowed to sign with this profile.
    std::vector<crypto::Bytes> developer_certificates;
    std::chrono::system_clock::time_point creation;
    std::chrono::system_clock::time_point expiration;
    // The original file, to be written to embedded.mobileprovision unchanged.
    crypto::Bytes raw;

    // Extracts the plist without checking Apple's signature on the envelope;
    // the device does that at install time.
    static ProvisioningProfile parse(crypto::ByteView raw);

    bool includes_device(std::string_view udid) const;
    bool includes_certificate(crypto::ByteView certificate_der) const;
    bool expired(std::chrono::system_clock::time_point now) const { return now >= expiration; }
    // "TEAMID.bundle.id" or a wildcard such as "TEAMID.*".
    std::string application_identifier() const;
    bool covers_bundle_id(std::string_view bundle_id) const;
};

// Entitlements to sign an app with: the profile's own, with wildcard
// identifiers resolved to the concrete bundle ID.
plist::Value make_entitlements(const ProvisioningProfile& profile, std::string_view bundle_id);

}  // namespace winx::auth
