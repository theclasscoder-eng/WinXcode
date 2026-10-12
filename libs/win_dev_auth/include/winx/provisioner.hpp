#pragma once

#include <functional>
#include <string>
#include <string_view>

#include "winx/developer_api.hpp"
#include "winx/identity.hpp"
#include "winx/plist.hpp"
#include "winx/provisioning_profile.hpp"

namespace winx::auth {

struct ProvisionRequest {
    std::string bundle_id;
    std::string device_udid;
    // Shown in the developer portal if the device has to be registered.
    std::string device_name = "iPhone";
    // Key under which the signing identity is stored: team ID or issuer ID.
    std::string account;
};

struct ProvisionResult {
    SigningIdentity identity;
    ProvisioningProfile profile;
    plist::Value entitlements;
};

// Makes sure everything needed to sign `bundle_id` for one device exists on
// Apple's side and locally, creating whatever is missing: device
// registration, bundle ID, development certificate and provisioning profile.
// It never revokes a certificate.
class Provisioner {
public:
    using Log = std::function<void(const std::string&)>;

    Provisioner(DeveloperApi& api, IdentityStore& identities, Log log = {});

    ProvisionResult provision(const ProvisionRequest& request);

    static std::string profile_name_for(std::string_view bundle_id);

private:
    Device ensure_device(const ProvisionRequest& request);
    BundleId ensure_bundle_id(const ProvisionRequest& request);
    IdentityStore::Stored ensure_identity(const ProvisionRequest& request);
    void say(const std::string& message) const;

    DeveloperApi& api_;
    IdentityStore& identities_;
    Log log_;
};

}  // namespace winx::auth
