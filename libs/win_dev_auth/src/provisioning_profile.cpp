#include "winx/provisioning_profile.hpp"

#include <windows.h>

#include <wincrypt.h>

#include <algorithm>
#include <cctype>

namespace winx::auth {
namespace {

constexpr std::int64_t kAppleEpochUnix = 978307200;

std::chrono::system_clock::time_point to_time_point(const plist::Value* value) {
    if (!value) return {};
    const auto* date = value->get_if<plist::Date>();
    if (!date) return {};
    return std::chrono::system_clock::time_point(
        std::chrono::seconds(static_cast<std::int64_t>(date->seconds) + kAppleEpochUnix));
}

bool equals_ignore_case(std::string_view a, std::string_view b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return std::tolower(static_cast<unsigned char>(x)) ==
                      std::tolower(static_cast<unsigned char>(y));
           });
}

crypto::Bytes cms_content(crypto::ByteView raw) {
    HCRYPTMSG message = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0,
                                             nullptr, nullptr);
    if (!message) throw ProfileError("cannot open the provisioning profile");
    crypto::Bytes content;
    bool ok = CryptMsgUpdate(message, raw.data(), static_cast<DWORD>(raw.size()), TRUE) != FALSE;
    DWORD size = 0;
    ok = ok && CryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0, nullptr, &size);
    if (ok) {
        content.resize(size);
        ok = CryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0, content.data(), &size) != FALSE;
        content.resize(size);
    }
    CryptMsgClose(message);
    if (!ok) throw ProfileError("the provisioning profile is not a valid CMS message");
    return content;
}

// Replaces a trailing ".*" wildcard with the concrete bundle ID.
std::string resolve_wildcard(const std::string& pattern, std::string_view team_id,
                             std::string_view bundle_id) {
    if (pattern.ends_with(".*") || pattern == "*") {
        return std::string(team_id) + "." + std::string(bundle_id);
    }
    return pattern;
}

}  // namespace

ProvisioningProfile ProvisioningProfile::parse(crypto::ByteView raw) {
    const crypto::Bytes content = cms_content(raw);
    plist::Value plist;
    try {
        plist = plist::parse(content);
    } catch (const plist::ParseError& error) {
        throw ProfileError(std::string("the provisioning profile payload is malformed: ") +
                           error.what());
    }
    if (!plist.is<plist::Dict>()) throw ProfileError("the provisioning profile payload is malformed");

    ProvisioningProfile profile;
    profile.raw.assign(raw.begin(), raw.end());
    profile.name = plist.string_at("Name").value_or("");
    profile.uuid = plist.string_at("UUID").value_or("");
    profile.team_name = plist.string_at("TeamName").value_or("");
    profile.app_id_name = plist.string_at("AppIDName").value_or("");
    profile.provisions_all_devices = plist.bool_at("ProvisionsAllDevices").value_or(false);
    profile.creation = to_time_point(plist.find("CreationDate"));
    profile.expiration = to_time_point(plist.find("ExpirationDate"));

    if (const plist::Value* teams = plist.find("TeamIdentifier")) {
        if (const auto* list = teams->get_if<plist::Array>(); list && !list->empty()) {
            if (const auto* first = list->front().get_if<std::string>()) profile.team_id = *first;
        }
    }
    if (const plist::Value* devices = plist.find("ProvisionedDevices")) {
        if (const auto* list = devices->get_if<plist::Array>()) {
            for (const plist::Value& device : *list) {
                if (const auto* udid = device.get_if<std::string>()) {
                    profile.provisioned_devices.push_back(*udid);
                }
            }
        }
    }
    if (const plist::Value* certificates = plist.find("DeveloperCertificates")) {
        if (const auto* list = certificates->get_if<plist::Array>()) {
            for (const plist::Value& certificate : *list) {
                if (const auto* data = certificate.get_if<plist::Data>()) {
                    profile.developer_certificates.push_back(data->bytes);
                }
            }
        }
    }
    if (const plist::Value* entitlements = plist.find("Entitlements")) {
        profile.entitlements = *entitlements;
    }
    if (!profile.entitlements.is<plist::Dict>()) {
        throw ProfileError("the provisioning profile has no Entitlements dictionary");
    }
    if (profile.team_id.empty()) {
        profile.team_id =
            profile.entitlements.string_at("com.apple.developer.team-identifier").value_or("");
    }
    return profile;
}

bool ProvisioningProfile::includes_device(std::string_view udid) const {
    if (provisions_all_devices) return true;
    return std::any_of(provisioned_devices.begin(), provisioned_devices.end(),
                       [&](const std::string& entry) { return equals_ignore_case(entry, udid); });
}

bool ProvisioningProfile::includes_certificate(crypto::ByteView certificate_der) const {
    return std::any_of(developer_certificates.begin(), developer_certificates.end(),
                       [&](const crypto::Bytes& entry) {
                           return std::equal(entry.begin(), entry.end(), certificate_der.begin(),
                                             certificate_der.end());
                       });
}

std::string ProvisioningProfile::application_identifier() const {
    return entitlements.string_at("application-identifier").value_or("");
}

bool ProvisioningProfile::covers_bundle_id(std::string_view bundle_id) const {
    const std::string pattern = application_identifier();
    const std::string prefix = team_id + ".";
    if (!pattern.starts_with(prefix)) return false;
    const std::string_view app = std::string_view(pattern).substr(prefix.size());
    if (app == "*") return true;
    if (app.ends_with(".*")) return bundle_id.starts_with(app.substr(0, app.size() - 1));
    return app == bundle_id;
}

plist::Value make_entitlements(const ProvisioningProfile& profile, std::string_view bundle_id) {
    if (!profile.covers_bundle_id(bundle_id)) {
        throw ProfileError("the provisioning profile '" + profile.name +
                           "' does not cover bundle ID " + std::string(bundle_id));
    }
    plist::Dict result;
    for (const auto& [key, value] : profile.entitlements.as_dict().items()) {
        if (key == "application-identifier") {
            result.set(key, resolve_wildcard(value.as_string(), profile.team_id, bundle_id));
        } else if (key == "keychain-access-groups" && value.is<plist::Array>()) {
            plist::Array groups;
            for (const plist::Value& group : value.as_array()) {
                if (const auto* text = group.get_if<std::string>()) {
                    groups.emplace_back(resolve_wildcard(*text, profile.team_id, bundle_id));
                } else {
                    groups.push_back(group);
                }
            }
            result.set(key, std::move(groups));
        } else {
            result.set(key, value);
        }
    }
    return result;
}

}  // namespace winx::auth
