#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "winx/crypto.hpp"
#include "winx/http.hpp"
#include "winx/keys.hpp"

// Apple's developer resources API (devices, bundle IDs, certificates,
// profiles). The same JSON:API schema is served to App Store Connect API keys
// and, through a different host and request envelope, to Apple ID sessions;
// the Transport hides which one is in use.
namespace winx::auth {

using json = nlohmann::json;
using Query = std::vector<std::pair<std::string, std::string>>;

class ApiError : public std::runtime_error {
public:
    ApiError(int status, std::string code, const std::string& message)
        : std::runtime_error(message), status_(status), code_(std::move(code)) {}
    int status() const noexcept { return status_; }
    // Apple's machine-readable code, e.g. "ENTITY_ERROR.ATTRIBUTE.INVALID".
    const std::string& code() const noexcept { return code_; }

private:
    int status_;
    std::string code_;
};

class Transport {
public:
    virtual ~Transport() = default;
    // `path` is the resource path, e.g. "/v1/devices". `body` may be null.
    virtual http::Response perform(std::string_view method, std::string_view path,
                                   const Query& query, const json* body) = 0;
};

// Official App Store Connect API with an ES256 bearer token.
class AscKeyTransport : public Transport {
public:
    AscKeyTransport(EcSigningKey key, std::string key_id, std::string issuer_id,
                    http::Sender sender,
                    std::string base_url = "https://api.appstoreconnect.apple.com");

    http::Response perform(std::string_view method, std::string_view path, const Query& query,
                           const json* body) override;

private:
    const std::string& token();

    EcSigningKey key_;
    std::string key_id_;
    std::string issuer_id_;
    http::Sender sender_;
    std::string base_url_;
    std::string token_;
    std::chrono::system_clock::time_point token_expiry_{};
};

struct Device {
    std::string id;
    std::string name;
    std::string udid;
    std::string platform;
    std::string status;
    std::string device_class;
    std::string model;
};

struct BundleId {
    std::string id;
    std::string identifier;
    std::string name;
    std::string platform;
    std::string seed_id;
};

struct Certificate {
    std::string id;
    std::string name;
    std::string display_name;
    std::string type;
    std::string serial_number;
    std::string expiration;
    crypto::Bytes content;  // DER
};

struct Profile {
    std::string id;
    std::string name;
    std::string uuid;
    std::string type;
    std::string state;
    std::string expiration;
    crypto::Bytes content;  // the .mobileprovision file
};

class DeveloperApi {
public:
    explicit DeveloperApi(std::shared_ptr<Transport> transport);

    std::vector<Device> list_devices(std::optional<std::string> udid = {});
    Device register_device(std::string_view name, std::string_view udid,
                           std::string_view platform = "IOS");

    std::vector<BundleId> list_bundle_ids(std::optional<std::string> identifier = {});
    BundleId create_bundle_id(std::string_view identifier, std::string_view name,
                              std::string_view platform = "IOS");

    std::vector<Certificate> list_certificates(std::optional<std::string> type = {});
    Certificate create_certificate(std::string_view csr_pem,
                                   std::string_view type = "DEVELOPMENT");
    void revoke_certificate(std::string_view id);

    std::vector<Profile> list_profiles(std::optional<std::string> name = {});
    Profile create_profile(std::string_view name, std::string_view bundle_id_resource,
                           const std::vector<std::string>& certificate_ids,
                           const std::vector<std::string>& device_ids,
                           std::string_view type = "IOS_APP_DEVELOPMENT");
    void delete_profile(std::string_view id);

private:
    json request(std::string_view method, std::string_view path, const Query& query,
                 const json* body);
    // Follows pagination and returns every element of `data`.
    std::vector<json> collect(std::string_view path, Query query);

    std::shared_ptr<Transport> transport_;
};

std::string encode_query(const Query& query);

}  // namespace winx::auth
