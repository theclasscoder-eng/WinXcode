#include "winx/developer_api.hpp"

#include <format>

#include "winx/base64.hpp"

namespace winx::auth {
namespace {

constexpr const char* kPageSize = "200";

std::string text(const json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string()) return {};
    return it->get<std::string>();
}

crypto::Bytes decode_content(const json& attributes, const char* key) {
    auto bytes = base64_decode(text(attributes, key));
    return bytes ? std::move(*bytes) : crypto::Bytes{};
}

const json& attributes_of(const json& resource) {
    static const json empty = json::object();
    const auto it = resource.find("attributes");
    return it != resource.end() && it->is_object() ? *it : empty;
}

Device to_device(const json& resource) {
    const json& a = attributes_of(resource);
    return {text(resource, "id"), text(a, "name"),        text(a, "udid"), text(a, "platform"),
            text(a, "status"),    text(a, "deviceClass"), text(a, "model")};
}

BundleId to_bundle_id(const json& resource) {
    const json& a = attributes_of(resource);
    return {text(resource, "id"), text(a, "identifier"), text(a, "name"), text(a, "platform"),
            text(a, "seedId")};
}

Certificate to_certificate(const json& resource) {
    const json& a = attributes_of(resource);
    return {text(resource, "id"),
            text(a, "name"),
            text(a, "displayName"),
            text(a, "certificateType"),
            text(a, "serialNumber"),
            text(a, "expirationDate"),
            decode_content(a, "certificateContent")};
}

Profile to_profile(const json& resource) {
    const json& a = attributes_of(resource);
    return {text(resource, "id"),
            text(a, "name"),
            text(a, "uuid"),
            text(a, "profileType"),
            text(a, "profileState"),
            text(a, "expirationDate"),
            decode_content(a, "profileContent")};
}

// Value of one query parameter in a URL, percent-decoded.
std::optional<std::string> query_parameter(std::string_view url, std::string_view name) {
    const auto question = url.find('?');
    if (question == std::string_view::npos) return std::nullopt;
    std::string_view rest = url.substr(question + 1);
    while (!rest.empty()) {
        const auto amp = rest.find('&');
        const std::string_view pair = rest.substr(0, amp);
        const auto equals = pair.find('=');
        if (equals != std::string_view::npos && pair.substr(0, equals) == name) {
            std::string value;
            const std::string_view raw = pair.substr(equals + 1);
            for (std::size_t i = 0; i < raw.size(); ++i) {
                if (raw[i] == '%' && i + 2 < raw.size()) {
                    const auto hex = crypto::from_hex(raw.substr(i + 1, 2));
                    if (hex && hex->size() == 1) {
                        value += static_cast<char>((*hex)[0]);
                        i += 2;
                        continue;
                    }
                }
                value += raw[i];
            }
            return value;
        }
        if (amp == std::string_view::npos) break;
        rest.remove_prefix(amp + 1);
    }
    return std::nullopt;
}

[[noreturn]] void throw_api_error(const http::Response& response) {
    std::string code;
    std::string message = std::format("HTTP {}", response.status);
    const json body = json::parse(response.body, nullptr, false);
    if (body.is_object() && body.contains("errors") && body["errors"].is_array() &&
        !body["errors"].empty()) {
        const json& first = body["errors"].front();
        code = text(first, "code");
        const std::string title = text(first, "title");
        const std::string detail = text(first, "detail");
        if (!title.empty() || !detail.empty()) {
            message = title;
            if (!detail.empty()) message += (message.empty() ? "" : ": ") + detail;
        }
    } else if (response.status == 401) {
        message = "not authorized; the credentials were rejected";
    }
    throw ApiError(response.status, std::move(code),
                   std::format("Apple developer API error ({}): {}", response.status, message));
}

}  // namespace

std::string encode_query(const Query& query) {
    std::string out;
    for (const auto& [name, value] : query) {
        if (!out.empty()) out += '&';
        out += http::url_encode(name) + "=" + http::url_encode(value);
    }
    return out;
}

AscKeyTransport::AscKeyTransport(EcSigningKey key, std::string key_id, std::string issuer_id,
                                 http::Sender sender, std::string base_url)
    : key_(std::move(key)),
      key_id_(std::move(key_id)),
      issuer_id_(std::move(issuer_id)),
      sender_(std::move(sender)),
      base_url_(std::move(base_url)) {}

const std::string& AscKeyTransport::token() {
    const auto now = std::chrono::system_clock::now();
    if (token_.empty() || now + std::chrono::minutes(1) >= token_expiry_) {
        const auto lifetime = std::chrono::minutes(15);
        token_ = make_asc_token(key_, key_id_, issuer_id_, now, lifetime);
        token_expiry_ = now + lifetime;
    }
    return token_;
}

http::Response AscKeyTransport::perform(std::string_view method, std::string_view path,
                                        const Query& query, const json* body) {
    http::Request request;
    request.method = std::string(method);
    request.url = base_url_ + std::string(path);
    if (!query.empty()) request.url += "?" + encode_query(query);
    request.headers = {{"Authorization", "Bearer " + token()}, {"Accept", "application/json"}};
    if (body) {
        request.headers.emplace_back("Content-Type", "application/json");
        request.body = body->dump();
    }
    return sender_(request);
}

DeveloperApi::DeveloperApi(std::shared_ptr<Transport> transport)
    : transport_(std::move(transport)) {}

json DeveloperApi::request(std::string_view method, std::string_view path, const Query& query,
                           const json* body) {
    const http::Response response = transport_->perform(method, path, query, body);
    if (!response.ok()) throw_api_error(response);
    if (response.body.empty()) return json::object();
    json parsed = json::parse(response.body, nullptr, false);
    if (parsed.is_discarded()) {
        throw ApiError(response.status, "", "Apple developer API returned a malformed response");
    }
    return parsed;
}

std::vector<json> DeveloperApi::collect(std::string_view path, Query query) {
    query.emplace_back("limit", kPageSize);
    std::vector<json> items;
    // Guards against a server that keeps returning the same cursor.
    for (int page = 0; page < 1000; ++page) {
        const json body = request("GET", path, query, nullptr);
        if (body.contains("data") && body["data"].is_array()) {
            for (const json& item : body["data"]) items.push_back(item);
        }
        std::string next;
        if (body.contains("links") && body["links"].is_object()) next = text(body["links"], "next");
        const auto cursor = query_parameter(next, "cursor");
        if (!cursor) break;
        std::erase_if(query, [](const auto& entry) { return entry.first == "cursor"; });
        query.emplace_back("cursor", *cursor);
    }
    return items;
}

std::vector<Device> DeveloperApi::list_devices(std::optional<std::string> udid) {
    Query query;
    if (udid) query.emplace_back("filter[udid]", *udid);
    std::vector<Device> devices;
    for (const json& item : collect("/v1/devices", std::move(query))) {
        devices.push_back(to_device(item));
    }
    return devices;
}

Device DeveloperApi::register_device(std::string_view name, std::string_view udid,
                                     std::string_view platform) {
    const json body = {
        {"data",
         {{"type", "devices"},
          {"attributes", {{"name", name}, {"udid", udid}, {"platform", platform}}}}}};
    return to_device(request("POST", "/v1/devices", {}, &body).at("data"));
}

std::vector<BundleId> DeveloperApi::list_bundle_ids(std::optional<std::string> identifier) {
    Query query;
    if (identifier) query.emplace_back("filter[identifier]", *identifier);
    std::vector<BundleId> bundle_ids;
    for (const json& item : collect("/v1/bundleIds", std::move(query))) {
        bundle_ids.push_back(to_bundle_id(item));
    }
    return bundle_ids;
}

BundleId DeveloperApi::create_bundle_id(std::string_view identifier, std::string_view name,
                                        std::string_view platform) {
    const json body = {
        {"data",
         {{"type", "bundleIds"},
          {"attributes", {{"identifier", identifier}, {"name", name}, {"platform", platform}}}}}};
    return to_bundle_id(request("POST", "/v1/bundleIds", {}, &body).at("data"));
}

std::vector<Certificate> DeveloperApi::list_certificates(std::optional<std::string> type) {
    Query query;
    if (type) query.emplace_back("filter[certificateType]", *type);
    std::vector<Certificate> certificates;
    for (const json& item : collect("/v1/certificates", std::move(query))) {
        certificates.push_back(to_certificate(item));
    }
    return certificates;
}

Certificate DeveloperApi::create_certificate(std::string_view csr_pem, std::string_view type) {
    const json body = {
        {"data",
         {{"type", "certificates"},
          {"attributes", {{"csrContent", csr_pem}, {"certificateType", type}}}}}};
    return to_certificate(request("POST", "/v1/certificates", {}, &body).at("data"));
}

void DeveloperApi::revoke_certificate(std::string_view id) {
    request("DELETE", "/v1/certificates/" + std::string(id), {}, nullptr);
}

std::vector<Profile> DeveloperApi::list_profiles(std::optional<std::string> name) {
    Query query;
    if (name) query.emplace_back("filter[name]", *name);
    std::vector<Profile> profiles;
    for (const json& item : collect("/v1/profiles", std::move(query))) {
        profiles.push_back(to_profile(item));
    }
    return profiles;
}

Profile DeveloperApi::create_profile(std::string_view name, std::string_view bundle_id_resource,
                                     const std::vector<std::string>& certificate_ids,
                                     const std::vector<std::string>& device_ids,
                                     std::string_view type) {
    json certificates = json::array();
    for (const std::string& id : certificate_ids) {
        certificates.push_back({{"type", "certificates"}, {"id", id}});
    }
    json devices = json::array();
    for (const std::string& id : device_ids) devices.push_back({{"type", "devices"}, {"id", id}});

    const json body = {
        {"data",
         {{"type", "profiles"},
          {"attributes", {{"name", name}, {"profileType", type}}},
          {"relationships",
           {{"bundleId", {{"data", {{"type", "bundleIds"}, {"id", bundle_id_resource}}}}},
            {"certificates", {{"data", certificates}}},
            {"devices", {{"data", devices}}}}}}}};
    return to_profile(request("POST", "/v1/profiles", {}, &body).at("data"));
}

void DeveloperApi::delete_profile(std::string_view id) {
    request("DELETE", "/v1/profiles/" + std::string(id), {}, nullptr);
}

}  // namespace winx::auth
