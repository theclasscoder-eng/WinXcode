#include "winx/apple_id.hpp"

#include <format>

namespace winx::auth {
namespace {

constexpr const char* kXcodeApp = "com.apple.gs.xcode.auth";
constexpr const char* kXcodeVersion = "11.2 (11B41)";
constexpr const char* kClientId = "XABBG36SBA";
constexpr const char* kProtocolVersion = "QH65B2";

http::Headers session_headers(const XcodeCredentials& credentials, AnisetteProvider& anisette) {
    http::Headers headers = {{"User-Agent", "Xcode"},
                             {"Accept-Language", "en-us"},
                             {"X-Apple-App-Info", kXcodeApp},
                             {"X-Xcode-Version", kXcodeVersion},
                             {"X-Apple-I-Identity-Id", credentials.adsid},
                             {"X-Apple-GS-Token", credentials.token}};
    for (auto& header : anisette.fetch().headers()) headers.push_back(std::move(header));
    return headers;
}

std::string uuid_v4() {
    crypto::Bytes bytes = crypto::random_bytes(16);
    bytes[6] = static_cast<std::uint8_t>((bytes[6] & 0x0F) | 0x40);
    bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3F) | 0x80);
    const std::string hex = crypto::to_hex(bytes, true);
    return std::format("{}-{}-{}-{}-{}", hex.substr(0, 8), hex.substr(8, 4), hex.substr(12, 4),
                       hex.substr(16, 4), hex.substr(20, 12));
}

}  // namespace

XcodeTransport::XcodeTransport(XcodeCredentials credentials,
                               std::shared_ptr<AnisetteProvider> anisette, http::Sender sender,
                               std::string base_url)
    : credentials_(std::move(credentials)),
      anisette_(std::move(anisette)),
      sender_(std::move(sender)),
      base_url_(std::move(base_url)) {}

http::Response XcodeTransport::perform(std::string_view method, std::string_view path,
                                       const Query& query, const json* body) {
    http::Request request;
    request.method = "POST";
    request.url = base_url_ + std::string(path);
    request.headers = session_headers(credentials_, *anisette_);
    request.headers.emplace_back("Accept", "application/vnd.api+json");
    request.headers.emplace_back("Content-Type", "application/vnd.api+json");

    if (method == "GET" || method == "DELETE") {
        // Xcode tunnels reads and deletes through POST, with the query string
        // carried in the body.
        request.headers.emplace_back("X-HTTP-Method-Override", std::string(method));
        Query with_team = query;
        with_team.emplace_back("teamId", credentials_.team_id);
        request.body = json::object({{"urlEncodedQueryParams", encode_query(with_team)}}).dump();
    } else if (method == "POST" || method == "PATCH") {
        if (method == "PATCH") request.headers.emplace_back("X-HTTP-Method-Override", "PATCH");
        json payload = body ? *body : json::object();
        payload["data"]["attributes"]["teamId"] = credentials_.team_id;
        request.body = payload.dump();
    } else {
        throw ApiError(0, "", "unsupported HTTP method for Xcode developer services: " +
                                  std::string(method));
    }
    return sender_(request);
}

std::vector<Team> XcodeTransport::list_teams(const XcodeCredentials& credentials,
                                             AnisetteProvider& anisette,
                                             const http::Sender& sender,
                                             std::string_view base_url) {
    const plist::Value body = plist::Dict{{"clientId", kClientId},
                                          {"protocolVersion", kProtocolVersion},
                                          {"requestId", uuid_v4()},
                                          {"userLocale", plist::Array{"en_US"}}};
    http::Request request;
    request.method = "POST";
    request.url = std::format("{}/{}/listTeams.action?clientId={}", base_url, kProtocolVersion,
                              kClientId);
    request.headers = session_headers(credentials, anisette);
    request.headers.emplace_back("Content-Type", "text/x-xml-plist");
    request.headers.emplace_back("Accept", "text/x-xml-plist");
    request.body = plist::to_xml(body);

    const http::Response response = sender(request);
    if (!response.ok()) {
        throw ApiError(response.status, "",
                       std::format("could not list developer teams (HTTP {})", response.status));
    }
    const plist::Value reply = plist::parse(crypto::as_bytes(response.body));
    const std::int64_t result_code = reply.int_at("resultCode").value_or(0);
    if (result_code != 0) {
        throw ApiError(response.status, std::to_string(result_code),
                       "could not list developer teams: " +
                           reply.string_at("userString")
                               .value_or(reply.string_at("resultString").value_or("unknown error")));
    }

    std::vector<Team> teams;
    if (const plist::Value* list = reply.find("teams"); list && list->is<plist::Array>()) {
        for (const plist::Value& entry : list->as_array()) {
            Team team;
            team.id = entry.string_at("teamId").value_or("");
            team.name = entry.string_at("name").value_or("");
            team.type = entry.string_at("type").value_or("");
            team.free = entry.bool_at("xcodeFreeOnly").value_or(false);
            if (!team.id.empty()) teams.push_back(std::move(team));
        }
    }
    return teams;
}

}  // namespace winx::auth
