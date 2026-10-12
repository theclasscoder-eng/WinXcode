#include "winx/apple_id.hpp"

#include <chrono>
#include <format>

#include "winx/base64.hpp"
#include "winx/files.hpp"

namespace winx::auth {
namespace {

constexpr const char* kLookupUrl = "https://gsa.apple.com/grandslam/GsService2/lookup";

std::string iso8601_now() {
    using namespace std::chrono;
    const auto now = floor<seconds>(system_clock::now());
    const auto date = floor<days>(now);
    const year_month_day ymd{date};
    const hh_mm_ss<seconds> clock{now - date};
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", static_cast<int>(ymd.year()),
                       static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()),
                       clock.hours().count(), clock.minutes().count(), clock.seconds().count());
}

std::string uuid_string(crypto::ByteView bytes) {
    const std::string hex = crypto::to_hex(bytes, true);
    return std::format("{}-{}-{}-{}-{}", hex.substr(0, 8), hex.substr(8, 4), hex.substr(12, 4),
                       hex.substr(16, 4), hex.substr(20, 12));
}

std::string websocket_url(std::string url) {
    if (url.starts_with("https://")) {
        url.replace(0, 5, "wss");
    } else if (url.starts_with("http://")) {
        url.replace(0, 4, "ws");
    }
    return url;
}

class WebSocketChannel : public TextChannel {
public:
    explicit WebSocketChannel(http::WebSocket socket) : socket_(std::move(socket)) {}
    void send(std::string_view text) override { socket_.send_text(text); }
    std::string receive() override { return socket_.receive_text(); }

private:
    http::WebSocket socket_;
};

std::string json_text(const json& object, const char* key) {
    const auto it = object.find(key);
    return it != object.end() && it->is_string() ? it->get<std::string>() : std::string{};
}

}  // namespace

http::Headers AnisetteData::headers() const {
    return {{"X-Apple-I-MD", one_time_password},
            {"X-Apple-I-MD-M", machine_id},
            {"X-Apple-I-MD-RINFO", routing_info},
            {"X-Apple-I-MD-LU", local_user_id},
            {"X-Mme-Device-Id", device_id},
            {"X-MMe-Client-Info", client_info},
            {"X-Apple-I-Client-Time", client_time},
            {"X-Apple-I-TimeZone", time_zone},
            {"X-Apple-Locale", locale},
            {"X-Apple-I-SRL-NO", "0"}};
}

ChannelFactory websocket_channel_factory(const http::Client& client) {
    return [client](const std::string& url) -> std::unique_ptr<TextChannel> {
        return std::make_unique<WebSocketChannel>(http::WebSocket::connect(client, url));
    };
}

RemoteAnisetteProvider::RemoteAnisetteProvider(Options options, http::Sender sender,
                                               ChannelFactory channels)
    : options_(std::move(options)), sender_(std::move(sender)), channels_(std::move(channels)) {
    while (options_.server_url.ends_with('/')) options_.server_url.pop_back();
}

RemoteAnisetteProvider::State RemoteAnisetteProvider::load_state() const {
    State state;
    if (options_.state_file.empty()) return state;
    try {
        const auto raw = secure::read_file(options_.state_file);
        if (!raw) return state;
        const json record = json::parse(raw->begin(), raw->end(), nullptr, false);
        if (!record.is_object()) return state;
        if (auto id = base64_decode(json_text(record, "identifier")); id && id->size() == 16) {
            state.identifier = std::move(*id);
            state.adi_pb = json_text(record, "adi_pb");
        }
    } catch (const std::exception&) {
        // Unreadable state (for example after a Windows profile reset) is
        // treated as absent; the machine is simply provisioned again.
    }
    return state;
}

void RemoteAnisetteProvider::save_state(const State& state) const {
    if (options_.state_file.empty()) return;
    const std::string text =
        json{{"identifier", base64_encode(state.identifier)}, {"adi_pb", state.adi_pb}}.dump();
    secure::write_file(options_.state_file, crypto::as_bytes(text));
}

void RemoteAnisetteProvider::reset() {
    std::error_code ec;
    if (!options_.state_file.empty()) std::filesystem::remove(options_.state_file, ec);
}

void RemoteAnisetteProvider::fetch_client_info() {
    http::Request request;
    request.url = options_.server_url + "/v3/client_info";
    const http::Response response = sender_(request);
    const json info = json::parse(response.body, nullptr, false);
    if (!response.ok() || !info.is_object()) {
        throw AppleIdError("the anisette server did not return client information");
    }
    client_info_ = json_text(info, "client_info");
    user_agent_ = json_text(info, "user_agent");
    if (client_info_.empty()) {
        throw AppleIdError("the anisette server returned empty client information");
    }
}

AnisetteData RemoteAnisetteProvider::base_data(const State& state) const {
    AnisetteData data;
    data.local_user_id =
        base64_encode(crypto::as_bytes(crypto::to_hex(crypto::sha256(state.identifier), true)));
    data.device_id = uuid_string(state.identifier);
    data.client_info = client_info_;
    data.user_agent = user_agent_;
    data.client_time = iso8601_now();
    return data;
}

std::string RemoteAnisetteProvider::provision(const State& state) {
    const AnisetteData identity = base_data(state);
    http::Headers apple_headers = {{"User-Agent", identity.user_agent},
                                   {"Content-Type", "text/x-xml-plist"},
                                   {"Accept", "*/*"},
                                   {"X-Apple-I-MD-LU", identity.local_user_id},
                                   {"X-Mme-Device-Id", identity.device_id},
                                   {"X-MMe-Client-Info", identity.client_info},
                                   {"X-Apple-I-Client-Time", identity.client_time},
                                   {"X-Apple-I-TimeZone", identity.time_zone},
                                   {"X-Apple-Locale", identity.locale}};

    const auto apple_plist = [&](const std::string& url, const std::string& method,
                                 const plist::Value* body) {
        http::Request request;
        request.method = method;
        request.url = url;
        request.headers = apple_headers;
        request.pinned_roots = options_.apple_roots;
        if (body) request.body = plist::to_xml(*body);
        const http::Response response = sender_(request);
        if (!response.ok()) {
            throw AppleIdError(std::format("Apple provisioning request failed (HTTP {})",
                                           response.status));
        }
        return plist::parse(crypto::as_bytes(response.body));
    };

    const plist::Value lookup = apple_plist(kLookupUrl, "GET", nullptr);
    const plist::Value* urls = lookup.find("urls");
    const std::string start_url = urls ? urls->string_at("midStartProvisioning").value_or("") : "";
    const std::string finish_url =
        urls ? urls->string_at("midFinishProvisioning").value_or("") : "";
    if (start_url.empty() || finish_url.empty()) {
        throw AppleIdError("Apple's service lookup did not list the provisioning endpoints");
    }

    const std::unique_ptr<TextChannel> channel =
        channels_(websocket_url(options_.server_url) + "/v3/provisioning_session");
    // The exchange is five messages long; the bound only stops a broken server.
    for (int step = 0; step < 16; ++step) {
        const json message = json::parse(channel->receive(), nullptr, false);
        if (!message.is_object()) throw AppleIdError("the anisette server sent a malformed message");
        const std::string result = json_text(message, "result");

        if (result == "GiveIdentifier") {
            channel->send(json::object({{"identifier", base64_encode(state.identifier)}}).dump());
        } else if (result == "GiveStartProvisioningData") {
            const plist::Value body =
                plist::Dict{{"Header", plist::Dict{}}, {"Request", plist::Dict{}}};
            const plist::Value reply = apple_plist(start_url, "POST", &body);
            const plist::Value* response = reply.find("Response");
            const std::string spim = response ? response->string_at("spim").value_or("") : "";
            if (spim.empty()) throw AppleIdError("Apple did not start machine provisioning");
            channel->send(json::object({{"spim", spim}}).dump());
        } else if (result == "GiveEndProvisioningData") {
            const plist::Value body = plist::Dict{
                {"Header", plist::Dict{}},
                {"Request", plist::Dict{{"cpim", json_text(message, "cpim")}}}};
            const plist::Value reply = apple_plist(finish_url, "POST", &body);
            const plist::Value* response = reply.find("Response");
            const std::string ptm = response ? response->string_at("ptm").value_or("") : "";
            const std::string tk = response ? response->string_at("tk").value_or("") : "";
            if (ptm.empty() || tk.empty()) {
                throw AppleIdError("Apple did not finish machine provisioning");
            }
            channel->send(json{{"ptm", ptm}, {"tk", tk}}.dump());
        } else if (result == "ProvisioningSuccess") {
            const std::string adi_pb = json_text(message, "adi_pb");
            if (adi_pb.empty()) throw AppleIdError("the anisette server returned no machine data");
            return adi_pb;
        } else {
            const std::string detail = json_text(message, "message");
            throw AppleIdError("anisette provisioning failed: " +
                               (detail.empty() ? result : detail));
        }
    }
    throw AppleIdError("anisette provisioning did not complete");
}

AnisetteData RemoteAnisetteProvider::fetch() {
    if (client_info_.empty()) fetch_client_info();

    State state = load_state();
    if (state.identifier.empty()) {
        state.identifier = crypto::random_bytes(16);
        state.adi_pb.clear();
    }

    std::string failure = "no response";
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (state.adi_pb.empty()) {
            state.adi_pb = provision(state);
            save_state(state);
        }
        http::Request request;
        request.method = "POST";
        request.url = options_.server_url + "/v3/get_headers";
        request.headers = {{"Content-Type", "application/json"}};
        request.body =
            json{{"identifier", base64_encode(state.identifier)}, {"adi_pb", state.adi_pb}}.dump();
        const http::Response response = sender_(request);
        const json headers = json::parse(response.body, nullptr, false);
        if (response.ok() && headers.is_object() && json_text(headers, "result") == "Headers") {
            AnisetteData data = base_data(state);
            data.one_time_password = json_text(headers, "X-Apple-I-MD");
            data.machine_id = json_text(headers, "X-Apple-I-MD-M");
            data.routing_info = json_text(headers, "X-Apple-I-MD-RINFO");
            if (data.routing_info.empty()) data.routing_info = "17106176";
            if (!data.one_time_password.empty() && !data.machine_id.empty()) return data;
            failure = "incomplete headers";
        } else {
            failure = headers.is_object() ? json_text(headers, "message")
                                          : std::format("HTTP {}", response.status);
        }
        // The stored machine identity may have been invalidated; provision once more.
        state.adi_pb.clear();
    }
    throw AppleIdError("the anisette server did not return machine headers: " + failure);
}

}  // namespace winx::auth
