#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// HTTP and WebSocket client on WinHTTP.
namespace winx::http {

using Headers = std::vector<std::pair<std::string, std::string>>;

struct Request {
    std::string method = "GET";
    std::string url;
    Headers headers;
    std::string body;
    std::chrono::milliseconds timeout{30000};
    // DER-encoded root certificates. When non-empty the server chain must
    // terminate in one of them instead of a root from the Windows trust store.
    // Needed for Apple hosts such as gsa.apple.com that chain to Apple Root CA.
    std::vector<std::vector<std::uint8_t>> pinned_roots;
};

struct Response {
    int status = 0;
    Headers headers;
    std::string body;

    bool ok() const noexcept { return status >= 200 && status < 300; }
    // Case-insensitive.
    std::optional<std::string> header(std::string_view name) const;
};

class HttpError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// The seam used by everything above this layer, so tests can substitute a fake.
using Sender = std::function<Response(const Request&)>;

class Client {
public:
    explicit Client(std::string_view user_agent = "winx/0.1");

    Response send(const Request& request) const;
    Sender sender() const;

private:
    friend class WebSocket;
    struct Session;
    std::shared_ptr<Session> session_;
};

class WebSocket {
public:
    // Accepts ws:// and wss:// URLs.
    static WebSocket connect(const Client& client, std::string_view url,
                             const Headers& headers = {});
    WebSocket(WebSocket&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    WebSocket(const WebSocket&) = delete;
    WebSocket& operator=(const WebSocket&) = delete;
    ~WebSocket();

    void send_text(std::string_view text);
    // Throws HttpError when the peer closes the socket.
    std::string receive_text();

private:
    explicit WebSocket(void* handle) : handle_(handle) {}
    void* handle_ = nullptr;
};

std::string url_encode(std::string_view text);

}  // namespace winx::http
