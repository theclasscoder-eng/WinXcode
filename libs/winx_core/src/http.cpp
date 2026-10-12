#include "winx/http.hpp"

#include <windows.h>

#include <wincrypt.h>
#include <winhttp.h>

#include <algorithm>
#include <cctype>
#include <format>

#include "winx/text.hpp"

namespace winx::http {
namespace {

class Handle {
public:
    Handle() = default;
    explicit Handle(HINTERNET handle) : handle_(handle) {}
    Handle(Handle&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { reset(); }

    void reset() {
        if (handle_) WinHttpCloseHandle(handle_);
        handle_ = nullptr;
    }
    HINTERNET get() const { return handle_; }
    HINTERNET release() { return std::exchange(handle_, nullptr); }
    explicit operator bool() const { return handle_ != nullptr; }

private:
    HINTERNET handle_ = nullptr;
};

[[noreturn]] void fail(std::string_view what, const std::string& url) {
    const DWORD code = GetLastError();
    std::string detail;
    switch (code) {
        case ERROR_WINHTTP_TIMEOUT: detail = "the request timed out"; break;
        case ERROR_WINHTTP_NAME_NOT_RESOLVED: detail = "the host name could not be resolved"; break;
        case ERROR_WINHTTP_CANNOT_CONNECT: detail = "could not connect to the server"; break;
        case ERROR_WINHTTP_SECURE_FAILURE: detail = "the TLS certificate was not trusted"; break;
        case ERROR_WINHTTP_CONNECTION_ERROR: detail = "the connection was reset"; break;
        default: detail = win32_error_message(code);
    }
    throw HttpError(std::format("{} failed for {}: {} (error {})", what, url, detail, code));
}

struct ParsedUrl {
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port = 0;
    bool secure = false;
};

ParsedUrl parse_url(const std::string& url) {
    const std::wstring wide = to_wide(url);
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = static_cast<DWORD>(-1);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wide.c_str(), static_cast<DWORD>(wide.size()), 0, &parts)) {
        throw HttpError("invalid URL: " + url);
    }
    ParsedUrl parsed;
    parsed.host.assign(parts.lpszHostName, parts.dwHostNameLength);
    parsed.path.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
    if (parts.lpszExtraInfo) parsed.path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    if (parsed.path.empty()) parsed.path = L"/";
    parsed.port = parts.nPort;
    parsed.secure = parts.nScheme == INTERNET_SCHEME_HTTPS;
    return parsed;
}

// Validates the server certificate against caller-supplied roots only.
bool chain_ends_in_pinned_root(PCCERT_CONTEXT server,
                               const std::vector<std::vector<std::uint8_t>>& roots,
                               const std::wstring& host) {
    HCERTSTORE root_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    if (!root_store) return false;
    for (const auto& der : roots) {
        CertAddEncodedCertificateToStore(root_store, X509_ASN_ENCODING, der.data(),
                                         static_cast<DWORD>(der.size()), CERT_STORE_ADD_ALWAYS,
                                         nullptr);
    }

    bool trusted = false;
    CERT_CHAIN_ENGINE_CONFIG config{};
    config.cbSize = sizeof(config);
    config.hExclusiveRoot = root_store;
    HCERTCHAINENGINE engine = nullptr;
    if (CertCreateCertificateChainEngine(&config, &engine)) {
        CERT_CHAIN_PARA chain_para{};
        chain_para.cbSize = sizeof(chain_para);
        PCCERT_CHAIN_CONTEXT chain = nullptr;
        if (CertGetCertificateChain(engine, server, nullptr, server->hCertStore, &chain_para, 0,
                                    nullptr, &chain)) {
            SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};
            ssl.cbSize = sizeof(ssl);
            ssl.dwAuthType = AUTHTYPE_SERVER;
            ssl.pwszServerName = const_cast<LPWSTR>(host.c_str());
            CERT_CHAIN_POLICY_PARA policy{};
            policy.cbSize = sizeof(policy);
            policy.pvExtraPolicyPara = &ssl;
            CERT_CHAIN_POLICY_STATUS status{};
            status.cbSize = sizeof(status);
            trusted = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &policy,
                                                       &status) &&
                      status.dwError == 0;
            CertFreeCertificateChain(chain);
        }
        CertFreeCertificateChainEngine(engine);
    }
    CertCloseStore(root_store, 0);
    return trusted;
}

struct PinContext {
    const std::vector<std::vector<std::uint8_t>>* roots = nullptr;
    std::wstring host;
    bool checked = false;
    bool trusted = false;
    // The callback closed the request handle.
    bool aborted = false;
};

// Runs after the TLS handshake and before any request bytes are sent.
void CALLBACK on_status(HINTERNET handle, DWORD_PTR context, DWORD status, LPVOID, DWORD) {
    if (status != WINHTTP_CALLBACK_STATUS_SENDING_REQUEST || context == 0) return;
    auto* pin = reinterpret_cast<PinContext*>(context);
    if (pin->checked) return;
    pin->checked = true;
    PCCERT_CONTEXT server = nullptr;
    DWORD size = sizeof(server);
    if (WinHttpQueryOption(handle, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &server, &size) && server) {
        pin->trusted = chain_ends_in_pinned_root(server, *pin->roots, pin->host);
        CertFreeCertificateContext(server);
    }
    if (!pin->trusted) {
        // Cancels the request before the headers and body go out.
        pin->aborted = true;
        WinHttpCloseHandle(handle);
    }
}

struct OpenedRequest {
    Handle connection;
    Handle request;
};

OpenedRequest open_request(HINTERNET session, const ParsedUrl& url, const std::string& method,
                           const Headers& headers, std::chrono::milliseconds timeout,
                           const std::string& original_url) {
    OpenedRequest opened;
    opened.connection = Handle(WinHttpConnect(session, url.host.c_str(), url.port, 0));
    if (!opened.connection) fail("connect", original_url);
    opened.request = Handle(
        WinHttpOpenRequest(opened.connection.get(), to_wide(method).c_str(), url.path.c_str(),
                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                           url.secure ? WINHTTP_FLAG_SECURE : 0));
    if (!opened.request) fail("open request", original_url);

    const int ms = static_cast<int>(timeout.count());
    WinHttpSetTimeouts(opened.request.get(), ms, ms, ms, ms);
    DWORD decompression = WINHTTP_DECOMPRESSION_FLAG_ALL;
    WinHttpSetOption(opened.request.get(), WINHTTP_OPTION_DECOMPRESSION, &decompression,
                     sizeof(decompression));

    for (const auto& [name, value] : headers) {
        const std::wstring line = to_wide(name + ": " + value);
        if (!WinHttpAddRequestHeaders(opened.request.get(), line.c_str(),
                                      static_cast<DWORD>(line.size()),
                                      WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
            fail("add header", original_url);
        }
    }
    return opened;
}

Headers read_headers(HINTERNET request) {
    DWORD size = 0;
    WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                        nullptr, &size, WINHTTP_NO_HEADER_INDEX);
    std::wstring raw(size / sizeof(wchar_t), L'\0');
    if (size == 0 ||
        !WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                             raw.data(), &size, WINHTTP_NO_HEADER_INDEX)) {
        return {};
    }
    raw.resize(size / sizeof(wchar_t));
    const std::string text = to_utf8(raw);
    Headers headers;
    std::size_t pos = 0;
    while (pos < text.size()) {
        auto end = text.find("\r\n", pos);
        if (end == std::string::npos) end = text.size();
        const std::string_view line(text.data() + pos, end - pos);
        const auto colon = line.find(':');
        if (colon != std::string_view::npos) {
            std::string_view value = line.substr(colon + 1);
            while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
            headers.emplace_back(std::string(line.substr(0, colon)), std::string(value));
        }
        pos = end + 2;
    }
    return headers;
}

}  // namespace

struct Client::Session {
    Handle handle;
};

std::optional<std::string> Response::header(std::string_view name) const {
    for (const auto& [key, value] : headers) {
        if (key.size() == name.size() &&
            std::equal(key.begin(), key.end(), name.begin(), [](char a, char b) {
                return std::tolower(static_cast<unsigned char>(a)) ==
                       std::tolower(static_cast<unsigned char>(b));
            })) {
            return value;
        }
    }
    return std::nullopt;
}

Client::Client(std::string_view user_agent) : session_(std::make_shared<Session>()) {
    session_->handle = Handle(WinHttpOpen(to_wide(user_agent).c_str(),
                                          WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                                          WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session_->handle) {
        throw HttpError("WinHttpOpen failed: " + win32_error_message(GetLastError()));
    }
}

Sender Client::sender() const {
    return [client = *this](const Request& request) { return client.send(request); };
}

Response Client::send(const Request& request) const {
    const ParsedUrl url = parse_url(request.url);
    OpenedRequest opened = open_request(session_->handle.get(), url, request.method,
                                        request.headers, request.timeout, request.url);
    const HINTERNET handle = opened.request.get();

    PinContext pin;
    const bool pinned = url.secure && !request.pinned_roots.empty();
    if (pinned) {
        pin.roots = &request.pinned_roots;
        pin.host = url.host;
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
        WinHttpSetOption(handle, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
        WinHttpSetStatusCallback(handle, on_status, WINHTTP_CALLBACK_FLAG_SEND_REQUEST, 0);
    }

    const BOOL sent = WinHttpSendRequest(
        handle, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        request.body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(request.body.data()),
        static_cast<DWORD>(request.body.size()), static_cast<DWORD>(request.body.size()),
        pinned ? reinterpret_cast<DWORD_PTR>(&pin) : 0);
    if (pin.aborted) opened.request.release();  // already closed by the callback
    if (pinned && !pin.trusted) {
        throw HttpError(std::format("TLS certificate for {} does not chain to a pinned root",
                                    to_utf8(url.host)));
    }
    if (!sent) fail("send", request.url);
    if (!WinHttpReceiveResponse(handle, nullptr)) fail("receive", request.url);

    Response response;
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    WinHttpQueryHeaders(handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                        WINHTTP_NO_HEADER_INDEX);
    response.status = static_cast<int>(status);
    response.headers = read_headers(handle);

    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(handle, &available)) fail("read", request.url);
        if (available == 0) break;
        const std::size_t offset = response.body.size();
        response.body.resize(offset + available);
        DWORD read = 0;
        if (!WinHttpReadData(handle, response.body.data() + offset, available, &read)) {
            fail("read", request.url);
        }
        response.body.resize(offset + read);
        if (read == 0) break;
    }
    return response;
}

WebSocket WebSocket::connect(const Client& client, std::string_view url, const Headers& headers) {
    std::string http_url(url);
    if (http_url.starts_with("wss://")) {
        http_url.replace(0, 3, "https");
    } else if (http_url.starts_with("ws://")) {
        http_url.replace(0, 2, "http");
    }
    const ParsedUrl parsed = parse_url(http_url);
    OpenedRequest opened = open_request(client.session_->handle.get(), parsed, "GET", headers,
                                        std::chrono::seconds(30), http_url);
    const HINTERNET request = opened.request.get();
    if (!WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
        fail("websocket upgrade", http_url);
    }
    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0,
                            0, 0) ||
        !WinHttpReceiveResponse(request, nullptr)) {
        fail("websocket handshake", http_url);
    }
    const HINTERNET socket = WinHttpWebSocketCompleteUpgrade(request, 0);
    if (!socket) fail("websocket upgrade", http_url);
    return WebSocket(socket);
}

WebSocket::~WebSocket() {
    if (handle_) {
        WinHttpWebSocketClose(handle_, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
        WinHttpCloseHandle(handle_);
    }
}

void WebSocket::send_text(std::string_view text) {
    const DWORD result =
        WinHttpWebSocketSend(handle_, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                             const_cast<char*>(text.data()), static_cast<DWORD>(text.size()));
    if (result != ERROR_SUCCESS) {
        throw HttpError("websocket send failed: " + win32_error_message(result));
    }
}

std::string WebSocket::receive_text() {
    std::string message;
    char buffer[8192];
    for (;;) {
        DWORD read = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
        const DWORD result = WinHttpWebSocketReceive(handle_, buffer, sizeof(buffer), &read, &type);
        if (result != ERROR_SUCCESS) {
            throw HttpError("websocket receive failed: " + win32_error_message(result));
        }
        if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            throw HttpError("websocket closed by the server");
        }
        message.append(buffer, read);
        if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE ||
            type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) {
            return message;
        }
    }
}

std::string url_encode(std::string_view text) {
    std::string out;
    for (const unsigned char c : text) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' ||
            c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += std::format("%{:02X}", c);
        }
    }
    return out;
}

}  // namespace winx::http
