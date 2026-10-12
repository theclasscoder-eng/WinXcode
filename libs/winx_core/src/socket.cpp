#include "winx/socket.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <format>
#include <limits>

#include "winx/text.hpp"

namespace winx::net {
namespace {

static_assert(sizeof(Socket::Handle) == sizeof(SOCKET));
static_assert(Socket::kInvalid == INVALID_SOCKET);

SOCKET raw(const Socket& socket) { return static_cast<SOCKET>(socket.native()); }

}  // namespace

SocketError::SocketError(const std::string& context, int code)
    : std::runtime_error(code == 0 ? context
                                   : std::format("{}: {} (WSA {})", context,
                                                 win32_error_message(static_cast<unsigned long>(code)),
                                                 code)),
      code_(code) {}

ConnectionClosed::ConnectionClosed() : SocketError("connection closed by peer", 0) {}

WsaSession::WsaSession() {
    WSADATA data{};
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) throw SocketError("WSAStartup failed", result);
}

WsaSession::~WsaSession() { WSACleanup(); }

void ensure_winsock() { static const WsaSession session; }

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = std::exchange(other.handle_, kInvalid);
    }
    return *this;
}

Socket::~Socket() { close(); }

void Socket::close() noexcept {
    if (handle_ != kInvalid) {
        closesocket(static_cast<SOCKET>(handle_));
        handle_ = kInvalid;
    }
}

Socket Socket::connect_tcp(std::string_view host, std::uint16_t port) {
    ensure_winsock();

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;

    const std::string host_text(host);
    const std::string port_text = std::to_string(port);
    addrinfo* results = nullptr;
    const int lookup = getaddrinfo(host_text.c_str(), port_text.c_str(), &hints, &results);
    if (lookup != 0) throw SocketError(std::format("cannot resolve {}", host_text), lookup);

    int last_error = WSAHOST_NOT_FOUND;
    Socket connected;
    for (const addrinfo* entry = results; entry != nullptr; entry = entry->ai_next) {
        const SOCKET handle = ::socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (handle == INVALID_SOCKET) {
            last_error = WSAGetLastError();
            continue;
        }
        Socket candidate(static_cast<Handle>(handle));
        if (::connect(handle, entry->ai_addr, static_cast<int>(entry->ai_addrlen)) == 0) {
            connected = std::move(candidate);
            break;
        }
        last_error = WSAGetLastError();
    }
    freeaddrinfo(results);

    if (!connected.valid()) {
        throw SocketError(std::format("cannot connect to {}:{}", host_text, port), last_error);
    }
    const BOOL no_delay = TRUE;
    setsockopt(raw(connected), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&no_delay),
               sizeof(no_delay));
    return connected;
}

void Socket::send_all(std::span<const std::uint8_t> data) {
    while (!data.empty()) {
        const int chunk =
            static_cast<int>(std::min<std::size_t>(data.size(), std::numeric_limits<int>::max()));
        const int sent = ::send(static_cast<SOCKET>(handle_),
                                reinterpret_cast<const char*>(data.data()), chunk, 0);
        if (sent == SOCKET_ERROR) throw SocketError("send failed", WSAGetLastError());
        data = data.subspan(static_cast<std::size_t>(sent));
    }
}

std::size_t Socket::recv_some(std::span<std::uint8_t> out) {
    const int chunk =
        static_cast<int>(std::min<std::size_t>(out.size(), std::numeric_limits<int>::max()));
    const int received =
        ::recv(static_cast<SOCKET>(handle_), reinterpret_cast<char*>(out.data()), chunk, 0);
    if (received == SOCKET_ERROR) throw SocketError("recv failed", WSAGetLastError());
    return static_cast<std::size_t>(received);
}

void Stream::recv_exact(std::span<std::uint8_t> out) {
    while (!out.empty()) {
        const std::size_t received = recv_some(out);
        if (received == 0) throw ConnectionClosed();
        out = out.subspan(received);
    }
}

bool Socket::wait_readable(std::chrono::milliseconds timeout) {
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(static_cast<SOCKET>(handle_), &readable);
    timeval wait{};
    wait.tv_sec = static_cast<long>(timeout.count() / 1000);
    wait.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
    const int ready = ::select(0, &readable, nullptr, nullptr, &wait);
    if (ready == SOCKET_ERROR) throw SocketError("select failed", WSAGetLastError());
    return ready > 0;
}

void Socket::set_timeouts(std::chrono::milliseconds receive, std::chrono::milliseconds send) {
    const DWORD receive_ms = static_cast<DWORD>(receive.count());
    const DWORD send_ms = static_cast<DWORD>(send.count());
    setsockopt(static_cast<SOCKET>(handle_), SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&receive_ms), sizeof(receive_ms));
    setsockopt(static_cast<SOCKET>(handle_), SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&send_ms), sizeof(send_ms));
}

TcpListener TcpListener::bind_loopback(std::uint16_t port) {
    ensure_winsock();

    const SOCKET handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle == INVALID_SOCKET) throw SocketError("socket failed", WSAGetLastError());
    TcpListener listener;
    listener.socket_ = Socket(static_cast<Socket::Handle>(handle));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (::bind(handle, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        throw SocketError("bind failed", WSAGetLastError());
    }
    if (::listen(handle, 8) != 0) throw SocketError("listen failed", WSAGetLastError());

    int length = sizeof(address);
    if (getsockname(handle, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        throw SocketError("getsockname failed", WSAGetLastError());
    }
    listener.port_ = ntohs(address.sin_port);
    return listener;
}

Socket TcpListener::accept(std::chrono::milliseconds timeout) {
    if (!socket_.wait_readable(timeout)) throw SocketError("accept timed out", WSAETIMEDOUT);
    const SOCKET handle = ::accept(raw(socket_), nullptr, nullptr);
    if (handle == INVALID_SOCKET) throw SocketError("accept failed", WSAGetLastError());
    return Socket(static_cast<Socket::Handle>(handle));
}

}  // namespace winx::net
