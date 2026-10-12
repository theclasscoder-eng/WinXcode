#pragma once

#include <chrono>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

// Thin RAII layer over WinSock2. <winsock2.h> stays out of this header.
namespace winx::net {

class SocketError : public std::runtime_error {
public:
    SocketError(const std::string& context, int code);
    // WSA error code, or 0 when the peer closed the connection cleanly.
    int code() const noexcept { return code_; }

private:
    int code_;
};

class ConnectionClosed : public SocketError {
public:
    ConnectionClosed();
};

// Pairs WSAStartup with WSACleanup.
class WsaSession {
public:
    WsaSession();
    ~WsaSession();
    WsaSession(const WsaSession&) = delete;
    WsaSession& operator=(const WsaSession&) = delete;
};

// Starts WinSock once for the lifetime of the process. Every entry point in
// this header calls it, so explicit WsaSession objects are optional.
void ensure_winsock();

// A reliable byte stream: a TCP socket, or TLS layered over one.
class Stream {
public:
    virtual ~Stream() = default;
    virtual void send_all(std::span<const std::uint8_t> data) = 0;
    // Returns 0 when the peer closed the connection.
    virtual std::size_t recv_some(std::span<std::uint8_t> out) = 0;
    virtual bool wait_readable(std::chrono::milliseconds timeout) = 0;
    // Throws ConnectionClosed if the peer closes before `out` is filled.
    void recv_exact(std::span<std::uint8_t> out);
};

class Socket : public Stream {
public:
    using Handle = std::uintptr_t;
    static constexpr Handle kInvalid = ~Handle{0};

    Socket() noexcept = default;
    explicit Socket(Handle handle) noexcept : handle_(handle) {}
    Socket(Socket&& other) noexcept : handle_(std::exchange(other.handle_, kInvalid)) {}
    Socket& operator=(Socket&& other) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    ~Socket() override;

    static Socket connect_tcp(std::string_view host, std::uint16_t port);

    bool valid() const noexcept { return handle_ != kInvalid; }
    Handle native() const noexcept { return handle_; }
    void close() noexcept;

    void send_all(std::span<const std::uint8_t> data) override;
    std::size_t recv_some(std::span<std::uint8_t> out) override;
    bool wait_readable(std::chrono::milliseconds timeout) override;
    // Zero means block indefinitely.
    void set_timeouts(std::chrono::milliseconds receive, std::chrono::milliseconds send);

private:
    Handle handle_ = kInvalid;
};

class TcpListener {
public:
    // Port 0 picks a free ephemeral port.
    static TcpListener bind_loopback(std::uint16_t port = 0);

    std::uint16_t port() const noexcept { return port_; }
    // Throws SocketError(WSAETIMEDOUT) if nothing connects in time.
    Socket accept(std::chrono::milliseconds timeout = std::chrono::seconds(5));

private:
    Socket socket_;
    std::uint16_t port_ = 0;
};

}  // namespace winx::net
