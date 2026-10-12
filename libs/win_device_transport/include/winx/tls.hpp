#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "winx/crypto.hpp"
#include "winx/socket.hpp"

// TLS over an already-connected stream, using SChannel. lockdownd upgrades a
// plain connection to TLS in place, so the usual "open a TLS socket" APIs do
// not fit.
namespace winx::device {

class TlsError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct TlsIdentity {
    crypto::Bytes certificate;  // DER
    // Name of the CNG key holding the matching private key. SChannel runs in
    // another process and can only use keys that are stored under a name.
    std::wstring key_name;
};

// Imports a PEM RSA private key ("RSA PRIVATE KEY" or "PRIVATE KEY") into the
// current user's CNG key store under `key_name`, replacing any existing key.
void import_rsa_private_key(std::string_view pem, std::wstring_view key_name);
bool remove_private_key(std::wstring_view key_name);
// DER of the first CERTIFICATE block.
crypto::Bytes certificate_from_pem(std::string_view pem);

struct TlsOptions {
    // Act as the TLS server. Used by the test suite to stand in for a device.
    bool server = false;
    std::optional<TlsIdentity> identity;

    // How a client decides whether to trust the server. Exactly one applies:
    // Windows' own validation for `server_name`, or the pinned lists below.
    bool system_trust = false;
    std::wstring server_name;
    // The peer's leaf certificate must equal one of these...
    std::vector<crypto::Bytes> accepted_peers;
    // ...or be signed by one of these.
    std::vector<crypto::Bytes> accepted_issuers;

    // Server only: ask the client for a certificate.
    bool request_client_certificate = false;
};

class TlsStream : public net::Stream {
public:
    // Runs the handshake on `transport` and takes ownership of it. Throws
    // TlsError if the handshake fails or the peer is not trusted.
    static std::unique_ptr<TlsStream> handshake(std::unique_ptr<net::Stream> transport,
                                                const TlsOptions& options);
    ~TlsStream() override;

    void send_all(std::span<const std::uint8_t> data) override;
    std::size_t recv_some(std::span<std::uint8_t> out) override;
    bool wait_readable(std::chrono::milliseconds timeout) override;

    // DER of the certificate the peer presented; empty if it sent none.
    const crypto::Bytes& peer_certificate() const noexcept;

private:
    struct Impl;
    explicit TlsStream(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

}  // namespace winx::device
