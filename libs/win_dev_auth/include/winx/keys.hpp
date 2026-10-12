#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "winx/crypto.hpp"

// Asymmetric keys held by the Windows CNG key storage provider (ncrypt.dll).
// Keys given a name persist in the user's profile and are created
// non-exportable; keys without a name live only as long as the object.
namespace winx::auth {

class KeyError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// ECDSA P-256 key, as issued by App Store Connect in a .p8 file.
class EcSigningKey {
public:
    // `pem` is the PKCS#8 "PRIVATE KEY" block from the .p8 file.
    static EcSigningKey import_p8(std::string_view pem, std::wstring_view persist_name = {});
    static EcSigningKey open(std::wstring_view name);
    static bool remove(std::wstring_view name);

    EcSigningKey(EcSigningKey&& other) noexcept;
    EcSigningKey& operator=(EcSigningKey&& other) noexcept;
    EcSigningKey(const EcSigningKey&) = delete;
    EcSigningKey& operator=(const EcSigningKey&) = delete;
    ~EcSigningKey();

    // ECDSA over SHA-256(message), returned as raw r || s (64 bytes), which is
    // the JWS ES256 signature format.
    crypto::Bytes sign(crypto::ByteView message) const;
    bool verify(crypto::ByteView message, crypto::ByteView signature) const;

private:
    explicit EcSigningKey(std::uintptr_t handle) : handle_(handle) {}
    std::uintptr_t handle_ = 0;
};

// RSA-2048 key for an Apple Development signing certificate.
class RsaKey {
public:
    static RsaKey create(std::wstring_view persist_name = {}, bool exportable = false);
    static RsaKey open(std::wstring_view name);
    static bool remove(std::wstring_view name);

    RsaKey(RsaKey&& other) noexcept;
    RsaKey& operator=(RsaKey&& other) noexcept;
    RsaKey(const RsaKey&) = delete;
    RsaKey& operator=(const RsaKey&) = delete;
    ~RsaKey();

    // NCRYPT_KEY_HANDLE, for crypt32 calls that sign with this key.
    std::uintptr_t handle() const noexcept { return handle_; }
    const std::wstring& name() const noexcept { return name_; }
    // DER SubjectPublicKeyInfo.
    crypto::Bytes public_key_info() const;

private:
    RsaKey(std::uintptr_t handle, std::wstring name) : handle_(handle), name_(std::move(name)) {}
    std::uintptr_t handle_ = 0;
    std::wstring name_;
};

std::string base64url_encode(crypto::ByteView data);
std::optional<crypto::Bytes> base64url_decode(std::string_view text);

// ES256 JWT for the App Store Connect API. Apple rejects lifetimes over 20
// minutes.
std::string make_asc_token(const EcSigningKey& key, std::string_view key_id,
                           std::string_view issuer_id, std::chrono::system_clock::time_point now,
                           std::chrono::seconds lifetime = std::chrono::minutes(15));

}  // namespace winx::auth
