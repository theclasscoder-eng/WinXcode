#include "winx/crypto.hpp"

#include <windows.h>

#include <bcrypt.h>

#include <format>
#include <utility>

namespace winx::crypto {
namespace {

void check(NTSTATUS status, const char* what) {
    if (!BCRYPT_SUCCESS(status)) {
        throw CryptoError(std::format("{} failed (0x{:08X})", what, static_cast<unsigned>(status)));
    }
}

class Provider {
public:
    Provider(LPCWSTR algorithm, ULONG flags, LPCWSTR chaining_mode = nullptr) {
        check(BCryptOpenAlgorithmProvider(&handle_, algorithm, nullptr, flags),
              "BCryptOpenAlgorithmProvider");
        if (chaining_mode) {
            check(BCryptSetProperty(handle_, BCRYPT_CHAINING_MODE,
                                    reinterpret_cast<PUCHAR>(const_cast<LPWSTR>(chaining_mode)),
                                    static_cast<ULONG>((wcslen(chaining_mode) + 1) * sizeof(wchar_t)),
                                    0),
                  "BCryptSetProperty(chaining mode)");
        }
    }
    ~Provider() { BCryptCloseAlgorithmProvider(handle_, 0); }
    Provider(const Provider&) = delete;
    Provider& operator=(const Provider&) = delete;
    BCRYPT_ALG_HANDLE get() const { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

BCRYPT_ALG_HANDLE hash_provider(HashAlgorithm algorithm, bool keyed) {
    switch (algorithm) {
        case HashAlgorithm::Sha1: {
            static const Provider plain(BCRYPT_SHA1_ALGORITHM, 0);
            static const Provider hmac(BCRYPT_SHA1_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            return keyed ? hmac.get() : plain.get();
        }
        case HashAlgorithm::Sha256: {
            static const Provider plain(BCRYPT_SHA256_ALGORITHM, 0);
            static const Provider hmac(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            return keyed ? hmac.get() : plain.get();
        }
        case HashAlgorithm::Sha384: {
            static const Provider plain(BCRYPT_SHA384_ALGORITHM, 0);
            static const Provider hmac(BCRYPT_SHA384_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            return keyed ? hmac.get() : plain.get();
        }
    }
    throw CryptoError("unknown hash algorithm");
}

class SymmetricKey {
public:
    SymmetricKey(BCRYPT_ALG_HANDLE provider, ByteView key) {
        if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
            throw CryptoError("AES key must be 16, 24 or 32 bytes");
        }
        check(BCryptGenerateSymmetricKey(provider, &handle_, nullptr, 0,
                                         const_cast<PUCHAR>(key.data()),
                                         static_cast<ULONG>(key.size()), 0),
              "BCryptGenerateSymmetricKey");
    }
    ~SymmetricKey() { BCryptDestroyKey(handle_); }
    SymmetricKey(const SymmetricKey&) = delete;
    SymmetricKey& operator=(const SymmetricKey&) = delete;
    BCRYPT_KEY_HANDLE get() const { return handle_; }

private:
    BCRYPT_KEY_HANDLE handle_ = nullptr;
};

BCRYPT_ALG_HANDLE cbc_provider() {
    static const Provider provider(BCRYPT_AES_ALGORITHM, 0, BCRYPT_CHAIN_MODE_CBC);
    return provider.get();
}

BCRYPT_ALG_HANDLE gcm_provider() {
    static const Provider provider(BCRYPT_AES_ALGORITHM, 0, BCRYPT_CHAIN_MODE_GCM);
    return provider.get();
}

Bytes aes_cbc(bool encrypt, ByteView key, ByteView iv, ByteView input) {
    if (iv.size() != 16) throw CryptoError("AES-CBC IV must be 16 bytes");
    const SymmetricKey handle(cbc_provider(), key);
    const auto run = [&](PUCHAR out, ULONG capacity, ULONG& written) {
        Bytes iv_copy(iv.begin(), iv.end());  // CNG updates the IV in place
        const auto in = const_cast<PUCHAR>(input.data());
        const auto size = static_cast<ULONG>(input.size());
        return encrypt ? BCryptEncrypt(handle.get(), in, size, nullptr, iv_copy.data(), 16, out,
                                       capacity, &written, BCRYPT_BLOCK_PADDING)
                       : BCryptDecrypt(handle.get(), in, size, nullptr, iv_copy.data(), 16, out,
                                       capacity, &written, BCRYPT_BLOCK_PADDING);
    };
    ULONG needed = 0;
    check(run(nullptr, 0, needed), encrypt ? "AES-CBC encrypt" : "AES-CBC decrypt");
    Bytes out(needed);
    ULONG written = 0;
    check(run(out.data(), needed, written), encrypt ? "AES-CBC encrypt" : "AES-CBC decrypt");
    out.resize(written);
    return out;
}

}  // namespace

std::size_t digest_size(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::Sha1: return 20;
        case HashAlgorithm::Sha256: return 32;
        case HashAlgorithm::Sha384: return 48;
    }
    throw CryptoError("unknown hash algorithm");
}

Hasher::Hasher(HashAlgorithm algorithm, ByteView key, bool keyed)
    : digest_size_(digest_size(algorithm)) {
    BCRYPT_HASH_HANDLE handle = nullptr;
    check(BCryptCreateHash(hash_provider(algorithm, keyed), &handle, nullptr, 0,
                           keyed ? const_cast<PUCHAR>(key.data()) : nullptr,
                           keyed ? static_cast<ULONG>(key.size()) : 0, 0),
          "BCryptCreateHash");
    handle_ = handle;
}

Hasher::Hasher(HashAlgorithm algorithm) : Hasher(algorithm, {}, false) {}

Hasher Hasher::hmac(HashAlgorithm algorithm, ByteView key) { return Hasher(algorithm, key, true); }

Hasher::Hasher(Hasher&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)), digest_size_(other.digest_size_) {}

Hasher::~Hasher() {
    if (handle_) BCryptDestroyHash(handle_);
}

Hasher& Hasher::update(ByteView data) {
    // BCryptHashData takes a 32-bit length.
    while (!data.empty()) {
        const std::size_t chunk = data.size() > 0x40000000 ? 0x40000000 : data.size();
        check(BCryptHashData(handle_, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(chunk), 0),
              "BCryptHashData");
        data = data.subspan(chunk);
    }
    return *this;
}

Hasher& Hasher::update(std::string_view text) { return update(as_bytes(text)); }

Bytes Hasher::finish() {
    Bytes out(digest_size_);
    check(BCryptFinishHash(handle_, out.data(), static_cast<ULONG>(out.size()), 0),
          "BCryptFinishHash");
    return out;
}

Bytes digest(HashAlgorithm algorithm, ByteView data) {
    return Hasher(algorithm).update(data).finish();
}

Bytes sha1(ByteView data) { return digest(HashAlgorithm::Sha1, data); }

Bytes sha256(ByteView data) { return digest(HashAlgorithm::Sha256, data); }

Bytes hmac_sha256(ByteView key, ByteView data) {
    return Hasher::hmac(HashAlgorithm::Sha256, key).update(data).finish();
}

Bytes pbkdf2_hmac_sha256(ByteView password, ByteView salt, std::uint64_t iterations,
                         std::size_t length) {
    Bytes out(length);
    check(BCryptDeriveKeyPBKDF2(hash_provider(HashAlgorithm::Sha256, true),
                                const_cast<PUCHAR>(password.data()),
                                static_cast<ULONG>(password.size()),
                                const_cast<PUCHAR>(salt.data()), static_cast<ULONG>(salt.size()),
                                iterations, out.data(), static_cast<ULONG>(out.size()), 0),
          "BCryptDeriveKeyPBKDF2");
    return out;
}

Bytes random_bytes(std::size_t count) {
    Bytes out(count);
    if (count == 0) return out;
    check(BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG),
          "BCryptGenRandom");
    return out;
}

Bytes aes_cbc_encrypt(ByteView key, ByteView iv, ByteView plaintext) {
    return aes_cbc(true, key, iv, plaintext);
}

Bytes aes_cbc_decrypt(ByteView key, ByteView iv, ByteView ciphertext) {
    return aes_cbc(false, key, iv, ciphertext);
}

GcmSealed aes_gcm_encrypt(ByteView key, ByteView nonce, ByteView plaintext, ByteView aad) {
    const SymmetricKey handle(gcm_provider(), key);
    GcmSealed sealed{Bytes(plaintext.size()), Bytes(16)};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce.data());
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = const_cast<PUCHAR>(aad.data());
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = sealed.tag.data();
    info.cbTag = static_cast<ULONG>(sealed.tag.size());
    ULONG written = 0;
    check(BCryptEncrypt(handle.get(), const_cast<PUCHAR>(plaintext.data()),
                        static_cast<ULONG>(plaintext.size()), &info, nullptr, 0,
                        sealed.ciphertext.data(), static_cast<ULONG>(sealed.ciphertext.size()),
                        &written, 0),
          "AES-GCM encrypt");
    return sealed;
}

Bytes aes_gcm_decrypt(ByteView key, ByteView nonce, ByteView ciphertext, ByteView tag,
                      ByteView aad) {
    const SymmetricKey handle(gcm_provider(), key);
    Bytes out(ciphertext.size());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce.data());
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = const_cast<PUCHAR>(aad.data());
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = const_cast<PUCHAR>(tag.data());
    info.cbTag = static_cast<ULONG>(tag.size());
    ULONG written = 0;
    const NTSTATUS status =
        BCryptDecrypt(handle.get(), const_cast<PUCHAR>(ciphertext.data()),
                      static_cast<ULONG>(ciphertext.size()), &info, nullptr, 0, out.data(),
                      static_cast<ULONG>(out.size()), &written, 0);
    if (!BCRYPT_SUCCESS(status)) throw CryptoError("AES-GCM decryption failed: bad key or tag");
    return out;
}

std::string to_hex(ByteView data, bool uppercase) {
    const char* digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (const std::uint8_t byte : data) {
        out += digits[byte >> 4];
        out += digits[byte & 0x0F];
    }
    return out;
}

std::optional<Bytes> from_hex(std::string_view text) {
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    Bytes out;
    int high = -1;
    for (const char c : text) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        const int value = nibble(c);
        if (value < 0) return std::nullopt;
        if (high < 0) {
            high = value;
        } else {
            out.push_back(static_cast<std::uint8_t>((high << 4) | value));
            high = -1;
        }
    }
    if (high >= 0) return std::nullopt;
    return out;
}

ByteView as_bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

}  // namespace winx::crypto
