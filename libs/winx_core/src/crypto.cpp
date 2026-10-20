#include "winx/crypto.hpp"

#include <windows.h>

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
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

BCRYPT_ALG_HANDLE ecb_provider() {
    static const Provider provider(BCRYPT_AES_ALGORITHM, 0, BCRYPT_CHAIN_MODE_ECB);
    return provider.get();
}

// ---- GCM for nonces CNG refuses -------------------------------------------
// CNG's GCM takes only 96-bit nonces, but Apple's GrandSlam uses 128-bit
// ones. NIST SP 800-38D defines the general case: the pre-counter block J0
// is GHASH of the nonce instead of nonce || 1. This implements that case on
// top of raw AES blocks; 96-bit nonces still go to CNG.

using Block = std::array<std::uint8_t, 16>;

// Multiplication in GF(2^128) with GCM's bit order (SP 800-38D, 6.3).
Block gf_multiply(const Block& x, const Block& y) {
    Block z{};
    Block v = y;
    for (int i = 0; i < 128; ++i) {
        if ((x[static_cast<std::size_t>(i / 8)] >> (7 - i % 8)) & 1) {
            for (std::size_t j = 0; j < 16; ++j) z[j] ^= v[j];
        }
        const bool carry = (v[15] & 1) != 0;
        for (std::size_t j = 15; j > 0; --j) {
            v[j] = static_cast<std::uint8_t>((v[j] >> 1) | (v[j - 1] << 7));
        }
        v[0] >>= 1;
        if (carry) v[0] ^= 0xE1;
    }
    return z;
}

class Ghash {
public:
    explicit Ghash(const Block& h) : h_(h) {}

    // Absorbs `data` zero-padded to a whole number of blocks.
    void update(ByteView data) {
        for (std::size_t offset = 0; offset < data.size(); offset += 16) {
            const std::size_t count = std::min<std::size_t>(16, data.size() - offset);
            for (std::size_t i = 0; i < count; ++i) y_[i] ^= data[offset + i];
            y_ = gf_multiply(y_, h_);
        }
    }

    // Absorbs the closing block of two 64-bit bit lengths and returns the hash.
    Block finish(std::uint64_t first_bytes, std::uint64_t second_bytes) {
        Block lengths{};
        for (int i = 0; i < 8; ++i) {
            const auto at = static_cast<std::size_t>(i);
            lengths[7 - at] = static_cast<std::uint8_t>((first_bytes * 8) >> (8 * i));
            lengths[15 - at] = static_cast<std::uint8_t>((second_bytes * 8) >> (8 * i));
        }
        update(lengths);
        return y_;
    }

private:
    Block h_;
    Block y_{};
};

using BlockCipher = void (*)(const void* key, std::uint8_t* blocks, std::size_t count);

struct GcmState {
    Block j0{};
    Block h{};
};

GcmState gcm_start(BlockCipher cipher, const void* key, ByteView nonce) {
    GcmState state;
    cipher(key, state.h.data(), 1);
    Ghash ghash(state.h);
    ghash.update(nonce);
    state.j0 = ghash.finish(0, nonce.size());
    return state;
}

// CTR mode from inc32(J0), in place.
void gcm_ctr(BlockCipher cipher, const void* key, const Block& j0, std::span<std::uint8_t> data) {
    const std::size_t blocks = (data.size() + 15) / 16;
    if (blocks == 0) return;
    std::vector<std::uint8_t> stream(blocks * 16);
    std::uint32_t counter = (std::uint32_t{j0[12]} << 24) | (std::uint32_t{j0[13]} << 16) |
                            (std::uint32_t{j0[14]} << 8) | j0[15];
    for (std::size_t b = 0; b < blocks; ++b) {
        ++counter;
        std::uint8_t* block = stream.data() + b * 16;
        std::memcpy(block, j0.data(), 12);
        block[12] = static_cast<std::uint8_t>(counter >> 24);
        block[13] = static_cast<std::uint8_t>(counter >> 16);
        block[14] = static_cast<std::uint8_t>(counter >> 8);
        block[15] = static_cast<std::uint8_t>(counter);
    }
    cipher(key, stream.data(), blocks);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] ^= stream[i];
}

Block gcm_tag(BlockCipher cipher, const void* key, const GcmState& state, ByteView aad,
              ByteView ciphertext) {
    Ghash ghash(state.h);
    ghash.update(aad);
    ghash.update(ciphertext);
    const Block s = ghash.finish(aad.size(), ciphertext.size());
    Block tag = state.j0;
    cipher(key, tag.data(), 1);
    for (std::size_t i = 0; i < 16; ++i) tag[i] ^= s[i];
    return tag;
}

// ---- end of the general GCM case -------------------------------------------

void ecb_encrypt_blocks(const void* key, std::uint8_t* blocks, std::size_t count) {
    const auto handle = static_cast<BCRYPT_KEY_HANDLE>(const_cast<void*>(key));
    const auto size = static_cast<ULONG>(count * 16);
    ULONG written = 0;
    check(BCryptEncrypt(handle, blocks, size, nullptr, nullptr, 0, blocks, size, &written, 0),
          "AES-ECB encrypt");
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
    if (nonce.empty()) throw CryptoError("AES-GCM needs a nonce");
    if (nonce.size() != 12) {
        const SymmetricKey handle(ecb_provider(), key);
        const GcmState state = gcm_start(ecb_encrypt_blocks, handle.get(), nonce);
        GcmSealed sealed{Bytes(plaintext.begin(), plaintext.end()), {}};
        gcm_ctr(ecb_encrypt_blocks, handle.get(), state.j0, sealed.ciphertext);
        const Block tag = gcm_tag(ecb_encrypt_blocks, handle.get(), state, aad, sealed.ciphertext);
        sealed.tag.assign(tag.begin(), tag.end());
        return sealed;
    }
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
    if (nonce.empty()) throw CryptoError("AES-GCM needs a nonce");
    if (nonce.size() != 12) {
        const SymmetricKey handle(ecb_provider(), key);
        const GcmState state = gcm_start(ecb_encrypt_blocks, handle.get(), nonce);
        const Block expected = gcm_tag(ecb_encrypt_blocks, handle.get(), state, aad, ciphertext);
        // Constant-time comparison; a truncated tag compares its prefix, as CNG does.
        std::uint8_t difference = tag.size() < 12 || tag.size() > 16 ? 1 : 0;
        for (std::size_t i = 0; i < std::min<std::size_t>(tag.size(), 16); ++i) {
            difference |= static_cast<std::uint8_t>(expected[i] ^ tag[i]);
        }
        if (difference != 0) throw CryptoError("AES-GCM decryption failed: bad key or tag");
        Bytes out(ciphertext.begin(), ciphertext.end());
        gcm_ctr(ecb_encrypt_blocks, handle.get(), state.j0, out);
        return out;
    }
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
