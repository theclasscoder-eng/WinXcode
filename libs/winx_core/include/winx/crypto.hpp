#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// Hashing and symmetric crypto on Windows CNG (bcrypt.dll).
namespace winx::crypto {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

class CryptoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

enum class HashAlgorithm { Sha1, Sha256, Sha384 };

std::size_t digest_size(HashAlgorithm algorithm);

// Incremental hash or HMAC.
class Hasher {
public:
    explicit Hasher(HashAlgorithm algorithm);
    static Hasher hmac(HashAlgorithm algorithm, ByteView key);
    Hasher(Hasher&& other) noexcept;
    Hasher(const Hasher&) = delete;
    Hasher& operator=(const Hasher&) = delete;
    ~Hasher();

    Hasher& update(ByteView data);
    Hasher& update(std::string_view text);
    // The hasher cannot be used again afterwards.
    Bytes finish();

private:
    Hasher(HashAlgorithm algorithm, ByteView key, bool keyed);
    void* handle_ = nullptr;
    std::size_t digest_size_ = 0;
};

Bytes digest(HashAlgorithm algorithm, ByteView data);
Bytes sha1(ByteView data);
Bytes sha256(ByteView data);
Bytes hmac_sha256(ByteView key, ByteView data);
Bytes pbkdf2_hmac_sha256(ByteView password, ByteView salt, std::uint64_t iterations,
                         std::size_t length);

Bytes random_bytes(std::size_t count);

// AES with PKCS#7 padding; the key length selects AES-128/192/256.
Bytes aes_cbc_encrypt(ByteView key, ByteView iv, ByteView plaintext);
Bytes aes_cbc_decrypt(ByteView key, ByteView iv, ByteView ciphertext);

struct GcmSealed {
    Bytes ciphertext;
    Bytes tag;
};
GcmSealed aes_gcm_encrypt(ByteView key, ByteView nonce, ByteView plaintext, ByteView aad);
// Throws CryptoError when the tag does not match.
Bytes aes_gcm_decrypt(ByteView key, ByteView nonce, ByteView ciphertext, ByteView tag,
                      ByteView aad);

std::string to_hex(ByteView data, bool uppercase = false);
std::optional<Bytes> from_hex(std::string_view text);

ByteView as_bytes(std::string_view text);

}  // namespace winx::crypto
