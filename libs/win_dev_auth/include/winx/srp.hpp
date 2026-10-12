#pragma once

#include <compare>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "winx/crypto.hpp"

// SRP-6a client as used by Apple's GrandSlam sign-in, with the small
// arbitrary-precision integer it needs. Not constant-time: adequate for a
// client running on the user's own machine, not for a server.
namespace winx::auth {

class BigUInt {
public:
    BigUInt() = default;
    BigUInt(std::uint64_t value);

    static BigUInt from_bytes(crypto::ByteView big_endian);
    // Whitespace is ignored. Throws std::invalid_argument on other characters.
    static BigUInt from_hex(std::string_view hex);
    // Big-endian, left-padded with zeros to at least `min_length`.
    crypto::Bytes to_bytes(std::size_t min_length = 0) const;

    bool is_zero() const noexcept { return limbs_.empty(); }
    std::size_t bit_length() const noexcept;
    bool bit(std::size_t index) const noexcept;

    friend std::strong_ordering operator<=>(const BigUInt& a, const BigUInt& b) noexcept;
    friend bool operator==(const BigUInt& a, const BigUInt& b) noexcept = default;

    BigUInt operator+(const BigUInt& other) const;
    // Throws std::domain_error if the result would be negative.
    BigUInt operator-(const BigUInt& other) const;
    BigUInt operator*(const BigUInt& other) const;
    BigUInt operator/(const BigUInt& divisor) const { return divmod(*this, divisor).first; }
    BigUInt operator%(const BigUInt& divisor) const { return divmod(*this, divisor).second; }

    // Quotient and remainder. Throws std::domain_error on division by zero.
    static std::pair<BigUInt, BigUInt> divmod(const BigUInt& dividend, const BigUInt& divisor);
    BigUInt mod_pow(const BigUInt& exponent, const BigUInt& modulus) const;

private:
    void trim();
    // Little-endian 32-bit limbs with no leading zero limb.
    std::vector<std::uint32_t> limbs_;
};

class SrpError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct SrpGroup {
    BigUInt modulus;
    BigUInt generator;
    std::size_t width;  // modulus length in bytes
};

// RFC 5054 2048-bit group.
const SrpGroup& srp_group_2048();

// SRP-6a with SHA-256, RFC 5054 padding for k and u, and no user name in x.
class SrpClient {
public:
    explicit SrpClient(std::string username);
    // Fixed private value, for tests.
    SrpClient(std::string username, crypto::ByteView private_value);

    // A = g^a mod N.
    crypto::Bytes public_value() const;

    // Consumes the server's salt and B and returns the client proof M1.
    // `password_key` is the already-derived password (see derive_gsa_password).
    crypto::Bytes process_challenge(crypto::ByteView password_key, crypto::ByteView salt,
                                    crypto::ByteView server_public);
    // Checks the server proof M2 returned after M1 was accepted.
    bool verify_server(crypto::ByteView server_proof) const;
    const crypto::Bytes& session_key() const noexcept { return session_key_; }

private:
    std::string username_;
    BigUInt private_;
    BigUInt public_;
    crypto::Bytes session_key_;
    crypto::Bytes expected_server_proof_;
};

// GrandSlam password derivation: PBKDF2-HMAC-SHA256 over SHA-256(password),
// or over its lowercase hex form for the "s2k_fo" protocol.
crypto::Bytes derive_gsa_password(std::string_view password, crypto::ByteView salt,
                                  std::uint64_t iterations, bool hex_digest);

}  // namespace winx::auth
