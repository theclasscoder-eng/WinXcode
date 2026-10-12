#include "winx/srp.hpp"

#include <algorithm>
#include <bit>

namespace winx::auth {
namespace {

constexpr std::uint64_t kBase = 1ULL << 32;

crypto::Bytes strip_leading_zeros(crypto::Bytes bytes) {
    const auto first = std::find_if(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b != 0; });
    bytes.erase(bytes.begin(), first);
    return bytes;
}

BigUInt hash_to_int(const crypto::Bytes& digest) { return BigUInt::from_bytes(digest); }

}  // namespace

BigUInt::BigUInt(std::uint64_t value) {
    if (value != 0) limbs_.push_back(static_cast<std::uint32_t>(value));
    if (value >> 32) limbs_.push_back(static_cast<std::uint32_t>(value >> 32));
}

void BigUInt::trim() {
    while (!limbs_.empty() && limbs_.back() == 0) limbs_.pop_back();
}

BigUInt BigUInt::from_bytes(crypto::ByteView big_endian) {
    BigUInt result;
    result.limbs_.assign((big_endian.size() + 3) / 4, 0);
    for (std::size_t i = 0; i < big_endian.size(); ++i) {
        const std::size_t position = big_endian.size() - 1 - i;  // distance from the low end
        result.limbs_[position / 4] |= static_cast<std::uint32_t>(big_endian[i])
                                       << (8 * (position % 4));
    }
    result.trim();
    return result;
}

BigUInt BigUInt::from_hex(std::string_view hex) {
    std::string digits;
    for (const char c : hex) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        digits += c;
    }
    if (digits.size() % 2) digits.insert(digits.begin(), '0');
    const auto bytes = crypto::from_hex(digits);
    if (!bytes) throw std::invalid_argument("invalid hexadecimal integer");
    return from_bytes(*bytes);
}

crypto::Bytes BigUInt::to_bytes(std::size_t min_length) const {
    const std::size_t length = std::max(min_length, (bit_length() + 7) / 8);
    crypto::Bytes out(length, 0);
    for (std::size_t position = 0; position < limbs_.size() * 4 && position < length; ++position) {
        out[length - 1 - position] =
            static_cast<std::uint8_t>(limbs_[position / 4] >> (8 * (position % 4)));
    }
    return out;
}

std::size_t BigUInt::bit_length() const noexcept {
    if (limbs_.empty()) return 0;
    return limbs_.size() * 32 - static_cast<std::size_t>(std::countl_zero(limbs_.back()));
}

bool BigUInt::bit(std::size_t index) const noexcept {
    const std::size_t limb = index / 32;
    return limb < limbs_.size() && ((limbs_[limb] >> (index % 32)) & 1u) != 0;
}

std::strong_ordering operator<=>(const BigUInt& a, const BigUInt& b) noexcept {
    if (a.limbs_.size() != b.limbs_.size()) return a.limbs_.size() <=> b.limbs_.size();
    for (std::size_t i = a.limbs_.size(); i-- > 0;) {
        if (a.limbs_[i] != b.limbs_[i]) return a.limbs_[i] <=> b.limbs_[i];
    }
    return std::strong_ordering::equal;
}

BigUInt BigUInt::operator+(const BigUInt& other) const {
    BigUInt result;
    const std::size_t count = std::max(limbs_.size(), other.limbs_.size());
    result.limbs_.resize(count + 1);
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint64_t sum = carry + (i < limbs_.size() ? limbs_[i] : 0) +
                                  (i < other.limbs_.size() ? other.limbs_[i] : 0);
        result.limbs_[i] = static_cast<std::uint32_t>(sum);
        carry = sum >> 32;
    }
    result.limbs_[count] = static_cast<std::uint32_t>(carry);
    result.trim();
    return result;
}

BigUInt BigUInt::operator-(const BigUInt& other) const {
    if (*this < other) throw std::domain_error("BigUInt subtraction would be negative");
    BigUInt result;
    result.limbs_.resize(limbs_.size());
    std::int64_t borrow = 0;
    for (std::size_t i = 0; i < limbs_.size(); ++i) {
        std::int64_t difference = static_cast<std::int64_t>(limbs_[i]) - borrow -
                                  (i < other.limbs_.size() ? other.limbs_[i] : 0);
        borrow = difference < 0 ? 1 : 0;
        if (difference < 0) difference += static_cast<std::int64_t>(kBase);
        result.limbs_[i] = static_cast<std::uint32_t>(difference);
    }
    result.trim();
    return result;
}

BigUInt BigUInt::operator*(const BigUInt& other) const {
    BigUInt result;
    if (is_zero() || other.is_zero()) return result;
    result.limbs_.assign(limbs_.size() + other.limbs_.size(), 0);
    for (std::size_t i = 0; i < limbs_.size(); ++i) {
        std::uint64_t carry = 0;
        for (std::size_t j = 0; j < other.limbs_.size(); ++j) {
            const std::uint64_t product = static_cast<std::uint64_t>(limbs_[i]) * other.limbs_[j] +
                                          result.limbs_[i + j] + carry;
            result.limbs_[i + j] = static_cast<std::uint32_t>(product);
            carry = product >> 32;
        }
        result.limbs_[i + other.limbs_.size()] = static_cast<std::uint32_t>(carry);
    }
    result.trim();
    return result;
}

std::pair<BigUInt, BigUInt> BigUInt::divmod(const BigUInt& dividend, const BigUInt& divisor) {
    if (divisor.is_zero()) throw std::domain_error("BigUInt division by zero");
    if (dividend < divisor) return {BigUInt{}, dividend};

    const auto& a = dividend.limbs_;
    const auto& b = divisor.limbs_;
    const std::size_t m = a.size();
    const std::size_t n = b.size();
    BigUInt quotient;
    BigUInt remainder;

    if (n == 1) {
        quotient.limbs_.resize(m);
        std::uint64_t rest = 0;
        for (std::size_t i = m; i-- > 0;) {
            const std::uint64_t current = (rest << 32) | a[i];
            quotient.limbs_[i] = static_cast<std::uint32_t>(current / b[0]);
            rest = current % b[0];
        }
        quotient.trim();
        return {quotient, BigUInt(rest)};
    }

    // Knuth, TAOCP vol. 2, Algorithm D. Normalize so the divisor's top bit is set.
    const int shift = std::countl_zero(b[n - 1]);
    const auto shl = [shift](std::uint32_t high, std::uint32_t low) {
        return shift == 0 ? high : (high << shift) | (low >> (32 - shift));
    };
    std::vector<std::uint32_t> vn(n);
    std::vector<std::uint32_t> un(m + 1);
    for (std::size_t i = n - 1; i > 0; --i) vn[i] = shl(b[i], b[i - 1]);
    vn[0] = b[0] << shift;
    un[m] = shift == 0 ? 0 : a[m - 1] >> (32 - shift);
    for (std::size_t i = m - 1; i > 0; --i) un[i] = shl(a[i], a[i - 1]);
    un[0] = a[0] << shift;

    quotient.limbs_.assign(m - n + 1, 0);
    for (std::size_t j = m - n + 1; j-- > 0;) {
        const std::uint64_t numerator = (static_cast<std::uint64_t>(un[j + n]) << 32) | un[j + n - 1];
        std::uint64_t qhat = numerator / vn[n - 1];
        std::uint64_t rhat = numerator % vn[n - 1];
        while (qhat >= kBase || qhat * vn[n - 2] > ((rhat << 32) | un[j + n - 2])) {
            --qhat;
            rhat += vn[n - 1];
            if (rhat >= kBase) break;
        }

        // Multiply and subtract qhat * vn from the current window of un.
        std::uint64_t carry = 0;
        std::int64_t t = 0;
        for (std::size_t i = 0; i < n; ++i) {
            const std::uint64_t product = qhat * vn[i];
            t = static_cast<std::int64_t>(un[i + j]) - static_cast<std::int64_t>(carry) -
                static_cast<std::int64_t>(product & 0xFFFFFFFFULL);
            un[i + j] = static_cast<std::uint32_t>(t);
            carry = (product >> 32) - static_cast<std::uint64_t>(t >> 32);
        }
        t = static_cast<std::int64_t>(un[j + n]) - static_cast<std::int64_t>(carry);
        un[j + n] = static_cast<std::uint32_t>(t);
        quotient.limbs_[j] = static_cast<std::uint32_t>(qhat);

        if (t < 0) {
            // qhat was one too large; add the divisor back.
            --quotient.limbs_[j];
            std::uint64_t add_carry = 0;
            for (std::size_t i = 0; i < n; ++i) {
                const std::uint64_t sum = static_cast<std::uint64_t>(un[i + j]) + vn[i] + add_carry;
                un[i + j] = static_cast<std::uint32_t>(sum);
                add_carry = sum >> 32;
            }
            un[j + n] += static_cast<std::uint32_t>(add_carry);
        }
    }

    remainder.limbs_.resize(n);
    for (std::size_t i = 0; i < n; ++i) {
        remainder.limbs_[i] =
            shift == 0 ? un[i] : (un[i] >> shift) | (un[i + 1] << (32 - shift));
    }
    quotient.trim();
    remainder.trim();
    return {quotient, remainder};
}

BigUInt BigUInt::mod_pow(const BigUInt& exponent, const BigUInt& modulus) const {
    if (modulus.is_zero()) throw std::domain_error("BigUInt modulus is zero");
    if (modulus == BigUInt(1)) return {};
    BigUInt result(1);
    const BigUInt base = *this % modulus;
    for (std::size_t i = exponent.bit_length(); i-- > 0;) {
        result = (result * result) % modulus;
        if (exponent.bit(i)) result = (result * base) % modulus;
    }
    return result;
}

const SrpGroup& srp_group_2048() {
    static const SrpGroup group{
        BigUInt::from_hex(
            "AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294 3DB56050"
            "A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D CD7F48A9 DA04FD50"
            "E8083969 EDB767B0 CF609517 9A163AB3 661A05FB D5FAAAE8 2918A996 2F0B93B8"
            "55F97993 EC975EEA A80D740A DBF4FF74 7359D041 D5C33EA7 1D281E44 6B14773B"
            "CA97B43A 23FB8016 76BD207A 436C6481 F1D2B907 8717461A 5B9D32E6 88F87748"
            "544523B5 24B0D57D 5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6"
            "AF874E73 03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6"
            "94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F 9E4AFF73"),
        BigUInt(2), 256};
    return group;
}

SrpClient::SrpClient(std::string username)
    : SrpClient(std::move(username), crypto::random_bytes(32)) {}

SrpClient::SrpClient(std::string username, crypto::ByteView private_value)
    : username_(std::move(username)), private_(BigUInt::from_bytes(private_value)) {
    const SrpGroup& group = srp_group_2048();
    public_ = group.generator.mod_pow(private_, group.modulus);
}

crypto::Bytes SrpClient::public_value() const { return public_.to_bytes(); }

crypto::Bytes SrpClient::process_challenge(crypto::ByteView password_key, crypto::ByteView salt,
                                           crypto::ByteView server_public) {
    using crypto::HashAlgorithm;
    using crypto::Hasher;
    const SrpGroup& group = srp_group_2048();
    const BigUInt& N = group.modulus;
    const crypto::Bytes n_bytes = N.to_bytes();
    const crypto::Bytes g_padded = group.generator.to_bytes(group.width);
    const crypto::Bytes a_bytes = public_.to_bytes();

    const BigUInt B = BigUInt::from_bytes(server_public);
    if ((B % N).is_zero()) throw SrpError("the server sent an invalid SRP public value");
    const crypto::Bytes b_bytes = B.to_bytes();

    // u = H(PAD(A) | PAD(B)), k = H(N | PAD(g))
    const BigUInt u = hash_to_int(Hasher(HashAlgorithm::Sha256)
                                      .update(public_.to_bytes(group.width))
                                      .update(B.to_bytes(group.width))
                                      .finish());
    if (u.is_zero()) throw SrpError("the SRP scrambling parameter is zero");
    const BigUInt k =
        hash_to_int(Hasher(HashAlgorithm::Sha256).update(n_bytes).update(g_padded).finish());

    // x = H(salt | H(":" | password_key))
    const crypto::Bytes inner =
        Hasher(HashAlgorithm::Sha256).update(std::string_view(":")).update(password_key).finish();
    const BigUInt x =
        hash_to_int(Hasher(HashAlgorithm::Sha256).update(salt).update(inner).finish());

    // S = (B - k * g^x) ^ (a + u * x) mod N
    const BigUInt v = group.generator.mod_pow(x, N);
    const BigUInt kv = (k * v) % N;
    const BigUInt base = ((B % N) + N - kv) % N;
    const BigUInt S = base.mod_pow(private_ + u * x, N);
    session_key_ = crypto::sha256(S.to_bytes());

    // M1 = H(H(N) xor H(PAD(g)) | H(I) | salt | A | B | K)
    crypto::Bytes hn_xor_hg = crypto::sha256(n_bytes);
    const crypto::Bytes hg = crypto::sha256(g_padded);
    for (std::size_t i = 0; i < hn_xor_hg.size(); ++i) hn_xor_hg[i] ^= hg[i];
    const crypto::Bytes salt_minimal =
        strip_leading_zeros(crypto::Bytes(salt.begin(), salt.end()));
    const crypto::Bytes proof = Hasher(HashAlgorithm::Sha256)
                                    .update(hn_xor_hg)
                                    .update(crypto::sha256(crypto::as_bytes(username_)))
                                    .update(salt_minimal)
                                    .update(a_bytes)
                                    .update(b_bytes)
                                    .update(session_key_)
                                    .finish();
    // M2 = H(A | M1 | K)
    expected_server_proof_ = Hasher(HashAlgorithm::Sha256)
                                 .update(a_bytes)
                                 .update(proof)
                                 .update(session_key_)
                                 .finish();
    return proof;
}

bool SrpClient::verify_server(crypto::ByteView server_proof) const {
    return !expected_server_proof_.empty() &&
           std::equal(server_proof.begin(), server_proof.end(), expected_server_proof_.begin(),
                      expected_server_proof_.end());
}

crypto::Bytes derive_gsa_password(std::string_view password, crypto::ByteView salt,
                                  std::uint64_t iterations, bool hex_digest) {
    crypto::Bytes digest = crypto::sha256(crypto::as_bytes(password));
    if (hex_digest) {
        const std::string hex = crypto::to_hex(digest);
        digest.assign(hex.begin(), hex.end());
    }
    return crypto::pbkdf2_hmac_sha256(digest, salt, iterations, 32);
}

}  // namespace winx::auth
