#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

// Minimal ASN.1 DER encoder and decoder.
namespace winx::der {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

inline constexpr std::uint8_t kBoolean = 0x01;
inline constexpr std::uint8_t kInteger = 0x02;
inline constexpr std::uint8_t kOctetString = 0x04;
inline constexpr std::uint8_t kObjectIdentifier = 0x06;
inline constexpr std::uint8_t kUtf8String = 0x0C;
inline constexpr std::uint8_t kSequence = 0x30;
inline constexpr std::uint8_t kSet = 0x31;

class DecodeError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Tag, definite length, content.
Bytes encode(std::uint8_t tag, ByteView content);
Bytes boolean(bool value);
Bytes integer(std::int64_t value);
Bytes utf8_string(std::string_view text);
Bytes octet_string(ByteView data);
// Dotted form, e.g. "1.2.840.113635.100.9.1".
Bytes object_identifier(std::string_view dotted);
// Content octets of an OID, without tag and length.
Bytes object_identifier_content(std::string_view dotted);
// Wraps already-encoded elements.
Bytes sequence(const std::vector<Bytes>& elements);
Bytes concat(const std::vector<Bytes>& parts);

struct Element {
    std::uint8_t tag = 0;
    ByteView content;
    ByteView encoded;  // tag and length included
};

class Reader {
public:
    explicit Reader(ByteView data) : data_(data) {}
    bool at_end() const noexcept { return data_.empty(); }
    // Throws DecodeError on truncated or indefinite-length input.
    Element read();

private:
    ByteView data_;
};

}  // namespace winx::der
