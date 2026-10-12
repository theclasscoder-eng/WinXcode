#include "winx/der.hpp"

#include <charconv>

namespace winx::der {
namespace {

void append_length(Bytes& out, std::size_t length) {
    if (length < 0x80) {
        out.push_back(static_cast<std::uint8_t>(length));
        return;
    }
    std::uint8_t digits[sizeof(std::size_t)];
    int count = 0;
    for (std::size_t rest = length; rest != 0; rest >>= 8) {
        digits[count++] = static_cast<std::uint8_t>(rest);
    }
    out.push_back(static_cast<std::uint8_t>(0x80 | count));
    while (count > 0) out.push_back(digits[--count]);
}

void append_base128(Bytes& out, std::uint64_t value) {
    std::uint8_t groups[10];
    int count = 0;
    do {
        groups[count++] = static_cast<std::uint8_t>(value & 0x7F);
        value >>= 7;
    } while (value != 0);
    while (count > 1) out.push_back(static_cast<std::uint8_t>(groups[--count] | 0x80));
    out.push_back(groups[0]);
}

}  // namespace

Bytes encode(std::uint8_t tag, ByteView content) {
    Bytes out;
    out.reserve(content.size() + 6);
    out.push_back(tag);
    append_length(out, content.size());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

Bytes boolean(bool value) {
    const std::uint8_t content = value ? 0xFF : 0x00;
    return encode(kBoolean, {&content, 1});
}

Bytes integer(std::int64_t value) {
    // Minimal two's-complement, big-endian.
    std::uint8_t bytes[8];
    for (int i = 0; i < 8; ++i) bytes[i] = static_cast<std::uint8_t>(value >> (8 * (7 - i)));
    int start = 0;
    while (start < 7) {
        const bool redundant_zero = bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0;
        const bool redundant_ones = bytes[start] == 0xFF && (bytes[start + 1] & 0x80) != 0;
        if (!redundant_zero && !redundant_ones) break;
        ++start;
    }
    return encode(kInteger, {bytes + start, static_cast<std::size_t>(8 - start)});
}

Bytes utf8_string(std::string_view text) {
    return encode(kUtf8String, {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()});
}

Bytes octet_string(ByteView data) { return encode(kOctetString, data); }

Bytes object_identifier_content(std::string_view dotted) {
    std::vector<std::uint64_t> arcs;
    std::size_t pos = 0;
    while (pos <= dotted.size()) {
        auto end = dotted.find('.', pos);
        if (end == std::string_view::npos) end = dotted.size();
        std::uint64_t arc = 0;
        const auto [ptr, ec] = std::from_chars(dotted.data() + pos, dotted.data() + end, arc);
        if (ec != std::errc{} || ptr != dotted.data() + end || end == pos) {
            throw std::invalid_argument("invalid object identifier");
        }
        arcs.push_back(arc);
        pos = end + 1;
    }
    if (arcs.size() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39)) {
        throw std::invalid_argument("invalid object identifier");
    }
    Bytes content;
    append_base128(content, arcs[0] * 40 + arcs[1]);
    for (std::size_t i = 2; i < arcs.size(); ++i) append_base128(content, arcs[i]);
    return content;
}

Bytes object_identifier(std::string_view dotted) {
    return encode(kObjectIdentifier, object_identifier_content(dotted));
}

Bytes concat(const std::vector<Bytes>& parts) {
    Bytes out;
    for (const Bytes& part : parts) out.insert(out.end(), part.begin(), part.end());
    return out;
}

Bytes sequence(const std::vector<Bytes>& elements) { return encode(kSequence, concat(elements)); }

Element Reader::read() {
    if (data_.size() < 2) throw DecodeError("truncated DER element");
    Element element;
    element.tag = data_[0];
    std::size_t header = 2;
    std::size_t length = data_[1];
    if (length & 0x80) {
        const std::size_t count = length & 0x7F;
        if (count == 0 || count > sizeof(std::size_t) || data_.size() < 2 + count) {
            throw DecodeError("unsupported DER length");
        }
        length = 0;
        for (std::size_t i = 0; i < count; ++i) length = (length << 8) | data_[2 + i];
        header += count;
    }
    if (length > data_.size() - header) throw DecodeError("DER element exceeds its container");
    element.content = data_.subspan(header, length);
    element.encoded = data_.subspan(0, header + length);
    data_ = data_.subspan(header + length);
    return element;
}

}  // namespace winx::der
