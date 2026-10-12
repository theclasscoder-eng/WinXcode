#include "winx/plist.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <format>

#include "winx/text.hpp"

namespace winx::plist {
namespace {

constexpr std::size_t kHeaderSize = 8;
constexpr std::size_t kTrailerSize = 32;
constexpr int kMaxDepth = 128;
// Shared references let a tiny file expand without bound; cap the work done.
constexpr std::size_t kMaxVisited = 4'000'000;

class BinaryReader {
public:
    explicit BinaryReader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

    Value parse_document() {
        if (bytes_.size() < kHeaderSize + kTrailerSize ||
            std::memcmp(bytes_.data(), "bplist", 6) != 0) {
            fail("not a binary plist");
        }
        body_end_ = bytes_.size() - kTrailerSize;
        const std::uint8_t* trailer = bytes_.data() + body_end_;
        offset_size_ = trailer[6];
        ref_size_ = trailer[7];
        object_count_ = read_be(body_end_ + 8, 8);
        const std::uint64_t top_object = read_be(body_end_ + 16, 8);
        table_offset_ = read_be(body_end_ + 24, 8);

        if (offset_size_ < 1 || offset_size_ > 8 || ref_size_ < 1 || ref_size_ > 8) {
            fail("invalid trailer sizes");
        }
        if (table_offset_ < kHeaderSize || table_offset_ > body_end_ ||
            object_count_ > (body_end_ - table_offset_) / offset_size_) {
            fail("offset table out of range");
        }
        if (top_object >= object_count_) fail("top object out of range");
        return read_object(top_object, 0);
    }

private:
    [[noreturn]] void fail(std::string_view message) const {
        throw ParseError(std::format("binary plist: {}", message));
    }

    void need(std::uint64_t offset, std::uint64_t length) const {
        if (offset > body_end_ || length > body_end_ - offset) fail("object out of range");
    }

    // Unchecked against body_end_ so it can also read the trailer.
    std::uint64_t read_be(std::uint64_t offset, std::size_t size) const {
        if (offset > bytes_.size() || size > bytes_.size() - offset) fail("truncated");
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < size; ++i) value = (value << 8) | bytes_[offset + i];
        return value;
    }

    // Length encoded in the marker's low nibble, or in a following integer.
    std::uint64_t read_count(std::uint8_t info, std::uint64_t& cursor) const {
        if (info != 0x0F) return info;
        need(cursor, 1);
        const std::uint8_t marker = bytes_[cursor++];
        if ((marker >> 4) != 0x1 || (marker & 0x0F) > 3) fail("invalid length marker");
        const std::size_t size = std::size_t{1} << (marker & 0x0F);
        need(cursor, size);
        const std::uint64_t count = read_be(cursor, size);
        cursor += size;
        return count;
    }

    std::uint64_t read_ref(std::uint64_t& cursor) const {
        need(cursor, ref_size_);
        const std::uint64_t ref = read_be(cursor, ref_size_);
        cursor += ref_size_;
        if (ref >= object_count_) fail("object reference out of range");
        return ref;
    }

    std::string read_utf16(std::uint64_t offset, std::uint64_t units) const {
        std::string out;
        out.reserve(units);
        for (std::uint64_t i = 0; i < units; ++i) {
            char32_t code_point = static_cast<char32_t>(read_be(offset + i * 2, 2));
            if (code_point >= 0xD800 && code_point <= 0xDBFF && i + 1 < units) {
                const auto low = static_cast<char32_t>(read_be(offset + (i + 1) * 2, 2));
                if (low >= 0xDC00 && low <= 0xDFFF) {
                    code_point = 0x10000 + ((code_point - 0xD800) << 10) + (low - 0xDC00);
                    ++i;
                }
            }
            append_utf8(out, code_point);
        }
        return out;
    }

    Value read_object(std::uint64_t index, int depth) {
        if (depth > kMaxDepth) fail("nesting too deep");
        if (++visited_ > kMaxVisited) fail("too many objects");

        const std::uint64_t offset = read_be(table_offset_ + index * offset_size_, offset_size_);
        need(offset, 1);
        const std::uint8_t marker = bytes_[offset];
        const std::uint8_t type = marker >> 4;
        const std::uint8_t info = marker & 0x0F;
        std::uint64_t cursor = offset + 1;

        switch (type) {
            case 0x0:
                if (info == 0x0) return {};
                if (info == 0x8) return false;
                if (info == 0x9) return true;
                fail("unsupported simple value");
            case 0x1: {
                if (info > 4) fail("unsupported integer size");
                const std::size_t size = std::size_t{1} << info;
                need(cursor, size);
                // 16-byte integers keep only their low 64 bits.
                const std::uint64_t raw =
                    size == 16 ? read_be(cursor + 8, 8) : read_be(cursor, size);
                return static_cast<std::int64_t>(raw);
            }
            case 0x2: {
                if (info == 2) {
                    need(cursor, 4);
                    return static_cast<double>(
                        std::bit_cast<float>(static_cast<std::uint32_t>(read_be(cursor, 4))));
                }
                if (info == 3) {
                    need(cursor, 8);
                    return std::bit_cast<double>(read_be(cursor, 8));
                }
                fail("unsupported real size");
            }
            case 0x3: {
                if (info != 3) fail("unsupported date size");
                need(cursor, 8);
                return Date{std::bit_cast<double>(read_be(cursor, 8))};
            }
            case 0x4: {
                const std::uint64_t count = read_count(info, cursor);
                need(cursor, count);
                const auto* first = bytes_.data() + cursor;
                return Data{std::vector<std::uint8_t>(first, first + count)};
            }
            case 0x5:
            case 0x7: {
                const std::uint64_t count = read_count(info, cursor);
                need(cursor, count);
                return std::string(reinterpret_cast<const char*>(bytes_.data() + cursor),
                                   static_cast<std::size_t>(count));
            }
            case 0x6: {
                const std::uint64_t units = read_count(info, cursor);
                if (units > (body_end_ - cursor) / 2) fail("object out of range");
                return read_utf16(cursor, units);
            }
            case 0x8: {
                const std::size_t size = std::size_t{info} + 1;
                if (size > 8) fail("unsupported UID size");
                need(cursor, size);
                return static_cast<std::int64_t>(read_be(cursor, size));
            }
            case 0xA:
            case 0xC: {
                const std::uint64_t count = read_count(info, cursor);
                if (count > (body_end_ - cursor) / ref_size_) fail("object out of range");
                Array array;
                array.reserve(static_cast<std::size_t>(count));
                for (std::uint64_t i = 0; i < count; ++i) {
                    array.push_back(read_object(read_ref(cursor), depth + 1));
                }
                return array;
            }
            case 0xD: {
                const std::uint64_t count = read_count(info, cursor);
                if (count > (body_end_ - cursor) / ref_size_ / 2) fail("object out of range");
                std::uint64_t value_cursor = cursor + count * ref_size_;
                Dict dict;
                for (std::uint64_t i = 0; i < count; ++i) {
                    Value key = read_object(read_ref(cursor), depth + 1);
                    const auto* name = key.get_if<std::string>();
                    if (!name) fail("dictionary key is not a string");
                    dict.set(*name, read_object(read_ref(value_cursor), depth + 1));
                }
                return dict;
            }
            default:
                fail("unknown object type");
        }
    }

    std::span<const std::uint8_t> bytes_;
    std::uint64_t body_end_ = 0;
    std::uint64_t table_offset_ = 0;
    std::uint64_t object_count_ = 0;
    std::size_t offset_size_ = 0;
    std::size_t ref_size_ = 0;
    std::size_t visited_ = 0;
};

class BinaryWriter {
public:
    std::vector<std::uint8_t> write(const Value& root) {
        collect(root);
        ref_size_ = bytes_needed(objects_.size());

        std::vector<std::uint8_t> out = {'b', 'p', 'l', 'i', 's', 't', '0', '0'};
        std::vector<std::uint64_t> offsets;
        offsets.reserve(objects_.size());
        for (const Object& object : objects_) {
            offsets.push_back(out.size());
            encode(out, object);
        }

        const std::uint64_t table_offset = out.size();
        const std::size_t offset_size = bytes_needed(table_offset);
        for (const std::uint64_t offset : offsets) put_be(out, offset, offset_size);

        out.insert(out.end(), 6, 0);  // unused bytes and sort version
        out.push_back(static_cast<std::uint8_t>(offset_size));
        out.push_back(static_cast<std::uint8_t>(ref_size_));
        put_be(out, objects_.size(), 8);
        put_be(out, 0, 8);  // the root is object 0
        put_be(out, table_offset, 8);
        return out;
    }

private:
    // One entry of the object table. Dictionary keys are objects of their own.
    struct Object {
        const Value* value = nullptr;
        std::string key;  // set instead of `value` for a dictionary key
        std::vector<std::size_t> refs;
    };

    static std::size_t bytes_needed(std::uint64_t value) {
        if (value < (1ull << 8)) return 1;
        if (value < (1ull << 16)) return 2;
        if (value < (1ull << 32)) return 4;
        return 8;
    }

    static void put_be(std::vector<std::uint8_t>& out, std::uint64_t value, std::size_t size) {
        for (std::size_t i = size; i-- > 0;) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    }

    std::size_t add_key(const std::string& key) {
        objects_.push_back(Object{nullptr, key, {}});
        return objects_.size() - 1;
    }

    // Depth-first, so the root lands at index 0.
    std::size_t collect(const Value& value) {
        if (value.is_null()) throw std::invalid_argument("cannot serialize a null plist value");
        const std::size_t index = objects_.size();
        objects_.push_back(Object{&value, {}, {}});
        if (const auto* array = value.get_if<Array>()) {
            std::vector<std::size_t> refs;
            for (const Value& item : *array) refs.push_back(collect(item));
            objects_[index].refs = std::move(refs);
        } else if (const auto* dict = value.get_if<Dict>()) {
            std::vector<std::size_t> keys;
            std::vector<std::size_t> values;
            for (const auto& [key, item] : dict->items()) keys.push_back(add_key(key));
            for (const auto& [key, item] : dict->items()) values.push_back(collect(item));
            keys.insert(keys.end(), values.begin(), values.end());
            objects_[index].refs = std::move(keys);
        }
        return index;
    }

    // Marker byte with the count in its low nibble, or 0xF plus an integer.
    static void put_marker(std::vector<std::uint8_t>& out, std::uint8_t type, std::uint64_t count) {
        if (count < 15) {
            out.push_back(static_cast<std::uint8_t>(type | count));
            return;
        }
        out.push_back(static_cast<std::uint8_t>(type | 0x0F));
        const std::size_t size = bytes_needed(count);
        out.push_back(static_cast<std::uint8_t>(0x10 | std::countr_zero(size)));
        put_be(out, count, size);
    }

    static void put_string(std::vector<std::uint8_t>& out, const std::string& text) {
        const bool ascii = std::all_of(text.begin(), text.end(),
                                       [](char c) { return static_cast<unsigned char>(c) < 0x80; });
        if (ascii) {
            put_marker(out, 0x50, text.size());
            out.insert(out.end(), text.begin(), text.end());
            return;
        }
        const std::wstring wide = to_wide(text);  // UTF-16 on Windows
        put_marker(out, 0x60, wide.size());
        for (const wchar_t unit : wide) put_be(out, static_cast<std::uint16_t>(unit), 2);
    }

    void encode(std::vector<std::uint8_t>& out, const Object& object) const {
        if (!object.value) {
            put_string(out, object.key);
            return;
        }
        const Value& value = *object.value;
        if (const auto* flag = value.get_if<bool>()) {
            out.push_back(*flag ? 0x09 : 0x08);
        } else if (const auto* integer = value.get_if<std::int64_t>()) {
            // Negative numbers always take the full eight bytes.
            const std::size_t size =
                *integer < 0 ? 8 : bytes_needed(static_cast<std::uint64_t>(*integer));
            out.push_back(static_cast<std::uint8_t>(0x10 | std::countr_zero(size)));
            put_be(out, static_cast<std::uint64_t>(*integer), size);
        } else if (const auto* real = value.get_if<double>()) {
            out.push_back(0x23);
            put_be(out, std::bit_cast<std::uint64_t>(*real), 8);
        } else if (const auto* date = value.get_if<Date>()) {
            out.push_back(0x33);
            put_be(out, std::bit_cast<std::uint64_t>(date->seconds), 8);
        } else if (const auto* data = value.get_if<Data>()) {
            put_marker(out, 0x40, data->bytes.size());
            out.insert(out.end(), data->bytes.begin(), data->bytes.end());
        } else if (const auto* text = value.get_if<std::string>()) {
            put_string(out, *text);
        } else if (value.is<Array>()) {
            put_marker(out, 0xA0, object.refs.size());
            for (const std::size_t ref : object.refs) put_be(out, ref, ref_size_);
        } else if (value.is<Dict>()) {
            put_marker(out, 0xD0, object.refs.size() / 2);
            for (const std::size_t ref : object.refs) put_be(out, ref, ref_size_);
        }
    }

    std::vector<Object> objects_;
    std::size_t ref_size_ = 1;
};

}  // namespace

Value parse_binary(std::span<const std::uint8_t> bytes) {
    return BinaryReader(bytes).parse_document();
}

std::vector<std::uint8_t> to_binary(const Value& value) { return BinaryWriter().write(value); }

}  // namespace winx::plist
