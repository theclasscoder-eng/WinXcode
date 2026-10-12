#include "winx/plist.hpp"

#include <charconv>
#include <chrono>
#include <cmath>
#include <format>

#include "winx/base64.hpp"
#include "winx/text.hpp"

namespace winx::plist {
namespace {

constexpr int kMaxDepth = 256;
constexpr std::int64_t kAppleEpochUnix = 978307200;  // 2001-01-01T00:00:00Z

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

std::string_view trim(std::string_view text) {
    while (!text.empty() && is_space(text.front())) text.remove_prefix(1);
    while (!text.empty() && is_space(text.back())) text.remove_suffix(1);
    return text;
}

std::int64_t parse_integer(std::string_view raw) {
    std::string_view text = trim(raw);
    bool negative = false;
    if (!text.empty() && (text.front() == '-' || text.front() == '+')) {
        negative = text.front() == '-';
        text.remove_prefix(1);
    }
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        base = 16;
        text.remove_prefix(2);
    }
    std::uint64_t magnitude = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), magnitude, base);
    if (ec != std::errc{} || end != text.data() + text.size() || text.empty()) {
        throw ParseError("invalid <integer> value");
    }
    // Values above INT64_MAX keep their bit pattern, as Core Foundation does.
    const auto value = static_cast<std::int64_t>(magnitude);
    return negative ? static_cast<std::int64_t>(0 - magnitude) : value;
}

double parse_real(std::string_view raw) {
    std::string_view text = trim(raw);
    if (text == "nan") return std::nan("");
    if (text == "+infinity" || text == "infinity" || text == "inf") return HUGE_VAL;
    if (text == "-infinity" || text == "-inf") return -HUGE_VAL;
    if (!text.empty() && text.front() == '+') text.remove_prefix(1);
    double value = 0.0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || end != text.data() + text.size() || text.empty()) {
        throw ParseError("invalid <real> value");
    }
    return value;
}

int parse_fixed(std::string_view text, std::size_t offset, std::size_t length) {
    if (offset + length > text.size()) throw ParseError("invalid <date> value");
    int value = 0;
    const char* first = text.data() + offset;
    const auto [end, ec] = std::from_chars(first, first + length, value);
    if (ec != std::errc{} || end != first + length) throw ParseError("invalid <date> value");
    return value;
}

// ISO 8601 "YYYY-MM-DDTHH:MM:SSZ".
double parse_date(std::string_view raw) {
    using namespace std::chrono;
    const std::string_view text = trim(raw);
    if (text.size() < 19 || text[4] != '-' || text[7] != '-' || text[10] != 'T' ||
        text[13] != ':' || text[16] != ':') {
        throw ParseError("invalid <date> value");
    }
    const year_month_day ymd{year{parse_fixed(text, 0, 4)},
                             month{static_cast<unsigned>(parse_fixed(text, 5, 2))},
                             day{static_cast<unsigned>(parse_fixed(text, 8, 2))}};
    if (!ymd.ok()) throw ParseError("invalid <date> value");
    const sys_seconds point = sys_days{ymd} + hours{parse_fixed(text, 11, 2)} +
                              minutes{parse_fixed(text, 14, 2)} +
                              seconds{parse_fixed(text, 17, 2)};
    return static_cast<double>(point.time_since_epoch().count() - kAppleEpochUnix);
}

std::string format_date(double apple_seconds) {
    using namespace std::chrono;
    if (!std::isfinite(apple_seconds)) apple_seconds = 0.0;
    const sys_seconds point{
        seconds{static_cast<std::int64_t>(std::floor(apple_seconds)) + kAppleEpochUnix}};
    const sys_days date = floor<days>(point);
    const year_month_day ymd{date};
    const hh_mm_ss<seconds> clock{point - date};
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", static_cast<int>(ymd.year()),
                       static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()),
                       clock.hours().count(), clock.minutes().count(), clock.seconds().count());
}

class XmlReader {
public:
    explicit XmlReader(std::string_view text) : text_(text) {}

    Value parse_document() {
        if (text_.starts_with("\xEF\xBB\xBF")) pos_ = 3;
        skip_misc();
        Tag tag = read_tag();
        if (tag.name != "plist") return parse_value(tag, 0);
        if (tag.closing) fail("unexpected </plist>");
        if (tag.self_closing) return {};

        skip_misc();
        tag = read_tag();
        if (tag.closing) {
            if (tag.name != "plist") fail("expected </plist>");
            return {};
        }
        Value value = parse_value(tag, 0);
        skip_misc();
        const Tag end = read_tag();
        if (!end.closing || end.name != "plist") fail("expected </plist>");
        return value;
    }

private:
    struct Tag {
        std::string_view name;
        bool closing = false;
        bool self_closing = false;
    };

    [[noreturn]] void fail(std::string_view message) const {
        throw ParseError(std::format("XML plist: {} (at byte {})", message, pos_));
    }

    bool at(std::string_view prefix) const { return text_.substr(pos_).starts_with(prefix); }

    void skip_past(std::string_view terminator) {
        const auto end = text_.find(terminator, pos_);
        if (end == std::string_view::npos) fail("unterminated markup");
        pos_ = end + terminator.size();
    }

    // Whitespace, the XML declaration, comments and the DOCTYPE.
    void skip_misc() {
        for (;;) {
            while (pos_ < text_.size() && is_space(text_[pos_])) ++pos_;
            if (at("<?")) {
                skip_past("?>");
            } else if (at("<!--")) {
                skip_past("-->");
            } else if (at("<!")) {
                int brackets = 0;
                for (;;) {
                    if (pos_ >= text_.size()) fail("unterminated DOCTYPE");
                    const char c = text_[pos_++];
                    if (c == '[') ++brackets;
                    if (c == ']') --brackets;
                    if (c == '>' && brackets <= 0) break;
                }
            } else {
                return;
            }
        }
    }

    Tag read_tag() {
        if (pos_ >= text_.size() || text_[pos_] != '<') fail("expected '<'");
        ++pos_;
        Tag tag;
        if (pos_ < text_.size() && text_[pos_] == '/') {
            tag.closing = true;
            ++pos_;
        }
        const std::size_t start = pos_;
        while (pos_ < text_.size() && !is_space(text_[pos_]) && text_[pos_] != '>' &&
               text_[pos_] != '/') {
            ++pos_;
        }
        tag.name = text_.substr(start, pos_ - start);
        if (tag.name.empty()) fail("empty tag name");

        for (;;) {
            if (pos_ >= text_.size()) fail("unterminated tag");
            const char c = text_[pos_++];
            if (c == '>') break;
            if (c == '"' || c == '\'') {
                const auto end = text_.find(c, pos_);
                if (end == std::string_view::npos) fail("unterminated attribute");
                pos_ = end + 1;
                tag.self_closing = false;
            } else if (c == '/') {
                tag.self_closing = true;
            } else if (!is_space(c)) {
                tag.self_closing = false;
            }
        }
        return tag;
    }

    void decode_entities(std::string_view raw, std::string& out) const {
        std::size_t i = 0;
        while (i < raw.size()) {
            const auto amp = raw.find('&', i);
            if (amp == std::string_view::npos) {
                out.append(raw.substr(i));
                return;
            }
            out.append(raw.substr(i, amp - i));
            const auto semi = raw.find(';', amp);
            if (semi == std::string_view::npos || semi - amp > 12) fail("malformed entity");
            const std::string_view name = raw.substr(amp + 1, semi - amp - 1);
            if (name == "amp") {
                out += '&';
            } else if (name == "lt") {
                out += '<';
            } else if (name == "gt") {
                out += '>';
            } else if (name == "quot") {
                out += '"';
            } else if (name == "apos") {
                out += '\'';
            } else if (name.starts_with('#')) {
                std::string_view digits = name.substr(1);
                int base = 10;
                if (digits.starts_with('x') || digits.starts_with('X')) {
                    base = 16;
                    digits.remove_prefix(1);
                }
                std::uint32_t code_point = 0;
                const auto [end, ec] =
                    std::from_chars(digits.data(), digits.data() + digits.size(), code_point, base);
                if (ec != std::errc{} || end != digits.data() + digits.size() || digits.empty()) {
                    fail("malformed character reference");
                }
                append_utf8(out, static_cast<char32_t>(code_point));
            } else {
                fail("unknown entity");
            }
            i = semi + 1;
        }
    }

    // Reads character data up to and including the closing tag for `name`.
    std::string read_text(std::string_view name) {
        std::string out;
        for (;;) {
            const auto lt = text_.find('<', pos_);
            if (lt == std::string_view::npos) fail("unterminated element");
            decode_entities(text_.substr(pos_, lt - pos_), out);
            pos_ = lt;
            if (at("<![CDATA[")) {
                const std::size_t start = pos_ + 9;
                const auto end = text_.find("]]>", start);
                if (end == std::string_view::npos) fail("unterminated CDATA");
                out.append(text_.substr(start, end - start));
                pos_ = end + 3;
            } else if (at("<!--")) {
                skip_past("-->");
            } else {
                const Tag tag = read_tag();
                if (!tag.closing || tag.name != name) fail("mismatched closing tag");
                return out;
            }
        }
    }

    std::string element_text(const Tag& tag) {
        return tag.self_closing ? std::string{} : read_text(tag.name);
    }

    Value parse_value(const Tag& tag, int depth) {
        if (depth > kMaxDepth) fail("nesting too deep");
        if (tag.closing) fail("unexpected closing tag");

        if (tag.name == "dict") {
            Dict dict;
            if (tag.self_closing) return dict;
            for (;;) {
                skip_misc();
                const Tag key_tag = read_tag();
                if (key_tag.closing) {
                    if (key_tag.name != "dict") fail("expected </dict>");
                    break;
                }
                if (key_tag.name != "key") fail("expected <key>");
                std::string key = element_text(key_tag);
                skip_misc();
                const Tag value_tag = read_tag();
                dict.set(std::move(key), parse_value(value_tag, depth + 1));
            }
            return dict;
        }
        if (tag.name == "array") {
            Array array;
            if (tag.self_closing) return array;
            for (;;) {
                skip_misc();
                const Tag item_tag = read_tag();
                if (item_tag.closing) {
                    if (item_tag.name != "array") fail("expected </array>");
                    break;
                }
                array.push_back(parse_value(item_tag, depth + 1));
            }
            return array;
        }
        if (tag.name == "string") return element_text(tag);
        if (tag.name == "integer") return parse_integer(element_text(tag));
        if (tag.name == "real") return parse_real(element_text(tag));
        if (tag.name == "true" || tag.name == "false") {
            if (!tag.self_closing) read_text(tag.name);
            return tag.name == "true";
        }
        if (tag.name == "data") {
            auto bytes = base64_decode(element_text(tag));
            if (!bytes) fail("invalid base64 in <data>");
            return Data{std::move(*bytes)};
        }
        if (tag.name == "date") return Date{parse_date(element_text(tag))};
        fail("unknown element");
    }

    std::string_view text_;
    std::size_t pos_ = 0;
};

void append_escaped(std::string& out, std::string_view text) {
    for (const char c : text) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            default: out += c;
        }
    }
}

void write_value(std::string& out, const Value& value, int depth) {
    const std::string pad(static_cast<std::size_t>(depth), '\t');
    if (value.is_null()) throw std::invalid_argument("cannot serialize a null plist value");

    if (const auto* flag = value.get_if<bool>()) {
        out += pad + (*flag ? "<true/>\n" : "<false/>\n");
    } else if (const auto* integer = value.get_if<std::int64_t>()) {
        out += std::format("{}<integer>{}</integer>\n", pad, *integer);
    } else if (const auto* real = value.get_if<double>()) {
        std::string text;
        if (std::isnan(*real)) {
            text = "nan";
        } else if (std::isinf(*real)) {
            text = *real > 0 ? "+infinity" : "-infinity";
        } else {
            text = std::format("{}", *real);
        }
        out += pad + "<real>" + text + "</real>\n";
    } else if (const auto* string = value.get_if<std::string>()) {
        out += pad + "<string>";
        append_escaped(out, *string);
        out += "</string>\n";
    } else if (const auto* data = value.get_if<Data>()) {
        out += pad + "<data>" + base64_encode(data->bytes) + "</data>\n";
    } else if (const auto* date = value.get_if<Date>()) {
        out += pad + "<date>" + format_date(date->seconds) + "</date>\n";
    } else if (const auto* array = value.get_if<Array>()) {
        if (array->empty()) {
            out += pad + "<array/>\n";
            return;
        }
        out += pad + "<array>\n";
        for (const Value& item : *array) write_value(out, item, depth + 1);
        out += pad + "</array>\n";
    } else if (const auto* dict = value.get_if<Dict>()) {
        if (dict->empty()) {
            out += pad + "<dict/>\n";
            return;
        }
        out += pad + "<dict>\n";
        for (const auto& [key, item] : dict->items()) {
            out += pad + "\t<key>";
            append_escaped(out, key);
            out += "</key>\n";
            write_value(out, item, depth + 1);
        }
        out += pad + "</dict>\n";
    }
}

}  // namespace

Value parse_xml(std::string_view text) { return XmlReader(text).parse_document(); }

std::string to_xml(const Value& value) {
    std::string out =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n";
    write_value(out, value, 0);
    out += "</plist>\n";
    return out;
}

}  // namespace winx::plist
