#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include "winx/base64.hpp"
#include "winx/plist.hpp"

using namespace winx;
using plist::Array;
using plist::Data;
using plist::Date;
using plist::Dict;
using plist::Value;

namespace {

using Bytes = std::vector<std::uint8_t>;

void put_be64(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(value >> shift));
}

// Assembles a bplist00 with one-byte offsets from already-encoded objects.
Bytes build_bplist(const std::vector<Bytes>& objects, std::uint64_t top_object = 0) {
    Bytes out{'b', 'p', 'l', 'i', 's', 't', '0', '0'};
    std::vector<std::size_t> offsets;
    for (const Bytes& object : objects) {
        offsets.push_back(out.size());
        out.insert(out.end(), object.begin(), object.end());
    }
    const std::size_t table_offset = out.size();
    for (const std::size_t offset : offsets) out.push_back(static_cast<std::uint8_t>(offset));
    out.insert(out.end(), 6, 0);  // unused + sort version
    out.push_back(1);             // offset size
    out.push_back(1);             // object reference size
    put_be64(out, objects.size());
    put_be64(out, top_object);
    put_be64(out, table_offset);
    return out;
}

Bytes ascii(const std::string& text) {
    Bytes out{static_cast<std::uint8_t>(0x50 | text.size())};
    out.insert(out.end(), text.begin(), text.end());
    return out;
}

}  // namespace

TEST_CASE("base64 round-trips and tolerates whitespace", "[base64]") {
    const Bytes hello{'h', 'e', 'l', 'l', 'o'};
    CHECK(base64_encode(hello) == "aGVsbG8=");
    CHECK(base64_encode(Bytes{}) == "");
    CHECK(base64_encode(Bytes{0xFF}) == "/w==");
    CHECK(base64_decode("aGVs\n\tbG8=") == hello);
    CHECK(base64_decode("aGVsbG8") == hello);
    CHECK_FALSE(base64_decode("aGVs*G8=").has_value());
}

TEST_CASE("XML plist parses a usbmux Attached message", "[plist][xml]") {
    const std::string xml = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>DeviceID</key>
	<integer>7</integer>
	<key>MessageType</key>
	<string>Attached</string>
	<key>Properties</key>
	<dict>
		<key>ConnectionType</key>
		<string>USB</string>
		<key>ProductID</key>
		<integer>4776</integer>
		<key>SerialNumber</key>
		<string>00008110001A2B3C4D5E6F78</string>
	</dict>
</dict>
</plist>)";
    const Value value = plist::parse_xml(xml);
    CHECK(value.string_at("MessageType") == "Attached");
    CHECK(value.int_at("DeviceID") == 7);
    const Value* properties = value.find("Properties");
    REQUIRE(properties != nullptr);
    CHECK(properties->string_at("ConnectionType") == "USB");
    CHECK(properties->int_at("ProductID") == 4776);
    CHECK_FALSE(value.string_at("Missing").has_value());
    CHECK_FALSE(value.int_at("MessageType").has_value());
}

TEST_CASE("XML plist handles every value type", "[plist][xml]") {
    const std::string xml = R"(<plist version="1.0"><dict>
        <key>t</key><true/>
        <key>f</key><false></false>
        <key>neg</key><integer> -42 </integer>
        <key>hex</key><integer>0x1F</integer>
        <key>real</key><real>1.5</real>
        <key>esc</key><string>a &lt; b &amp;&amp; c &#x263A; &#65;</string>
        <key>cdata</key><string><![CDATA[<raw & text>]]></string>
        <key>empty</key><string/>
        <key>data</key><data>
            aGVs
            bG8=
        </data>
        <key>date</key><date>2001-01-02T00:00:01Z</date>
        <key>list</key><array><integer>1</integer><!-- note --><string>two</string><array/></array>
        <key>nothing</key><dict/>
    </dict></plist>)";
    const Value value = plist::parse_xml(xml);
    CHECK(value.bool_at("t") == true);
    CHECK(value.bool_at("f") == false);
    CHECK(value.int_at("neg") == -42);
    CHECK(value.int_at("hex") == 31);
    CHECK(*value.find("real") == Value(1.5));
    CHECK(value.string_at("esc") == "a < b && c \xE2\x98\xBA A");
    CHECK(value.string_at("cdata") == "<raw & text>");
    CHECK(value.string_at("empty") == "");
    REQUIRE(value.data_at("data") != nullptr);
    CHECK(value.data_at("data")->bytes == Bytes{'h', 'e', 'l', 'l', 'o'});
    CHECK(*value.find("date") == Value(Date{86401.0}));
    const Array& list = value.find("list")->as_array();
    REQUIRE(list.size() == 3);
    CHECK(list[0] == Value(1));
    CHECK(list[1] == Value("two"));
    CHECK(list[2].as_array().empty());
    CHECK(value.find("nothing")->as_dict().empty());
}

TEST_CASE("XML plist survives a write/parse round trip", "[plist][xml]") {
    const Value original = Dict{
        {"MessageType", "Listen"},
        {"kLibUSBMuxVersion", 3},
        {"Flag", true},
        {"Ratio", 0.25},
        {"Text", "tags <b> & \"quotes\" \xC3\xA9"},
        {"Blob", Data{{0x00, 0x01, 0xFE, 0xFF}}},
        {"When", Date{730000000.0}},
        {"Items", Array{1, "two", Dict{{"three", 3}}, Array{}}},
        {"Empty", Dict{}},
    };
    const std::string xml = plist::to_xml(original);
    CHECK(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    CHECK(plist::parse_xml(xml) == original);
    // parse() must pick the XML reader for text input.
    const Bytes bytes(xml.begin(), xml.end());
    CHECK(plist::parse(bytes) == original);
}

TEST_CASE("XML plist rejects malformed input", "[plist][xml]") {
    CHECK_THROWS_AS(plist::parse_xml(""), plist::ParseError);
    CHECK_THROWS_AS(plist::parse_xml("<plist><dict><key>a</key>"), plist::ParseError);
    CHECK_THROWS_AS(plist::parse_xml("<plist><dict><string>a</string></dict></plist>"),
                    plist::ParseError);
    CHECK_THROWS_AS(plist::parse_xml("<plist><bogus/></plist>"), plist::ParseError);
    CHECK_THROWS_AS(plist::parse_xml("<plist><integer>12x</integer></plist>"), plist::ParseError);
    CHECK_THROWS_AS(plist::parse_xml("<plist><data>!!!</data></plist>"), plist::ParseError);
    CHECK_THROWS_AS(plist::parse_xml("<plist><string>a</integer></plist>"), plist::ParseError);
    CHECK_THROWS_AS(plist::parse_xml("<plist><string>&bogus;</string></plist>"),
                    plist::ParseError);
    CHECK_THROWS_AS(plist::to_xml(Value{}), std::invalid_argument);
}

TEST_CASE("binary plist parses a dictionary of mixed types", "[plist][binary]") {
    const std::vector<Bytes> objects{
        {0xD5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},     // 0: dict, 5 keys then 5 values
        ascii("HostID"),                           // 1
        ascii("Count"),                            // 2
        ascii("Blob"),                             // 3
        ascii("Flag"),                             // 4
        ascii("Name"),                             // 5
        ascii("ABC-123"),                          // 6
        {0x11, 0x01, 0x00},                        // 7: 2-byte integer 256
        {0x43, 0x01, 0x02, 0x03},                  // 8: data
        {0x09},                                    // 9: true
        {0x63, 0x00, 0x5A, 0x00, 0x6F, 0x00, 0xEB} // 10: UTF-16 "Zoë"
    };
    const Bytes bytes = build_bplist(objects);
    const Value value = plist::parse(bytes);
    CHECK(value.string_at("HostID") == "ABC-123");
    CHECK(value.int_at("Count") == 256);
    REQUIRE(value.data_at("Blob") != nullptr);
    CHECK(value.data_at("Blob")->bytes == Bytes{1, 2, 3});
    CHECK(value.bool_at("Flag") == true);
    CHECK(value.string_at("Name") == "Zo\xC3\xAB");
}

TEST_CASE("binary plist handles numbers, dates and long strings", "[plist][binary]") {
    const std::string long_text(20, 'x');
    Bytes long_string{0x5F, 0x10, 0x14};  // length 0x14 follows as a 1-byte integer
    long_string.insert(long_string.end(), long_text.begin(), long_text.end());

    const std::vector<Bytes> objects{
        {0xA5, 1, 2, 3, 4, 5},                                          // 0: array
        {0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE},         // 1: -2
        {0x23, 0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},         // 2: 1.5
        {0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},         // 3: date 0
        long_string,                                                    // 4
        {0x08},                                                         // 5: false
    };
    const Value value = plist::parse_binary(build_bplist(objects));
    const Array& array = value.as_array();
    REQUIRE(array.size() == 5);
    CHECK(array[0] == Value(-2));
    CHECK(array[1] == Value(1.5));
    CHECK(array[2] == Value(Date{0.0}));
    CHECK(array[3] == Value(long_text));
    CHECK(array[4] == Value(false));
    CHECK(plist::to_xml(array[2]).find("<date>2001-01-01T00:00:00Z</date>") != std::string::npos);
}

TEST_CASE("binary plist rejects malformed input", "[plist][binary]") {
    const Bytes valid = build_bplist({ascii("ok")});
    CHECK(plist::parse_binary(valid) == Value("ok"));

    SECTION("truncated file") {
        const Bytes truncated(valid.begin(), valid.begin() + 12);
        CHECK_THROWS_AS(plist::parse_binary(truncated), plist::ParseError);
    }
    SECTION("array that contains itself") {
        CHECK_THROWS_AS(plist::parse_binary(build_bplist({{0xA1, 0}})), plist::ParseError);
    }
    SECTION("reference past the object table") {
        CHECK_THROWS_AS(plist::parse_binary(build_bplist({{0xA1, 9}})), plist::ParseError);
    }
    SECTION("string longer than the file") {
        CHECK_THROWS_AS(plist::parse_binary(build_bplist({{0x5F, 0x11, 0xFF, 0xFF, 'a'}})),
                        plist::ParseError);
    }
    SECTION("top object out of range") {
        CHECK_THROWS_AS(plist::parse_binary(build_bplist({ascii("ok")}, 3)), plist::ParseError);
    }
    SECTION("non-string dictionary key") {
        CHECK_THROWS_AS(plist::parse_binary(build_bplist({{0xD1, 1, 1}, {0x09}})),
                        plist::ParseError);
    }
}
