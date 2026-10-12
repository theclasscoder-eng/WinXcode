#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>

#include "winx/pair_record.hpp"
#include "winx/plist.hpp"

using namespace winx;
using plist::Data;
using plist::Dict;

namespace {

const std::string kUdid = "00008110-001A2B3C4D5E6F78";

plist::Value sample_record() {
    return Dict{
        {"HostID", "11111111-2222-3333-4444-555555555555"},
        {"SystemBUID", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"},
        {"HostCertificate", Data{{'c', 'e', 'r', 't'}}},
        {"HostPrivateKey", Data{{'k', 'e', 'y'}}},
        {"RootCertificate", Data{{'r', 'o', 'o', 't'}}},
        {"DeviceCertificate", Data{{'d', 'e', 'v'}}},
        {"WiFiMACAddress", "aa:bb:cc:dd:ee:ff"},
    };
}

}  // namespace

TEST_CASE("pair record fields are extracted from a plist", "[pair_record]") {
    const device::PairRecord record = device::parse_pair_record(sample_record(), kUdid);
    CHECK(record.udid == kUdid);
    CHECK(record.host_id == "11111111-2222-3333-4444-555555555555");
    CHECK(record.system_buid == "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
    CHECK(record.host_private_key.size() == 3);
    CHECK(record.escrow_bag.empty());
    CHECK(record.usable_for_session());

    const auto fields = record.present_fields();
    CHECK(std::find(fields.begin(), fields.end(), "HostPrivateKey") != fields.end());
    CHECK(std::find(fields.begin(), fields.end(), "EscrowBag") == fields.end());
}

TEST_CASE("a record without host credentials cannot start a session", "[pair_record]") {
    const device::PairRecord record =
        device::parse_pair_record(Dict{{"HostID", "x"}, {"SystemBUID", "y"}}, kUdid);
    CHECK_FALSE(record.usable_for_session());
    CHECK_THROWS_AS(device::parse_pair_record(plist::Value("not a dict"), kUdid),
                    plist::ParseError);
}

TEST_CASE("pair records load from a directory by UDID", "[pair_record]") {
    const auto directory = std::filesystem::temp_directory_path() / "winx_pair_record_test";
    std::filesystem::create_directories(directory);
    {
        std::ofstream out(directory / (kUdid + ".plist"), std::ios::binary);
        out << plist::to_xml(sample_record());
    }

    const auto record = device::load_pair_record(kUdid, directory);
    REQUIRE(record.has_value());
    CHECK(record->wifi_mac_address == "aa:bb:cc:dd:ee:ff");

    CHECK_FALSE(device::load_pair_record("00000000-0000000000000000", directory).has_value());
    // A UDID is used as a file name, so path-like input must be refused.
    CHECK_FALSE(device::load_pair_record("..\\" + kUdid, directory).has_value());
    CHECK_FALSE(device::load_pair_record("", directory).has_value());

    std::filesystem::remove_all(directory);
}
