#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "winx/plist.hpp"

// Pairing records written by Apple Mobile Device Service when the user taps
// "Trust" on a device. One <UDID>.plist per device, XML or binary, under
// %ProgramData%\Apple\Lockdown.
namespace winx::device {

struct PairRecord {
    std::string udid;
    std::string host_id;
    std::string system_buid;
    std::string wifi_mac_address;
    // PEM-encoded. The private keys must never be logged or displayed.
    std::vector<std::uint8_t> host_certificate;
    std::vector<std::uint8_t> host_private_key;
    std::vector<std::uint8_t> root_certificate;
    std::vector<std::uint8_t> root_private_key;
    std::vector<std::uint8_t> device_certificate;
    std::vector<std::uint8_t> escrow_bag;

    // True when the record has everything a lockdown TLS session needs.
    bool usable_for_session() const noexcept;
    // Names of the fields that are present, for diagnostics.
    std::vector<std::string> present_fields() const;
};

// %ProgramData%\Apple\Lockdown
std::filesystem::path lockdown_directory();

PairRecord parse_pair_record(const plist::Value& plist, std::string udid);

// Returns nullopt when no record exists for the device. Throws if the file
// exists but cannot be read or parsed.
std::optional<PairRecord> load_pair_record(std::string_view udid);
std::optional<PairRecord> load_pair_record(std::string_view udid,
                                           const std::filesystem::path& directory);

// SystemBUID from SystemConfiguration.plist: the identity this PC presents to
// every device it pairs with.
std::optional<std::string> load_system_buid();

// UDIDs that have a record on disk.
std::vector<std::string> list_paired_udids();

}  // namespace winx::device
