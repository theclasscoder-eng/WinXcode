#include "winx/pair_record.hpp"

#include <windows.h>

#include <knownfolders.h>
#include <shlobj.h>

#include <algorithm>
#include <stdexcept>
#include <system_error>

#include "winx/text.hpp"

namespace winx::device {
namespace {

constexpr std::string_view kSystemConfiguration = "SystemConfiguration";

// A UDID becomes a file name, so restrict it to the characters Apple uses.
bool is_valid_udid(std::string_view udid) {
    return !udid.empty() && udid.size() <= 64 &&
           std::all_of(udid.begin(), udid.end(), [](unsigned char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      c == '-';
           });
}

std::vector<std::uint8_t> bytes_at(const plist::Value& plist, std::string_view key) {
    const plist::Data* data = plist.data_at(key);
    return data ? data->bytes : std::vector<std::uint8_t>{};
}

}  // namespace

bool PairRecord::usable_for_session() const noexcept {
    return !host_id.empty() && !system_buid.empty() && !host_certificate.empty() &&
           !host_private_key.empty() && !root_certificate.empty();
}

std::vector<std::string> PairRecord::present_fields() const {
    std::vector<std::string> fields;
    const auto add = [&fields](bool present, const char* name) {
        if (present) fields.emplace_back(name);
    };
    add(!host_id.empty(), "HostID");
    add(!system_buid.empty(), "SystemBUID");
    add(!host_certificate.empty(), "HostCertificate");
    add(!host_private_key.empty(), "HostPrivateKey");
    add(!root_certificate.empty(), "RootCertificate");
    add(!root_private_key.empty(), "RootPrivateKey");
    add(!device_certificate.empty(), "DeviceCertificate");
    add(!escrow_bag.empty(), "EscrowBag");
    add(!wifi_mac_address.empty(), "WiFiMACAddress");
    return fields;
}

std::filesystem::path lockdown_directory() {
    PWSTR program_data = nullptr;
    const HRESULT result = SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &program_data);
    if (FAILED(result)) {
        CoTaskMemFree(program_data);
        throw std::runtime_error("cannot resolve %ProgramData%");
    }
    std::filesystem::path directory(program_data);
    CoTaskMemFree(program_data);
    return directory / L"Apple" / L"Lockdown";
}

PairRecord parse_pair_record(const plist::Value& plist, std::string udid) {
    if (!plist.is<plist::Dict>()) throw plist::ParseError("pairing record is not a dictionary");
    PairRecord record;
    record.udid = std::move(udid);
    record.host_id = plist.string_at("HostID").value_or("");
    record.system_buid = plist.string_at("SystemBUID").value_or("");
    record.wifi_mac_address = plist.string_at("WiFiMACAddress").value_or("");
    record.host_certificate = bytes_at(plist, "HostCertificate");
    record.host_private_key = bytes_at(plist, "HostPrivateKey");
    record.root_certificate = bytes_at(plist, "RootCertificate");
    record.root_private_key = bytes_at(plist, "RootPrivateKey");
    record.device_certificate = bytes_at(plist, "DeviceCertificate");
    record.escrow_bag = bytes_at(plist, "EscrowBag");
    return record;
}

std::optional<PairRecord> load_pair_record(std::string_view udid,
                                           const std::filesystem::path& directory) {
    if (!is_valid_udid(udid)) return std::nullopt;
    const std::filesystem::path path = directory / (to_wide(udid) + L".plist");
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) return std::nullopt;
    return parse_pair_record(plist::load_file(path), std::string(udid));
}

std::optional<PairRecord> load_pair_record(std::string_view udid) {
    return load_pair_record(udid, lockdown_directory());
}

std::optional<std::string> load_system_buid() {
    const std::filesystem::path path = lockdown_directory() / L"SystemConfiguration.plist";
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) return std::nullopt;
    return plist::load_file(path).string_at("SystemBUID");
}

std::vector<std::string> list_paired_udids() {
    std::vector<std::string> udids;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(lockdown_directory(), ec)) {
        if (!entry.is_regular_file(ec) || entry.path().extension() != L".plist") continue;
        std::string stem = to_utf8(entry.path().stem().wstring());
        if (stem != kSystemConfiguration && is_valid_udid(stem)) udids.push_back(std::move(stem));
    }
    return udids;
}

}  // namespace winx::device
