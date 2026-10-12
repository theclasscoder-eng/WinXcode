#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace winx {

std::string base64_encode(std::span<const std::uint8_t> data);

// Whitespace is ignored and padding is optional. Returns nullopt on any other
// character outside the base64 alphabet.
std::optional<std::vector<std::uint8_t>> base64_decode(std::string_view text);

}  // namespace winx
