#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace winx {

// Per-user state directory: %WINX_HOME% if set, otherwise %LOCALAPPDATA%\WinXcode.
// Created on first use.
std::filesystem::path app_data_dir();

// Returns nullopt if the file does not exist; throws on other failures.
std::optional<std::vector<std::uint8_t>> read_file(const std::filesystem::path& path);
std::optional<std::string> read_text_file(const std::filesystem::path& path);

// Writes to a temporary file and renames it into place.
void write_file(const std::filesystem::path& path, std::span<const std::uint8_t> data);
void write_text_file(const std::filesystem::path& path, std::string_view text);

// Encryption bound to the current Windows user (DPAPI).
namespace secure {

std::vector<std::uint8_t> protect(std::span<const std::uint8_t> plaintext);
std::vector<std::uint8_t> unprotect(std::span<const std::uint8_t> ciphertext);

void write_file(const std::filesystem::path& path, std::span<const std::uint8_t> plaintext);
std::optional<std::vector<std::uint8_t>> read_file(const std::filesystem::path& path);

}  // namespace secure

struct PemBlock {
    std::string label;
    std::vector<std::uint8_t> der;
};

std::vector<PemBlock> pem_decode_all(std::string_view text);
// First block with the given label.
std::optional<std::vector<std::uint8_t>> pem_decode(std::string_view text, std::string_view label);
std::string pem_encode(std::string_view label, std::span<const std::uint8_t> der);

}  // namespace winx
