#include "winx/files.hpp"

#include <windows.h>

#include <dpapi.h>
#include <knownfolders.h>
#include <shlobj.h>

#include <fstream>
#include <iterator>
#include <stdexcept>
#include <system_error>

#include "winx/base64.hpp"
#include "winx/text.hpp"

namespace winx {

std::filesystem::path app_data_dir() {
    std::filesystem::path directory;
    wchar_t override_path[MAX_PATH];
    const DWORD length = GetEnvironmentVariableW(L"WINX_HOME", override_path, MAX_PATH);
    if (length > 0 && length < MAX_PATH) {
        directory = override_path;
    } else {
        PWSTR local = nullptr;
        const HRESULT result = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local);
        if (FAILED(result)) {
            CoTaskMemFree(local);
            throw std::runtime_error("cannot resolve %LOCALAPPDATA%");
        }
        directory = std::filesystem::path(local) / L"WinXcode";
        CoTaskMemFree(local);
    }
    std::filesystem::create_directories(directory);
    return directory;
}

std::optional<std::vector<std::uint8_t>> read_file(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) return std::nullopt;
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + to_utf8(path.wstring()));
    const std::vector<char> raw((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
    return std::vector<std::uint8_t>(raw.begin(), raw.end());
}

std::optional<std::string> read_text_file(const std::filesystem::path& path) {
    const auto bytes = read_file(path);
    if (!bytes) return std::nullopt;
    return std::string(bytes->begin(), bytes->end());
}

void write_file(const std::filesystem::path& path, std::span<const std::uint8_t> data) {
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
    std::filesystem::path temporary = path;
    temporary += L".tmp";
    {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot write " + to_utf8(temporary.wstring()));
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
        if (!out) throw std::runtime_error("cannot write " + to_utf8(temporary.wstring()));
    }
    std::filesystem::rename(temporary, path);
}

void write_text_file(const std::filesystem::path& path, std::string_view text) {
    write_file(path, {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()});
}

namespace secure {

std::vector<std::uint8_t> protect(std::span<const std::uint8_t> plaintext) {
    DATA_BLOB in{static_cast<DWORD>(plaintext.size()), const_cast<BYTE*>(plaintext.data())};
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"WinXcode", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN,
                          &out)) {
        throw std::runtime_error("CryptProtectData failed: " + win32_error_message(GetLastError()));
    }
    std::vector<std::uint8_t> result(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return result;
}

std::vector<std::uint8_t> unprotect(std::span<const std::uint8_t> ciphertext) {
    DATA_BLOB in{static_cast<DWORD>(ciphertext.size()), const_cast<BYTE*>(ciphertext.data())};
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN,
                            &out)) {
        throw std::runtime_error("CryptUnprotectData failed: " +
                                 win32_error_message(GetLastError()));
    }
    std::vector<std::uint8_t> result(out.pbData, out.pbData + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return result;
}

void write_file(const std::filesystem::path& path, std::span<const std::uint8_t> plaintext) {
    winx::write_file(path, protect(plaintext));
}

std::optional<std::vector<std::uint8_t>> read_file(const std::filesystem::path& path) {
    const auto encrypted = winx::read_file(path);
    if (!encrypted) return std::nullopt;
    return unprotect(*encrypted);
}

}  // namespace secure

std::vector<PemBlock> pem_decode_all(std::string_view text) {
    static constexpr std::string_view kBegin = "-----BEGIN ";
    static constexpr std::string_view kDashes = "-----";
    std::vector<PemBlock> blocks;
    std::size_t pos = 0;
    for (;;) {
        const auto begin = text.find(kBegin, pos);
        if (begin == std::string_view::npos) break;
        const auto label_start = begin + kBegin.size();
        const auto label_end = text.find(kDashes, label_start);
        if (label_end == std::string_view::npos) break;
        const std::string label(text.substr(label_start, label_end - label_start));
        const std::string footer = "-----END " + label + "-----";
        const auto body_start = label_end + kDashes.size();
        const auto body_end = text.find(footer, body_start);
        if (body_end == std::string_view::npos) break;
        if (auto der = base64_decode(text.substr(body_start, body_end - body_start))) {
            blocks.push_back({label, std::move(*der)});
        }
        pos = body_end + footer.size();
    }
    return blocks;
}

std::optional<std::vector<std::uint8_t>> pem_decode(std::string_view text, std::string_view label) {
    for (auto& block : pem_decode_all(text)) {
        if (block.label == label) return std::move(block.der);
    }
    return std::nullopt;
}

std::string pem_encode(std::string_view label, std::span<const std::uint8_t> der) {
    const std::string encoded = base64_encode(der);
    std::string out = "-----BEGIN " + std::string(label) + "-----\n";
    for (std::size_t i = 0; i < encoded.size(); i += 64) {
        out.append(encoded, i, 64);
        out += '\n';
    }
    out += "-----END " + std::string(label) + "-----\n";
    return out;
}

}  // namespace winx
