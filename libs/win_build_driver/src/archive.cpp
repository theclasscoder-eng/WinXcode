#include "winx/archive.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <format>

#include <lzma.h>
#include <miniz.h>

#include "winx/text.hpp"

namespace winx::build {
namespace {

constexpr std::array<std::uint8_t, 6> kXzMagic = {0xFD, '7', 'z', 'X', 'Z', 0x00};
constexpr std::uint64_t kPbzxMoreChunks = 1ull << 24;
constexpr std::uint64_t kMaxChunk = 256ull * 1024 * 1024;
constexpr std::size_t kCpioHeaderSize = 76;

std::uint64_t be(const std::uint8_t* data, std::size_t size) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < size; ++i) value = (value << 8) | data[i];
    return value;
}

std::uint64_t read_be64(ByteSource& source) {
    std::array<std::uint8_t, 8> raw{};
    source.read_exact(raw);
    return be(raw.data(), 8);
}

// Text between <tag> and </tag>, searching `xml` from `from`.
std::string tag_text(std::string_view xml, std::string_view tag, std::size_t from = 0) {
    const std::string open = "<" + std::string(tag) + ">";
    const std::string close = "</" + std::string(tag) + ">";
    const auto start = xml.find(open, from);
    if (start == std::string_view::npos) return {};
    const auto end = xml.find(close, start);
    if (end == std::string_view::npos) return {};
    return std::string(xml.substr(start + open.size(), end - start - open.size()));
}

std::uint64_t parse_octal(const char* text, std::size_t length) {
    std::uint64_t value = 0;
    const auto [end, ec] = std::from_chars(text, text + length, value, 8);
    if (ec != std::errc{} || end != text + length) throw ArchiveError("malformed cpio header");
    return value;
}

std::uint64_t parse_decimal(const std::string& text) {
    std::uint64_t value = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || text.empty()) throw ArchiveError("malformed xar table of contents");
    (void)end;
    return value;
}

}  // namespace

void ByteSource::read_exact(std::span<std::uint8_t> out) {
    while (!out.empty()) {
        const std::size_t count = read(out);
        if (count == 0) throw ArchiveError("the archive ends unexpectedly");
        out = out.subspan(count);
    }
}

std::size_t MemorySource::read(std::span<std::uint8_t> out) {
    const std::size_t count = std::min(out.size(), data_.size() - offset_);
    std::copy_n(data_.begin() + static_cast<std::ptrdiff_t>(offset_), count, out.begin());
    offset_ += count;
    return count;
}

FileRangeSource::FileRangeSource(const std::filesystem::path& path, std::uint64_t offset,
                                 std::uint64_t length)
    : file_(path, std::ios::binary), length_(length) {
    if (!file_) throw ArchiveError("cannot open " + to_utf8(path.wstring()));
    file_.seekg(static_cast<std::streamoff>(offset));
}

std::size_t FileRangeSource::read(std::span<std::uint8_t> out) {
    const std::uint64_t left = length_ - consumed_;
    const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), left));
    if (want == 0) return 0;
    file_.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(want));
    const auto got = static_cast<std::size_t>(file_.gcount());
    consumed_ += got;
    return got;
}

std::vector<XarMember> read_xar_members(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw ArchiveError("cannot open " + to_utf8(path.wstring()));
    std::array<std::uint8_t, 28> header{};
    file.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (file.gcount() != static_cast<std::streamsize>(header.size()) ||
        std::memcmp(header.data(), "xar!", 4) != 0) {
        throw ArchiveError("not a xip/xar archive");
    }
    const std::uint64_t header_size = be(header.data() + 4, 2);
    const std::uint64_t toc_compressed = be(header.data() + 8, 8);
    const std::uint64_t toc_uncompressed = be(header.data() + 16, 8);
    if (header_size < 28 || toc_compressed == 0 || toc_compressed > kMaxChunk ||
        toc_uncompressed > kMaxChunk) {
        throw ArchiveError("the xar header is not valid");
    }

    Bytes compressed(static_cast<std::size_t>(toc_compressed));
    file.seekg(static_cast<std::streamoff>(header_size));
    file.read(reinterpret_cast<char*>(compressed.data()),
              static_cast<std::streamsize>(compressed.size()));
    if (file.gcount() != static_cast<std::streamsize>(compressed.size())) {
        throw ArchiveError("the xar table of contents is truncated");
    }
    std::string toc(static_cast<std::size_t>(toc_uncompressed), '\0');
    mz_ulong toc_size = static_cast<mz_ulong>(toc.size());
    if (mz_uncompress(reinterpret_cast<unsigned char*>(toc.data()), &toc_size, compressed.data(),
                      static_cast<mz_ulong>(compressed.size())) != MZ_OK) {
        throw ArchiveError("the xar table of contents cannot be decompressed");
    }
    toc.resize(toc_size);

    const std::uint64_t heap = header_size + toc_compressed;
    std::vector<XarMember> members;
    std::size_t pos = 0;
    for (;;) {
        const auto start = toc.find("<file", pos);
        if (start == std::string::npos) break;
        const auto end = toc.find("</file>", start);
        if (end == std::string::npos) break;
        const std::string_view block(toc.data() + start, end - start);
        const std::string data = tag_text(block, "data");
        XarMember member;
        member.name = tag_text(block, "name");
        if (!data.empty()) {
            member.offset = heap + parse_decimal(tag_text(data, "offset"));
            member.length = parse_decimal(tag_text(data, "length"));
            const auto style = data.find("style=\"");
            if (style != std::string::npos) {
                const auto close = data.find('"', style + 7);
                if (close != std::string::npos) member.encoding = data.substr(style + 7, close - style - 7);
            }
        }
        if (!member.name.empty()) members.push_back(std::move(member));
        pos = end + 7;
    }
    return members;
}

PbzxSource::PbzxSource(ByteSource& input) : input_(input) {
    std::array<std::uint8_t, 4> magic{};
    input_.read_exact(magic);
    if (std::memcmp(magic.data(), "pbzx", 4) != 0) throw ArchiveError("not a pbzx stream");
    // The first word is the chunk size; its bit 24 says that chunks follow.
    more_ = (read_be64(input_) & kPbzxMoreChunks) != 0;
}

bool PbzxSource::next_chunk() {
    if (!more_) return false;
    const std::uint64_t flags = read_be64(input_);
    const std::uint64_t length = read_be64(input_);
    more_ = (flags & kPbzxMoreChunks) != 0;
    if (length > kMaxChunk) throw ArchiveError("a pbzx chunk is implausibly large");

    Bytes raw(static_cast<std::size_t>(length));
    input_.read_exact(raw);
    offset_ = 0;
    if (raw.size() < kXzMagic.size() || !std::equal(kXzMagic.begin(), kXzMagic.end(), raw.begin())) {
        chunk_ = std::move(raw);  // stored uncompressed
        return true;
    }

    // `flags` holds the uncompressed size for all but unusual streams; grow
    // the buffer if a chunk turns out larger.
    std::size_t capacity = static_cast<std::size_t>(std::max<std::uint64_t>(flags & 0xFFFFFFFF, 1 << 16));
    for (;;) {
        chunk_.resize(capacity);
        std::uint64_t memory_limit = UINT64_MAX;
        std::size_t in_pos = 0;
        std::size_t out_pos = 0;
        const lzma_ret result =
            lzma_stream_buffer_decode(&memory_limit, 0, nullptr, raw.data(), &in_pos, raw.size(),
                                      chunk_.data(), &out_pos, chunk_.size());
        if (result == LZMA_OK) {
            chunk_.resize(out_pos);
            return true;
        }
        if (result == LZMA_BUF_ERROR && capacity < kMaxChunk) {
            capacity *= 2;
            continue;
        }
        throw ArchiveError(std::format("a pbzx chunk failed to decompress (lzma error {})",
                                       static_cast<int>(result)));
    }
}

std::size_t PbzxSource::read(std::span<std::uint8_t> out) {
    while (offset_ == chunk_.size()) {
        if (!next_chunk()) return 0;
    }
    const std::size_t count = std::min(out.size(), chunk_.size() - offset_);
    std::copy_n(chunk_.begin() + static_cast<std::ptrdiff_t>(offset_), count, out.begin());
    offset_ += count;
    return count;
}

void CpioReader::skip_data() {
    std::array<std::uint8_t, 64 * 1024> scratch{};
    while (remaining_ > 0) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(remaining_, scratch.size()));
        input_.read_exact(std::span(scratch.data(), want));
        remaining_ -= want;
    }
}

bool CpioReader::next(ArchiveEntry& entry) {
    skip_data();
    std::array<char, kCpioHeaderSize> header{};
    input_.read_exact(std::span(reinterpret_cast<std::uint8_t*>(header.data()), header.size()));
    if (std::memcmp(header.data(), "070707", 6) != 0) {
        throw ArchiveError("unsupported cpio variant (expected the 070707 format)");
    }
    // magic 6, dev 6, ino 6, mode 6, uid 6, gid 6, nlink 6, rdev 6, mtime 11, namesize 6, filesize 11
    const auto mode = static_cast<std::uint32_t>(parse_octal(header.data() + 18, 6));
    const std::uint64_t name_size = parse_octal(header.data() + 59, 6);
    const std::uint64_t file_size = parse_octal(header.data() + 65, 11);
    if (name_size == 0 || name_size > 64 * 1024) throw ArchiveError("malformed cpio entry name");

    std::string name(static_cast<std::size_t>(name_size), '\0');
    input_.read_exact(std::span(reinterpret_cast<std::uint8_t*>(name.data()), name.size()));
    name.resize(std::strlen(name.c_str()));
    remaining_ = file_size;
    if (name == "TRAILER!!!") return false;

    while (name.starts_with("./")) name.erase(0, 2);
    entry = ArchiveEntry{};
    entry.path = std::move(name);
    entry.mode = mode;
    entry.size = file_size;
    switch (mode & 0170000) {
        case 0100000: entry.type = ArchiveEntry::Type::File; break;
        case 0040000: entry.type = ArchiveEntry::Type::Directory; break;
        case 0120000: {
            entry.type = ArchiveEntry::Type::Symlink;
            if (file_size > 64 * 1024) throw ArchiveError("malformed cpio symlink");
            entry.link_target.resize(static_cast<std::size_t>(file_size));
            input_.read_exact(std::span(reinterpret_cast<std::uint8_t*>(entry.link_target.data()),
                                        entry.link_target.size()));
            remaining_ = 0;
            entry.size = 0;
            break;
        }
        default: entry.type = ArchiveEntry::Type::Other;
    }
    return true;
}

void CpioReader::read_data(const std::function<void(ByteView)>& sink) {
    Bytes buffer(1024 * 1024);
    while (remaining_ > 0) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(remaining_, buffer.size()));
        input_.read_exact(std::span(buffer.data(), want));
        remaining_ -= want;
        sink(ByteView(buffer.data(), want));
    }
}

}  // namespace winx::build
