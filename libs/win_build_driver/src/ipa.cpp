#include "winx/ipa.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <format>
#include <fstream>
#include <string>
#include <tuple>
#include <vector>

#include <miniz.h>

#include "winx/text.hpp"

namespace winx::build {
namespace {

namespace fs = std::filesystem;

constexpr std::uint32_t kLocalHeader = 0x04034b50;
constexpr std::uint32_t kCentralHeader = 0x02014b50;
constexpr std::uint32_t kEndOfCentral = 0x06054b50;
constexpr std::uint32_t kZip64EndOfCentral = 0x06064b50;
constexpr std::uint32_t kZip64Locator = 0x07064b50;
constexpr std::uint16_t kUtf8Names = 0x0800;
constexpr std::uint16_t kStored = 0;
constexpr std::uint16_t kDeflated = 8;
// "Made by" Unix, so readers honour the mode in the high external-attribute bits.
constexpr std::uint16_t kMadeByUnix = 3 << 8;
constexpr std::uint16_t kVersion = 20;
constexpr std::uint16_t kVersionZip64 = 45;
constexpr std::uint64_t kMax32 = 0xFFFFFFFF;
constexpr std::uint32_t kDirectoryMode = 0040755;
constexpr std::uint32_t kFileMode = 0100644;
constexpr std::uint32_t kExecutableMode = 0100755;
constexpr std::uint32_t kTypeMask = 0170000;
constexpr std::uint32_t kSymlinkType = 0120000;
constexpr std::size_t kChunk = 256 * 1024;

void put16(std::vector<std::uint8_t>& out, std::uint64_t value) {
    out.push_back(static_cast<std::uint8_t>(value));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
}

void put32(std::vector<std::uint8_t>& out, std::uint64_t value) {
    put16(out, value & 0xFFFF);
    put16(out, (value >> 16) & 0xFFFF);
}

void put64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    put32(out, value & kMax32);
    put32(out, value >> 32);
}

std::string display(const fs::path& path) { return to_utf8(path.wstring()); }

bool is_macho(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    std::array<std::uint8_t, 4> magic{};
    file.read(reinterpret_cast<char*>(magic.data()), magic.size());
    if (file.gcount() != static_cast<std::streamsize>(magic.size())) return false;
    const std::uint32_t big = (std::uint32_t{magic[0]} << 24) | (std::uint32_t{magic[1]} << 16) |
                              (std::uint32_t{magic[2]} << 8) | magic[3];
    switch (big) {
        case 0xFEEDFACE: case 0xFEEDFACF:  // thin, big-endian
        case 0xCEFAEDFE: case 0xCFFAEDFE:  // thin, little-endian (arm64)
        case 0xCAFEBABE: case 0xCAFEBABF:  // universal
            return true;
        default:
            return false;
    }
}

// The current time in MS-DOS format, as every entry is stamped.
std::pair<std::uint16_t, std::uint16_t> dos_now() {
    const auto now = std::chrono::system_clock::now();
    const auto days = std::chrono::floor<std::chrono::days>(now);
    const std::chrono::year_month_day date(days);
    const std::chrono::hh_mm_ss time(std::chrono::floor<std::chrono::seconds>(now - days));
    const int year = std::clamp(static_cast<int>(date.year()), 1980, 2107);
    const auto dos_date = static_cast<std::uint16_t>((static_cast<unsigned>(year - 1980) << 9) |
                                                     (static_cast<unsigned>(date.month()) << 5) |
                                                     static_cast<unsigned>(date.day()));
    const auto dos_time = static_cast<std::uint16_t>((time.hours().count() << 11) |
                                                     (time.minutes().count() << 5) |
                                                     (time.seconds().count() / 2));
    return {dos_time, dos_date};
}

// A minimal streaming zip writer. miniz has one, but it cannot set the Unix
// modes an .ipa needs.
class ZipWriter {
public:
    explicit ZipWriter(const fs::path& path) : path_(path), out_(path, std::ios::binary) {
        if (!out_) throw ArchiveError("cannot create " + display(path));
        std::tie(dos_time_, dos_date_) = dos_now();
    }

    void add_directory(std::string name) {
        Entry entry;
        entry.name = std::move(name) + "/";
        entry.mode = kDirectoryMode;
        entry.offset = position();
        write_local_header(entry);
        entries_.push_back(std::move(entry));
    }

    void add_file(std::string name, const fs::path& source) {
        Entry entry;
        entry.name = std::move(name);
        entry.mode = is_macho(source) ? kExecutableMode : kFileMode;
        entry.size = fs::file_size(source);
        if (entry.size >= kMax32) {
            throw ArchiveError(std::format("{} is too large for an .ipa (4 GiB per file)",
                                           display(source)));
        }
        entry.method = entry.size == 0 ? kStored : kDeflated;
        entry.offset = position();
        write_local_header(entry);
        if (entry.size > 0) deflate_file(entry, source);

        // Sizes and checksum are known only now; fill them into the local header.
        std::vector<std::uint8_t> fields;
        put32(fields, entry.crc);
        put32(fields, entry.compressed);
        put32(fields, entry.size);
        out_.seekp(static_cast<std::streamoff>(entry.offset + 14));
        write(fields);
        out_.seekp(0, std::ios::end);
        entries_.push_back(std::move(entry));
    }

    void finish() {
        const std::uint64_t directory_offset = position();
        for (const Entry& entry : entries_) write_central_header(entry);
        const std::uint64_t directory_size = position() - directory_offset;
        const std::uint64_t count = entries_.size();

        std::vector<std::uint8_t> record;
        const bool zip64 = count >= 0xFFFF || directory_offset >= kMax32 || directory_size >= kMax32;
        if (zip64) {
            const std::uint64_t zip64_offset = position();
            put32(record, kZip64EndOfCentral);
            put64(record, 44);  // size of the rest of this record
            put16(record, kMadeByUnix | kVersionZip64);
            put16(record, kVersionZip64);
            put32(record, 0);
            put32(record, 0);
            put64(record, count);
            put64(record, count);
            put64(record, directory_size);
            put64(record, directory_offset);
            put32(record, kZip64Locator);
            put32(record, 0);
            put64(record, zip64_offset);
            put32(record, 1);
        }
        put32(record, kEndOfCentral);
        put16(record, 0);
        put16(record, 0);
        // With zip64 the classic fields hold sentinels; the real values are above.
        put16(record, zip64 ? 0xFFFF : count);
        put16(record, zip64 ? 0xFFFF : count);
        put32(record, zip64 ? kMax32 : directory_size);
        put32(record, zip64 ? kMax32 : directory_offset);
        put16(record, 0);
        write(record);
        out_.close();
        if (!out_) throw ArchiveError("cannot write " + display(path_));
    }

private:
    struct Entry {
        std::string name;
        std::uint32_t mode = 0;
        std::uint16_t method = kStored;
        std::uint32_t crc = 0;
        std::uint64_t compressed = 0;
        std::uint64_t size = 0;
        std::uint64_t offset = 0;
    };

    std::uint64_t position() { return static_cast<std::uint64_t>(out_.tellp()); }

    void write(const std::vector<std::uint8_t>& bytes) {
        out_.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        if (!out_) throw ArchiveError("cannot write " + display(path_));
    }

    void write_local_header(const Entry& entry) {
        std::vector<std::uint8_t> header;
        put32(header, kLocalHeader);
        put16(header, kVersion);
        put16(header, kUtf8Names);
        put16(header, entry.method);
        put16(header, dos_time_);
        put16(header, dos_date_);
        put32(header, 0);  // crc, compressed and uncompressed size, filled in later
        put32(header, 0);
        put32(header, 0);
        put16(header, entry.name.size());
        put16(header, 0);
        header.insert(header.end(), entry.name.begin(), entry.name.end());
        write(header);
    }

    void write_central_header(const Entry& entry) {
        const bool zip64 = entry.offset >= kMax32;
        std::vector<std::uint8_t> header;
        put32(header, kCentralHeader);
        put16(header, kMadeByUnix | (zip64 ? kVersionZip64 : kVersion));
        put16(header, zip64 ? kVersionZip64 : kVersion);
        put16(header, kUtf8Names);
        put16(header, entry.method);
        put16(header, dos_time_);
        put16(header, dos_date_);
        put32(header, entry.crc);
        // Past 4 GiB all three fields move to the zip64 extra field: miniz's
        // reader rejects an entry whose offset alone is there.
        put32(header, zip64 ? kMax32 : entry.compressed);
        put32(header, zip64 ? kMax32 : entry.size);
        put16(header, entry.name.size());
        put16(header, zip64 ? 28 : 0);
        put16(header, 0);  // comment
        put16(header, 0);  // disk
        put16(header, 0);  // internal attributes
        const bool directory = (entry.mode & kTypeMask) == 0040000;
        put32(header, (std::uint64_t{entry.mode} << 16) | (directory ? 0x10 : 0));
        put32(header, zip64 ? kMax32 : entry.offset);
        header.insert(header.end(), entry.name.begin(), entry.name.end());
        if (zip64) {
            put16(header, 0x0001);
            put16(header, 24);
            put64(header, entry.size);
            put64(header, entry.compressed);
            put64(header, entry.offset);
        }
        write(header);
    }

    void deflate_file(Entry& entry, const fs::path& source) {
        std::ifstream in(source, std::ios::binary);
        if (!in) throw ArchiveError("cannot read " + display(source));
        mz_stream stream{};
        // Negative window bits: raw deflate, without the zlib wrapper.
        if (mz_deflateInit2(&stream, MZ_DEFAULT_LEVEL, MZ_DEFLATED, -MZ_DEFAULT_WINDOW_BITS, 9,
                            MZ_DEFAULT_STRATEGY) != MZ_OK) {
            throw ArchiveError("cannot start compression");
        }
        struct End {
            mz_stream* stream;
            ~End() { mz_deflateEnd(stream); }
        } end{&stream};

        std::vector<std::uint8_t> input(kChunk);
        std::vector<std::uint8_t> output(kChunk);
        mz_ulong crc = MZ_CRC32_INIT;
        std::uint64_t read_total = 0;
        int status = MZ_OK;
        bool finishing = false;
        while (status != MZ_STREAM_END) {
            if (stream.avail_in == 0 && !finishing) {
                in.read(reinterpret_cast<char*>(input.data()), static_cast<std::streamsize>(input.size()));
                const auto got = static_cast<std::size_t>(in.gcount());
                read_total += got;
                crc = mz_crc32(crc, input.data(), got);
                stream.next_in = input.data();
                stream.avail_in = static_cast<unsigned>(got);
                finishing = got == 0 || read_total >= entry.size;
            }
            stream.next_out = output.data();
            stream.avail_out = static_cast<unsigned>(output.size());
            status = mz_deflate(&stream, finishing ? MZ_FINISH : MZ_NO_FLUSH);
            if (status != MZ_OK && status != MZ_STREAM_END && status != MZ_BUF_ERROR) {
                throw ArchiveError("compression failed for " + display(source));
            }
            const std::size_t produced = output.size() - stream.avail_out;
            out_.write(reinterpret_cast<const char*>(output.data()),
                       static_cast<std::streamsize>(produced));
            entry.compressed += produced;
        }
        if (!out_) throw ArchiveError("cannot write " + display(path_));
        if (read_total != entry.size) throw ArchiveError(display(source) + " changed while being packed");
        if (entry.compressed >= kMax32) throw ArchiveError(display(source) + " is too large for an .ipa");
        entry.crc = static_cast<std::uint32_t>(crc);
    }

    fs::path path_;
    std::ofstream out_;
    std::uint16_t dos_time_ = 0;
    std::uint16_t dos_date_ = 0;
    std::vector<Entry> entries_;
};

// Turns an archive member name into a path under `root`, or refuses it.
fs::path safe_destination(const fs::path& root, std::string_view name) {
    const auto refuse = [&] {
        return ArchiveError("the .ipa contains an unsafe path: " + std::string(name));
    };
    if (name.empty() || name.front() == '/' || name.find('\\') != std::string_view::npos ||
        name.find(':') != std::string_view::npos) {
        throw refuse();
    }
    fs::path relative;
    std::size_t start = 0;
    while (start < name.size()) {
        auto end = name.find('/', start);
        if (end == std::string_view::npos) end = name.size();
        const std::string_view part = name.substr(start, end - start);
        if (part.empty() || part == "." || part == "..") throw refuse();
        relative /= to_wide(part);
        start = end + 1;
    }
    return root / relative;
}

}  // namespace

void write_ipa(const fs::path& bundle, const fs::path& ipa) {
    if (!fs::is_directory(bundle) || bundle.extension() != L".app") {
        throw ArchiveError("not an .app bundle: " + display(bundle));
    }
    const std::string app = "Payload/" + to_utf8(bundle.filename().wstring());

    // Sorted, so the same bundle always packs to the same layout.
    std::vector<fs::path> items;
    for (const fs::directory_entry& item : fs::recursive_directory_iterator(bundle)) {
        if (item.is_symlink()) {
            throw ArchiveError("the bundle contains a symbolic link, which cannot go into an .ipa: " +
                               display(item.path()));
        }
        items.push_back(item.path());
    }
    std::sort(items.begin(), items.end());

    if (!ipa.parent_path().empty()) fs::create_directories(ipa.parent_path());
    fs::path partial = ipa;
    partial += L".partial";
    try {
        ZipWriter zip(partial);
        zip.add_directory("Payload");
        zip.add_directory(app);
        for (const fs::path& item : items) {
            const std::string name = app + "/" + to_utf8(item.lexically_relative(bundle).generic_wstring());
            if (fs::is_directory(item)) {
                zip.add_directory(name);
            } else {
                zip.add_file(name, item);
            }
        }
        zip.finish();
        fs::rename(partial, ipa);
    } catch (...) {
        std::error_code ignored;
        fs::remove(partial, ignored);
        throw;
    }
}

fs::path extract_ipa(const fs::path& ipa, const fs::path& directory) {
    std::ifstream in(ipa, std::ios::binary);
    if (!in) throw ArchiveError("cannot open " + display(ipa));
    mz_zip_archive zip{};
    zip.m_pIO_opaque = &in;
    zip.m_pRead = [](void* opaque, mz_uint64 offset, void* buffer, std::size_t size) -> std::size_t {
        auto& file = *static_cast<std::ifstream*>(opaque);
        file.clear();
        file.seekg(static_cast<std::streamoff>(offset));
        file.read(static_cast<char*>(buffer), static_cast<std::streamsize>(size));
        return static_cast<std::size_t>(file.gcount());
    };
    if (!mz_zip_reader_init(&zip, fs::file_size(ipa), 0)) {
        throw ArchiveError(display(ipa) + " is not a zip archive");
    }
    struct End {
        mz_zip_archive* zip;
        ~End() { mz_zip_reader_end(zip); }
    } end{&zip};

    fs::create_directories(directory);
    const mz_uint count = mz_zip_reader_get_num_files(&zip);
    for (mz_uint i = 0; i < count; ++i) {
        mz_zip_archive_file_stat stat{};
        if (!mz_zip_reader_file_stat(&zip, i, &stat)) {
            throw ArchiveError(std::format("entry {} of {} cannot be read", i, display(ipa)));
        }
        const std::string name = stat.m_filename;
        if (stat.m_is_encrypted || !stat.m_is_supported) {
            throw ArchiveError("the .ipa entry " + name + " is encrypted or uses an unsupported method");
        }
        if ((stat.m_version_made_by >> 8) == 3 && ((stat.m_external_attr >> 16) & kTypeMask) == kSymlinkType) {
            throw ArchiveError("the .ipa contains a symbolic link, which Windows cannot unpack: " + name);
        }
        const fs::path destination = safe_destination(directory, name);
        if (stat.m_is_directory) {
            fs::create_directories(destination);
            continue;
        }
        fs::create_directories(destination.parent_path());
        std::ofstream out(destination, std::ios::binary | std::ios::trunc);
        if (!out) throw ArchiveError("cannot create " + display(destination));
        const auto sink = [](void* opaque, mz_uint64, const void* data, std::size_t size) -> std::size_t {
            auto& file = *static_cast<std::ofstream*>(opaque);
            file.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
            return file ? size : 0;
        };
        if (!mz_zip_reader_extract_to_callback(&zip, i, sink, &out, 0)) {
            throw ArchiveError(std::format("{} could not be unpacked ({})", name,
                                           mz_zip_get_error_string(mz_zip_get_last_error(&zip))));
        }
    }

    std::vector<fs::path> apps;
    const fs::path payload = directory / L"Payload";
    if (fs::is_directory(payload)) {
        for (const fs::directory_entry& item : fs::directory_iterator(payload)) {
            if (item.is_directory() && item.path().extension() == L".app") apps.push_back(item.path());
        }
    }
    if (apps.size() != 1) {
        throw ArchiveError(apps.empty() ? "the .ipa holds no .app in Payload/"
                                        : "the .ipa holds more than one .app in Payload/");
    }
    return apps.front();
}

}  // namespace winx::build
