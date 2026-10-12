#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

// Readers for the three nested formats of an Xcode.xip download:
// a xar container, holding a pbzx stream, holding a cpio archive.
namespace winx::build {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

class ArchiveError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Pull-style byte stream.
class ByteSource {
public:
    virtual ~ByteSource() = default;
    // Fills as much of `out` as is available; returns 0 only at end of stream.
    virtual std::size_t read(std::span<std::uint8_t> out) = 0;
    // Fills `out` completely or throws ArchiveError.
    void read_exact(std::span<std::uint8_t> out);
};

class MemorySource : public ByteSource {
public:
    explicit MemorySource(Bytes data) : data_(std::move(data)) {}
    std::size_t read(std::span<std::uint8_t> out) override;

private:
    Bytes data_;
    std::size_t offset_ = 0;
};

// A byte range of a file on disk.
class FileRangeSource : public ByteSource {
public:
    FileRangeSource(const std::filesystem::path& path, std::uint64_t offset, std::uint64_t length);
    std::size_t read(std::span<std::uint8_t> out) override;
    std::uint64_t consumed() const noexcept { return consumed_; }
    std::uint64_t length() const noexcept { return length_; }

private:
    std::ifstream file_;
    std::uint64_t length_;
    std::uint64_t consumed_ = 0;
};

// ---- xar ------------------------------------------------------------------

struct XarMember {
    std::string name;
    std::uint64_t offset = 0;  // absolute position in the xar file
    std::uint64_t length = 0;  // stored size
    std::string encoding;      // MIME type, "application/octet-stream" when stored as is
};

// Top-level members listed in the archive's table of contents.
std::vector<XarMember> read_xar_members(const std::filesystem::path& path);

// ---- pbzx -----------------------------------------------------------------

// Decodes a pbzx stream: a sequence of chunks, each either an xz stream or raw.
class PbzxSource : public ByteSource {
public:
    explicit PbzxSource(ByteSource& input);
    std::size_t read(std::span<std::uint8_t> out) override;

private:
    bool next_chunk();
    ByteSource& input_;
    Bytes chunk_;
    std::size_t offset_ = 0;
    bool more_ = true;
};

// ---- cpio -----------------------------------------------------------------

struct ArchiveEntry {
    enum class Type { File, Directory, Symlink, Other };
    std::string path;  // forward slashes, no leading "./"
    Type type = Type::Other;
    std::uint32_t mode = 0;
    std::uint64_t size = 0;
    std::string link_target;  // for symlinks
};

// Reads "odc" (070707) cpio archives sequentially.
class CpioReader {
public:
    explicit CpioReader(ByteSource& input) : input_(input) {}

    // Advances to the next entry, skipping any unread data of the current
    // one. Returns false at the trailer.
    bool next(ArchiveEntry& entry);
    // Streams the current file's contents. May be called at most once per entry.
    void read_data(const std::function<void(ByteView)>& sink);

private:
    void skip_data();
    ByteSource& input_;
    std::uint64_t remaining_ = 0;
};

}  // namespace winx::build
