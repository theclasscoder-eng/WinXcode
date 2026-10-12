#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// Read-only view of Mach-O images: enough structure to place and check a
// code signature.
namespace winx::codesign {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

class MachOError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

inline constexpr std::uint32_t kMachHeaderMagic64 = 0xFEEDFACF;
inline constexpr std::uint32_t kFatMagic = 0xCAFEBABE;
inline constexpr std::uint32_t kCpuTypeArm64 = 0x0100000C;
inline constexpr std::uint32_t kFileTypeExecute = 2;
inline constexpr std::uint32_t kFileTypeDylib = 6;
inline constexpr std::uint32_t kLoadCommandSegment64 = 0x19;
inline constexpr std::uint32_t kLoadCommandCodeSignature = 0x1D;
inline constexpr std::size_t kMachHeaderSize64 = 32;
inline constexpr std::size_t kLinkeditDataCommandSize = 16;

struct Segment {
    std::string name;
    std::size_t command_offset = 0;  // of the LC_SEGMENT_64 within the image
    std::uint64_t vm_address = 0;
    std::uint64_t vm_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
};

// One architecture. All offsets are relative to the start of the slice.
struct MachOSlice {
    std::uint32_t cpu_type = 0;
    std::uint32_t cpu_subtype = 0;
    std::uint32_t file_type = 0;
    std::uint32_t command_count = 0;
    std::uint32_t commands_size = 0;
    std::vector<Segment> segments;
    // LC_CODE_SIGNATURE, when the image already has one.
    std::optional<std::size_t> signature_command_offset;
    std::uint32_t signature_offset = 0;
    std::uint32_t signature_size = 0;
    // Lowest file offset used by section contents: the limit for growing the
    // load commands.
    std::uint64_t first_section_offset = 0;

    const Segment* find_segment(std::string_view name) const;
    std::size_t page_size() const { return cpu_type == kCpuTypeArm64 ? 0x4000 : 0x1000; }

    // Accepts 64-bit little-endian images only, which covers every iOS target
    // since iOS 11.
    static MachOSlice parse(ByteView image);
};

struct FatArch {
    std::uint32_t cpu_type = 0;
    std::uint32_t cpu_subtype = 0;
    std::uint32_t offset = 0;
    std::uint32_t size = 0;
    std::uint32_t align = 0;  // log2
};

bool is_thin_macho(ByteView data);
bool is_fat_macho(ByteView data);
bool is_macho(ByteView data);
std::vector<FatArch> parse_fat(ByteView data);

// Little- and big-endian accessors shared with the signer.
std::uint32_t read_le32(ByteView data, std::size_t offset);
std::uint64_t read_le64(ByteView data, std::size_t offset);
std::uint32_t read_be32(ByteView data, std::size_t offset);
std::uint64_t read_be64(ByteView data, std::size_t offset);
void write_le32(Bytes& data, std::size_t offset, std::uint32_t value);
void write_le64(Bytes& data, std::size_t offset, std::uint64_t value);
void append_be32(Bytes& data, std::uint32_t value);
void append_be64(Bytes& data, std::uint64_t value);

}  // namespace winx::codesign
