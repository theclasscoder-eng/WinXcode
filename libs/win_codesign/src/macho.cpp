#include "winx/macho.hpp"

#include <algorithm>
#include <format>

namespace winx::codesign {
namespace {

constexpr std::size_t kSegmentCommandSize64 = 72;
constexpr std::size_t kSectionSize64 = 80;
constexpr std::uint32_t kSectionTypeMask = 0xFF;
constexpr std::uint32_t kSectionZeroFill = 0x1;
constexpr std::uint32_t kSectionThreadZeroFill = 0x12;
constexpr std::uint32_t kSectionGbZeroFill = 0xC;

void need(ByteView data, std::size_t offset, std::size_t length) {
    if (offset > data.size() || length > data.size() - offset) {
        throw MachOError("the Mach-O image is truncated");
    }
}

std::string fixed_string(ByteView data, std::size_t offset, std::size_t length) {
    need(data, offset, length);
    const char* text = reinterpret_cast<const char*>(data.data() + offset);
    return std::string(text, std::find(text, text + length, '\0'));
}

}  // namespace

std::uint32_t read_le32(ByteView data, std::size_t offset) {
    need(data, offset, 4);
    return static_cast<std::uint32_t>(data[offset]) |
           (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::uint64_t read_le64(ByteView data, std::size_t offset) {
    return read_le32(data, offset) | (static_cast<std::uint64_t>(read_le32(data, offset + 4)) << 32);
}

std::uint32_t read_be32(ByteView data, std::size_t offset) {
    need(data, offset, 4);
    return (static_cast<std::uint32_t>(data[offset]) << 24) |
           (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
           static_cast<std::uint32_t>(data[offset + 3]);
}

std::uint64_t read_be64(ByteView data, std::size_t offset) {
    return (static_cast<std::uint64_t>(read_be32(data, offset)) << 32) | read_be32(data, offset + 4);
}

void write_le32(Bytes& data, std::size_t offset, std::uint32_t value) {
    need(data, offset, 4);
    for (int i = 0; i < 4; ++i) data[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
}

void write_le64(Bytes& data, std::size_t offset, std::uint64_t value) {
    write_le32(data, offset, static_cast<std::uint32_t>(value));
    write_le32(data, offset + 4, static_cast<std::uint32_t>(value >> 32));
}

void append_be32(Bytes& data, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) data.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append_be64(Bytes& data, std::uint64_t value) {
    append_be32(data, static_cast<std::uint32_t>(value >> 32));
    append_be32(data, static_cast<std::uint32_t>(value));
}

bool is_thin_macho(ByteView data) {
    return data.size() >= kMachHeaderSize64 && read_le32(data, 0) == kMachHeaderMagic64;
}

bool is_fat_macho(ByteView data) {
    // Java class files share the magic; they have a much larger "arch count".
    return data.size() >= 8 && read_be32(data, 0) == kFatMagic && read_be32(data, 4) < 32;
}

bool is_macho(ByteView data) { return is_thin_macho(data) || is_fat_macho(data); }

const Segment* MachOSlice::find_segment(std::string_view name) const {
    for (const Segment& segment : segments) {
        if (segment.name == name) return &segment;
    }
    return nullptr;
}

MachOSlice MachOSlice::parse(ByteView image) {
    if (!is_thin_macho(image)) throw MachOError("not a 64-bit Mach-O image");
    MachOSlice slice;
    slice.cpu_type = read_le32(image, 4);
    slice.cpu_subtype = read_le32(image, 8);
    slice.file_type = read_le32(image, 12);
    slice.command_count = read_le32(image, 16);
    slice.commands_size = read_le32(image, 20);
    need(image, kMachHeaderSize64, slice.commands_size);

    std::uint64_t first_section = image.size();
    std::size_t offset = kMachHeaderSize64;
    const std::size_t commands_end = kMachHeaderSize64 + slice.commands_size;
    for (std::uint32_t index = 0; index < slice.command_count; ++index) {
        if (offset + 8 > commands_end) throw MachOError("load commands overrun their table");
        const std::uint32_t command = read_le32(image, offset);
        const std::uint32_t size = read_le32(image, offset + 4);
        if (size < 8 || size > commands_end - offset) {
            throw MachOError("a load command has an invalid size");
        }

        if (command == kLoadCommandSegment64) {
            if (size < kSegmentCommandSize64) throw MachOError("a segment command is too small");
            Segment segment;
            segment.command_offset = offset;
            segment.name = fixed_string(image, offset + 8, 16);
            segment.vm_address = read_le64(image, offset + 24);
            segment.vm_size = read_le64(image, offset + 32);
            segment.file_offset = read_le64(image, offset + 40);
            segment.file_size = read_le64(image, offset + 48);
            const std::uint32_t section_count = read_le32(image, offset + 64);
            if (section_count > (size - kSegmentCommandSize64) / kSectionSize64) {
                throw MachOError("a segment lists more sections than fit in its command");
            }
            for (std::uint32_t s = 0; s < section_count; ++s) {
                const std::size_t section = offset + kSegmentCommandSize64 + s * kSectionSize64;
                const std::uint32_t section_offset = read_le32(image, section + 48);
                const std::uint32_t type = read_le32(image, section + 64) & kSectionTypeMask;
                const bool zero_fill = type == kSectionZeroFill || type == kSectionThreadZeroFill ||
                                       type == kSectionGbZeroFill;
                if (!zero_fill && section_offset != 0) {
                    first_section = std::min<std::uint64_t>(first_section, section_offset);
                }
            }
            slice.segments.push_back(std::move(segment));
        } else if (command == kLoadCommandCodeSignature) {
            if (size != kLinkeditDataCommandSize) {
                throw MachOError("the code signature load command has an unexpected size");
            }
            slice.signature_command_offset = offset;
            slice.signature_offset = read_le32(image, offset + 8);
            slice.signature_size = read_le32(image, offset + 12);
        }
        offset += size;
    }
    slice.first_section_offset = first_section;

    if (slice.signature_command_offset) {
        need(image, slice.signature_offset, slice.signature_size);
    }
    return slice;
}

std::vector<FatArch> parse_fat(ByteView data) {
    if (!is_fat_macho(data)) throw MachOError("not a universal Mach-O file");
    const std::uint32_t count = read_be32(data, 4);
    std::vector<FatArch> arches;
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::size_t entry = 8 + static_cast<std::size_t>(i) * 20;
        FatArch arch;
        arch.cpu_type = read_be32(data, entry);
        arch.cpu_subtype = read_be32(data, entry + 4);
        arch.offset = read_be32(data, entry + 8);
        arch.size = read_be32(data, entry + 12);
        arch.align = read_be32(data, entry + 16);
        need(data, arch.offset, arch.size);
        if (arch.align > 20) throw MachOError("a universal slice has an implausible alignment");
        arches.push_back(arch);
    }
    return arches;
}

}  // namespace winx::codesign
