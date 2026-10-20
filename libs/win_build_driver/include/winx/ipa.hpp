#pragma once

#include <filesystem>

#include "winx/archive.hpp"

// .ipa packages: a zip archive holding the app as Payload/<Name>.app. This is
// what App Store Connect, sideloading tools and MDM servers accept.
namespace winx::build {

// Packs the .app directory `bundle` into `ipa`, replacing an existing file.
// Mach-O files are marked executable and directories get Unix modes, so the
// archive unpacks correctly on macOS and on the device. Throws ArchiveError.
void write_ipa(const std::filesystem::path& bundle, const std::filesystem::path& ipa);

// Unpacks `ipa` into `directory` and returns the path of the .app inside
// Payload/. Entries that would land outside `directory`, symbolic links and
// encrypted entries are refused with ArchiveError.
std::filesystem::path extract_ipa(const std::filesystem::path& ipa,
                                  const std::filesystem::path& directory);

}  // namespace winx::build
