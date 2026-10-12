#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "winx/plist.hpp"
#include "winx/project.hpp"

// Assembles an iOS .app bundle from build products.
namespace winx::build {

struct BundleRequest {
    std::filesystem::path project_dir;
    ProjectConfig config;
    std::string product;
    std::string deployment_target;  // e.g. "17.0"; taken from the package manifest
    std::string sdk_version;        // e.g. "18.2"
    std::filesystem::path executable;
    // Directory the build left its products in; resource bundles and dynamic
    // libraries found here are copied into the app.
    std::filesystem::path bin_dir;
    std::filesystem::path output_dir;
};

struct BundleResult {
    std::filesystem::path bundle;
    std::string bundle_id;
    std::vector<std::string> warnings;
};

// Info.plist contents: the keys iOS requires, overlaid with the user's own
// plist when the project has one.
plist::Value make_info_plist(const BundleRequest& request, const std::string& bundle_id,
                             const plist::Value* user_plist);

// Creates <output_dir>/<product>.app, replacing an existing one.
BundleResult assemble_bundle(const BundleRequest& request);

// ---- Images (Windows Imaging Component) -----------------------------------

// Writes `source` scaled to size x size pixels as a PNG.
void scale_png(const std::filesystem::path& source, const std::filesystem::path& destination,
               unsigned size);
// Writes 32-bit BGRA pixels as a PNG.
void write_png(const std::filesystem::path& destination, unsigned width, unsigned height,
               std::span<const std::uint8_t> bgra);
std::pair<unsigned, unsigned> image_size(const std::filesystem::path& path);

}  // namespace winx::build
