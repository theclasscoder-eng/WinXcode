#pragma once

#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// xtool-compatible project description: a SwiftPM package plus xtool.yml.
namespace winx::build {

class ProjectError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct ExtensionConfig {
    std::string product;
    std::string bundle_id;
    std::string info_path;
    std::string entitlements_path;
    std::vector<std::string> resources;
};

// The contents of xtool.yml. Field names in the file follow xtool: version,
// orgID, bundleID, product, infoPath, entitlementsPath, iconPath, resources,
// extensions.
struct ProjectConfig {
    int version = 1;
    std::string org_id;
    std::string bundle_id;
    std::string product;
    std::string info_path;
    std::string entitlements_path;
    std::string icon_path;
    std::vector<std::string> resources;
    std::vector<ExtensionConfig> extensions;

    static ProjectConfig parse(std::string_view yaml);
    // Reads <project>/xtool.yml.
    static ProjectConfig load(const std::filesystem::path& project_dir);
    std::string to_yaml() const;
    void save(const std::filesystem::path& project_dir) const;

    // bundleID when set, otherwise "<orgID>.<product>".
    std::string bundle_id_for(std::string_view product_name) const;
};

// What `swift package dump-package` says about the root package.
struct PackageInfo {
    std::string name;
    std::vector<std::string> library_products;
    std::string ios_deployment_target;  // empty when the manifest does not set one
};

PackageInfo parse_package_dump(std::string_view json_text);
// The library product that becomes the app: the configured one, or the only one.
std::string select_product(const ProjectConfig& config, const PackageInfo& package);

bool is_valid_project_name(std::string_view name);
// Writes a new SwiftUI project into `directory`, which must not exist yet.
void create_project(const std::filesystem::path& directory, std::string_view name,
                    std::string_view org_id = "com.example");

}  // namespace winx::build
