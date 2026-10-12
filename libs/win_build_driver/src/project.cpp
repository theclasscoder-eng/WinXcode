#include "winx/project.hpp"

#include <algorithm>
#include <cctype>
#include <format>

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include "winx/files.hpp"
#include "winx/text.hpp"

namespace winx::build {
namespace {

std::string scalar(const YAML::Node& node, const char* key) {
    const YAML::Node value = node[key];
    if (!value) return {};
    if (!value.IsScalar()) throw ProjectError(std::format("xtool.yml: '{}' must be a string", key));
    return value.as<std::string>();
}

std::vector<std::string> string_list(const YAML::Node& node, const char* key) {
    const YAML::Node value = node[key];
    std::vector<std::string> list;
    if (!value) return list;
    if (!value.IsSequence()) throw ProjectError(std::format("xtool.yml: '{}' must be a list", key));
    for (const YAML::Node& item : value) list.push_back(item.as<std::string>());
    return list;
}

std::string bundle_safe(std::string_view text) {
    std::string out;
    for (const char c : text) {
        const bool allowed = std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '.';
        out += allowed ? c : '-';
    }
    return out;
}

}  // namespace

ProjectConfig ProjectConfig::parse(std::string_view yaml) {
    YAML::Node root;
    try {
        root = YAML::Load(std::string(yaml));
    } catch (const YAML::Exception& error) {
        throw ProjectError(std::string("xtool.yml is not valid YAML: ") + error.what());
    }
    if (!root.IsMap()) throw ProjectError("xtool.yml must be a mapping");

    ProjectConfig config;
    try {
        if (!root["version"]) throw ProjectError("xtool.yml: 'version' is required");
        config.version = root["version"].as<int>();
        if (config.version != 1) {
            throw ProjectError(std::format("xtool.yml: unsupported version {}", config.version));
        }
        config.org_id = scalar(root, "orgID");
        config.bundle_id = scalar(root, "bundleID");
        config.product = scalar(root, "product");
        config.info_path = scalar(root, "infoPath");
        config.entitlements_path = scalar(root, "entitlementsPath");
        config.icon_path = scalar(root, "iconPath");
        config.resources = string_list(root, "resources");
        if (const YAML::Node extensions = root["extensions"]) {
            if (!extensions.IsSequence()) throw ProjectError("xtool.yml: 'extensions' must be a list");
            for (const YAML::Node& node : extensions) {
                ExtensionConfig extension;
                extension.product = scalar(node, "product");
                extension.bundle_id = scalar(node, "bundleID");
                extension.info_path = scalar(node, "infoPath");
                extension.entitlements_path = scalar(node, "entitlementsPath");
                extension.resources = string_list(node, "resources");
                if (extension.product.empty() || extension.info_path.empty()) {
                    throw ProjectError("xtool.yml: an extension needs 'product' and 'infoPath'");
                }
                config.extensions.push_back(std::move(extension));
            }
        }
    } catch (const YAML::Exception& error) {
        throw ProjectError(std::string("xtool.yml: ") + error.what());
    }

    if (config.bundle_id.empty() && config.org_id.empty()) {
        throw ProjectError("xtool.yml: set either 'bundleID' or 'orgID'");
    }
    if (!config.icon_path.empty() && !config.icon_path.ends_with(".png")) {
        throw ProjectError("xtool.yml: 'iconPath' must point to a .png file");
    }
    return config;
}

ProjectConfig ProjectConfig::load(const std::filesystem::path& project_dir) {
    const auto text = read_text_file(project_dir / L"xtool.yml");
    if (!text) {
        throw ProjectError("no xtool.yml in " + to_utf8(project_dir.wstring()) +
                           "; run `winx new` to create a project");
    }
    return parse(*text);
}

std::string ProjectConfig::to_yaml() const {
    YAML::Emitter out;
    out << YAML::BeginMap;
    out << YAML::Key << "version" << YAML::Value << version;
    const auto put = [&](const char* key, const std::string& value) {
        if (!value.empty()) out << YAML::Key << key << YAML::Value << value;
    };
    const auto put_list = [&](const char* key, const std::vector<std::string>& values) {
        if (values.empty()) return;
        out << YAML::Key << key << YAML::Value << YAML::BeginSeq;
        for (const std::string& value : values) out << value;
        out << YAML::EndSeq;
    };
    put("orgID", org_id);
    put("bundleID", bundle_id);
    put("product", product);
    put("infoPath", info_path);
    put("entitlementsPath", entitlements_path);
    put("iconPath", icon_path);
    put_list("resources", resources);
    if (!extensions.empty()) {
        out << YAML::Key << "extensions" << YAML::Value << YAML::BeginSeq;
        for (const ExtensionConfig& extension : extensions) {
            out << YAML::BeginMap;
            put("product", extension.product);
            put("bundleID", extension.bundle_id);
            put("infoPath", extension.info_path);
            put("entitlementsPath", extension.entitlements_path);
            put_list("resources", extension.resources);
            out << YAML::EndMap;
        }
        out << YAML::EndSeq;
    }
    out << YAML::EndMap;
    return std::string(out.c_str()) + "\n";
}

void ProjectConfig::save(const std::filesystem::path& project_dir) const {
    write_text_file(project_dir / L"xtool.yml", to_yaml());
}

std::string ProjectConfig::bundle_id_for(std::string_view product_name) const {
    if (!bundle_id.empty()) return bundle_id;
    return org_id + "." + bundle_safe(product_name);
}

PackageInfo parse_package_dump(std::string_view json_text) {
    using nlohmann::json;
    const json dump = json::parse(json_text, nullptr, false);
    if (!dump.is_object()) throw ProjectError("`swift package dump-package` produced no JSON");
    PackageInfo info;
    info.name = dump.value("name", std::string{});
    if (dump.contains("products") && dump["products"].is_array()) {
        for (const json& product : dump["products"]) {
            if (!product.is_object() || !product.contains("type") || !product["type"].is_object()) {
                continue;
            }
            if (product["type"].contains("library")) {
                info.library_products.push_back(product.value("name", std::string{}));
            }
        }
    }
    if (dump.contains("platforms") && dump["platforms"].is_array()) {
        for (const json& platform : dump["platforms"]) {
            if (platform.is_object() && platform.value("platformName", std::string{}) == "ios") {
                info.ios_deployment_target = platform.value("version", std::string{});
            }
        }
    }
    return info;
}

std::string select_product(const ProjectConfig& config, const PackageInfo& package) {
    const auto& products = package.library_products;
    if (!config.product.empty()) {
        if (std::find(products.begin(), products.end(), config.product) == products.end()) {
            throw ProjectError(std::format(
                "xtool.yml names product '{}', but the package has no library product by that name",
                config.product));
        }
        return config.product;
    }
    if (products.empty()) {
        throw ProjectError("the package has no library product; the app must be a .library product");
    }
    if (products.size() > 1) {
        throw ProjectError("the package has several library products; choose one with 'product' in "
                           "xtool.yml");
    }
    return products.front();
}

bool is_valid_project_name(std::string_view name) {
    if (name.empty() || name.size() > 64) return false;
    if (!std::isalpha(static_cast<unsigned char>(name.front()))) return false;
    return std::all_of(name.begin(), name.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
    });
}

void create_project(const std::filesystem::path& directory, std::string_view name,
                    std::string_view org_id) {
    if (!is_valid_project_name(name)) {
        throw ProjectError("the project name must start with a letter and contain only letters, "
                           "digits and underscores");
    }
    if (std::filesystem::exists(directory)) {
        throw ProjectError(to_utf8(directory.wstring()) + " already exists");
    }
    const std::string n(name);

    write_text_file(directory / L"Package.swift", std::format(
        "// swift-tools-version: 6.0\n"
        "\n"
        "import PackageDescription\n"
        "\n"
        "let package = Package(\n"
        "    name: \"{0}\",\n"
        "    platforms: [\n"
        "        .iOS(.v17),\n"
        "        .macOS(.v14),\n"
        "    ],\n"
        "    products: [\n"
        "        // The project must contain exactly one library product: the app itself.\n"
        "        .library(\n"
        "            name: \"{0}\",\n"
        "            targets: [\"{0}\"]\n"
        "        ),\n"
        "    ],\n"
        "    targets: [\n"
        "        .target(\n"
        "            name: \"{0}\"\n"
        "        ),\n"
        "    ]\n"
        ")\n",
        n));

    const std::filesystem::path sources = directory / L"Sources" / to_wide(n);
    write_text_file(sources / to_wide(n + "App.swift"), std::format(
        "import SwiftUI\n"
        "\n"
        "@main\n"
        "struct {0}App: App {{\n"
        "    var body: some Scene {{\n"
        "        WindowGroup {{\n"
        "            ContentView()\n"
        "        }}\n"
        "    }}\n"
        "}}\n",
        n));
    write_text_file(sources / L"ContentView.swift",
        "import SwiftUI\n"
        "\n"
        "struct ContentView: View {\n"
        "    var body: some View {\n"
        "        VStack {\n"
        "            Image(systemName: \"globe\")\n"
        "                .imageScale(.large)\n"
        "                .foregroundStyle(.tint)\n"
        "            Text(\"Hello, world!\")\n"
        "        }\n"
        "        .padding()\n"
        "    }\n"
        "}\n");

    ProjectConfig config;
    config.bundle_id = std::string(org_id) + "." + n;
    config.save(directory);
    write_text_file(directory / L".gitignore", ".build/\n.swiftpm/\n*.app/\n");
}

}  // namespace winx::build
