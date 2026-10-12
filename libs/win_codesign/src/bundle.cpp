#include "winx/codesign.hpp"

#include <algorithm>
#include <format>
#include <map>

#include "winx/files.hpp"
#include "winx/text.hpp"

namespace winx::codesign {
namespace {

namespace fs = std::filesystem;

constexpr const wchar_t* kSignatureDirectory = L"_CodeSignature";
constexpr const wchar_t* kResourcesFile = L"CodeResources";

Bytes read_required(const fs::path& path) {
    auto bytes = read_file(path);
    if (!bytes) throw SignError("missing file: " + to_utf8(path.wstring()));
    return std::move(*bytes);
}

// Bundle-relative path with forward slashes, as CodeResources spells them.
std::string relative_key(const fs::path& bundle, const fs::path& file) {
    std::string key = to_utf8(fs::relative(file, bundle).generic_wstring());
    return key;
}

bool in_lproj(std::string_view key) {
    const auto slash = key.find('/');
    return key.find(".lproj/") != std::string_view::npos && slash != std::string_view::npos;
}

struct SealedFile {
    std::string key;
    fs::path path;
};

// Every regular file the seal covers, sorted by key. The main executable and
// the signature directory itself are never sealed.
std::vector<SealedFile> sealed_files(const fs::path& bundle, const std::string& executable) {
    std::vector<SealedFile> files;
    for (const auto& entry : fs::recursive_directory_iterator(bundle)) {
        if (!entry.is_regular_file()) continue;
        std::string key = relative_key(bundle, entry.path());
        if (key == executable) continue;
        if (key.starts_with("_CodeSignature/")) continue;
        files.push_back({std::move(key), entry.path()});
    }
    std::sort(files.begin(), files.end(),
              [](const SealedFile& a, const SealedFile& b) { return a.key < b.key; });
    return files;
}

bool omitted_from_v1(std::string_view key) { return key.ends_with(".lproj/locversion.plist"); }

bool omitted_from_v2(std::string_view key) {
    if (key == "Info.plist" || key == "PkgInfo") return true;
    if (key == ".DS_Store" || key.ends_with("/.DS_Store")) return true;
    return omitted_from_v1(key);
}

plist::Dict rule(std::initializer_list<plist::Dict::Item> items) { return plist::Dict(items); }

plist::Dict rules_v1() {
    return {{"^.*", true},
            {"^.*\\.lproj/", rule({{"optional", true}, {"weight", 1000.0}})},
            {"^.*\\.lproj/locversion.plist$", rule({{"omit", true}, {"weight", 1100.0}})},
            {"^Base\\.lproj/", rule({{"weight", 1010.0}})},
            {"^version.plist$", true}};
}

plist::Dict rules_v2() {
    return {{".*\\.dSYM($|/)", rule({{"weight", 11.0}})},
            {"^(.*/)?\\.DS_Store$", rule({{"omit", true}, {"weight", 2000.0}})},
            {"^.*", true},
            {"^.*\\.lproj/", rule({{"optional", true}, {"weight", 1000.0}})},
            {"^.*\\.lproj/locversion.plist$", rule({{"omit", true}, {"weight", 1100.0}})},
            {"^Base\\.lproj/", rule({{"weight", 1010.0}})},
            {"^Info\\.plist$", rule({{"omit", true}, {"weight", 20.0}})},
            {"^PkgInfo$", rule({{"omit", true}, {"weight", 20.0}})},
            {"^embedded\\.provisionprofile$", rule({{"weight", 20.0}})},
            {"^version\\.plist$", rule({{"weight", 20.0}})}};
}

bool has_extension(const fs::path& path, std::wstring_view extension) {
    std::wstring actual = path.extension().wstring();
    std::transform(actual.begin(), actual.end(), actual.begin(), ::towlower);
    return actual == extension;
}

// Entitlements for an app extension: the host app's, re-targeted at the
// extension's own bundle identifier.
plist::Value entitlements_for_nested(const plist::Value& host, const std::string& identifier) {
    plist::Dict result;
    for (const auto& [key, value] : host.as_dict().items()) {
        if (key == "application-identifier" && value.is<std::string>()) {
            const std::string& app_id = value.as_string();
            const auto dot = app_id.find('.');
            const std::string prefix = dot == std::string::npos ? app_id : app_id.substr(0, dot);
            result.set(key, prefix + "." + identifier);
        } else {
            result.set(key, value);
        }
    }
    return result;
}

void say(const BundleSignOptions& options, const std::string& message) {
    if (options.log) options.log(message);
}

void sign_file_in_place(const fs::path& path, const MachOSignOptions& options,
                        const SigningCredentials& credentials) {
    const Bytes original = read_required(path);
    write_file(path, sign_macho(original, options, credentials));
}

}  // namespace

BundleInfo read_bundle_info(const fs::path& bundle) {
    BundleInfo info;
    info.info_plist = read_required(bundle / L"Info.plist");
    plist::Value plist;
    try {
        plist = plist::parse(info.info_plist);
    } catch (const plist::ParseError& error) {
        throw SignError(std::string("Info.plist is malformed: ") + error.what());
    }
    info.identifier = plist.string_at("CFBundleIdentifier").value_or("");
    info.executable = plist.string_at("CFBundleExecutable").value_or("");
    if (info.identifier.empty() || info.executable.empty()) {
        throw SignError("Info.plist must define CFBundleIdentifier and CFBundleExecutable");
    }
    return info;
}

Bytes build_code_resources(const fs::path& bundle, const std::string& executable) {
    plist::Dict files;
    plist::Dict files2;
    for (const SealedFile& file : sealed_files(bundle, executable)) {
        const Bytes content = read_required(file.path);
        const bool optional = in_lproj(file.key);
        if (!omitted_from_v1(file.key)) {
            if (optional) {
                files.set(file.key, plist::Dict{{"hash", plist::Data{crypto::sha1(content)}},
                                                {"optional", true}});
            } else {
                files.set(file.key, plist::Data{crypto::sha1(content)});
            }
        }
        if (!omitted_from_v2(file.key)) {
            plist::Dict entry{{"hash", plist::Data{crypto::sha1(content)}},
                              {"hash2", plist::Data{crypto::sha256(content)}}};
            if (optional) entry.set("optional", true);
            files2.set(file.key, std::move(entry));
        }
    }
    const plist::Value resources = plist::Dict{{"files", std::move(files)},
                                               {"files2", std::move(files2)},
                                               {"rules", rules_v1()},
                                               {"rules2", rules_v2()}};
    const std::string xml = plist::to_xml(resources);
    return Bytes(xml.begin(), xml.end());
}

void sign_bundle(const fs::path& bundle, const SigningCredentials& credentials,
                 const BundleSignOptions& options) {
    const BundleInfo info = read_bundle_info(bundle);
    const fs::path executable = bundle / to_wide(info.executable);
    if (!fs::is_regular_file(executable)) {
        throw SignError("the bundle executable is missing: " + info.executable);
    }

    // Nested code is signed first so that the hashes sealed below are final.
    for (const wchar_t* directory : {L"Frameworks", L"PlugIns", L"Extensions"}) {
        const fs::path nested_root = bundle / directory;
        if (!fs::is_directory(nested_root)) continue;
        std::vector<fs::path> entries;
        for (const auto& entry : fs::directory_iterator(nested_root)) entries.push_back(entry.path());
        std::sort(entries.begin(), entries.end());
        for (const fs::path& entry : entries) {
            if (fs::is_directory(entry) &&
                (has_extension(entry, L".framework") || has_extension(entry, L".appex"))) {
                BundleSignOptions nested;
                nested.log = options.log;
                if (has_extension(entry, L".appex")) {
                    nested.provisioning_profile = options.provisioning_profile;
                    if (options.entitlements) {
                        nested.entitlements = entitlements_for_nested(
                            *options.entitlements, read_bundle_info(entry).identifier);
                    }
                }
                sign_bundle(entry, credentials, nested);
            } else if (fs::is_regular_file(entry)) {
                const Bytes content = read_required(entry);
                if (!is_macho(content)) continue;
                say(options, "Signing " + relative_key(bundle, entry));
                MachOSignOptions library;
                library.identifier = to_utf8(entry.stem().wstring());
                write_file(entry, sign_macho(content, library, credentials));
            }
        }
    }

    if (!options.provisioning_profile.empty()) {
        write_file(bundle / L"embedded.mobileprovision", options.provisioning_profile);
    }

    const Bytes resources = build_code_resources(bundle, info.executable);
    write_file(bundle / kSignatureDirectory / kResourcesFile, resources);

    say(options, "Signing " + to_utf8(bundle.filename().wstring()) + " (" + info.identifier + ")");
    MachOSignOptions main;
    main.identifier = info.identifier;
    main.info_plist = info.info_plist;
    main.code_resources = resources;
    main.entitlements = options.entitlements;
    sign_file_in_place(executable, main, credentials);
}

std::vector<std::string> verify_bundle(const fs::path& bundle) {
    std::vector<std::string> problems;
    BundleInfo info;
    try {
        info = read_bundle_info(bundle);
    } catch (const SignError& error) {
        return {error.what()};
    }
    const std::string name = to_utf8(bundle.filename().wstring());
    const auto add = [&](const std::string& problem) { problems.push_back(name + ": " + problem); };

    // Nested bundles and libraries.
    for (const wchar_t* directory : {L"Frameworks", L"PlugIns", L"Extensions"}) {
        const fs::path nested_root = bundle / directory;
        if (!fs::is_directory(nested_root)) continue;
        for (const auto& entry : fs::directory_iterator(nested_root)) {
            if (entry.is_directory() && (has_extension(entry.path(), L".framework") ||
                                         has_extension(entry.path(), L".appex"))) {
                for (std::string& problem : verify_bundle(entry.path())) {
                    problems.push_back(std::move(problem));
                }
            } else if (entry.is_regular_file()) {
                const auto content = read_file(entry.path());
                if (!content || !is_macho(*content)) continue;
                for (const std::string& problem : verify_macho(*content)) {
                    add(relative_key(bundle, entry.path()) + ": " + problem);
                }
            }
        }
    }

    const auto executable = read_file(bundle / to_wide(info.executable));
    if (!executable) {
        add("the executable is missing");
        return problems;
    }
    for (const std::string& problem : verify_macho(*executable)) add(problem);

    const auto resources = read_file(bundle / kSignatureDirectory / kResourcesFile);
    if (!resources) {
        add("_CodeSignature/CodeResources is missing");
        return problems;
    }

    // The executable's signature must seal this Info.plist and CodeResources.
    try {
        const ByteView image(*executable);
        const ByteView thin = is_fat_macho(image)
                                  ? image.subspan(parse_fat(image).front().offset,
                                                  parse_fat(image).front().size)
                                  : image;
        if (const auto signature = read_signature(thin)) {
            for (const CodeDirectoryInfo& directory : signature->code_directories) {
                const auto sealed = [&](std::uint32_t slot, const Bytes& content) {
                    return directory.special_hashes.size() >= slot &&
                           directory.special_hashes[slot - 1] ==
                               crypto::digest(directory.algorithm(), content);
                };
                if (!sealed(kSlotInfoPlist, info.info_plist)) {
                    add("Info.plist does not match the hash in the signature");
                }
                if (!sealed(kSlotResourceDirectory, *resources)) {
                    add("CodeResources does not match the hash in the signature");
                }
                if (directory.identifier != info.identifier) {
                    add("the signing identifier differs from CFBundleIdentifier");
                }
            }
        }
    } catch (const MachOError& error) {
        add(error.what());
    }

    // Every sealed file must exist with the recorded hash, and nothing may be unsealed.
    plist::Value seal;
    try {
        seal = plist::parse(*resources);
    } catch (const plist::ParseError&) {
        add("CodeResources is malformed");
        return problems;
    }
    const plist::Value* files2 = seal.find("files2");
    if (!files2 || !files2->is<plist::Dict>()) {
        add("CodeResources has no files2 dictionary");
        return problems;
    }
    std::map<std::string, bool> seen;
    for (const auto& [key, entry] : files2->as_dict().items()) seen[key] = false;
    for (const SealedFile& file : sealed_files(bundle, info.executable)) {
        if (omitted_from_v2(file.key)) continue;
        const plist::Value* entry = files2->find(file.key);
        if (!entry) {
            add("unsealed file: " + file.key);
            continue;
        }
        seen[file.key] = true;
        const plist::Data* hash2 = entry->data_at("hash2");
        const auto content = read_file(file.path);
        if (!hash2 || !content || hash2->bytes != crypto::sha256(*content)) {
            add("modified file: " + file.key);
        }
    }
    for (const auto& [key, found] : seen) {
        if (!found) add("sealed file is missing: " + key);
    }
    return problems;
}

}  // namespace winx::codesign
