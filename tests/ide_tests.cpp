#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "support.hpp"
#include "swift_language.hpp"
#include "winx/files.hpp"
#include "winx/project.hpp"
#include "winx/sdk.hpp"
#include "winx/text.hpp"
#include "workspace.hpp"

using namespace winx;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

class ScopedEnv {
public:
    ScopedEnv(const char* name, const std::string& value) : name_(name) {
        _putenv_s(name, value.c_str());
    }
    ~ScopedEnv() { _putenv_s(name_.c_str(), ""); }

private:
    std::string name_;
};

// Runs a tokenizer function over `text` and returns how many characters it consumed.
template <class Tokenizer>
std::size_t consumed(Tokenizer tokenizer, std::string_view text) {
    std::vector<TextEditor::Glyph> glyphs;
    for (const char c : text) glyphs.emplace_back(static_cast<ImWchar>(static_cast<unsigned char>(c)));
    glyphs.emplace_back(ImWchar{0});  // keeps data() valid for empty input
    const TextEditor::Iterator start(glyphs.data());
    const TextEditor::Iterator end(glyphs.data() + text.size());
    return tokenizer(start, end) - start;
}

// Polls until the run finishes or the time limit passes.
bool wait_until_idle(ide::Workspace& workspace) {
    for (int i = 0; i < 400; ++i) {
        workspace.poll();
        if (!workspace.running()) return true;
        std::this_thread::sleep_for(50ms);
    }
    return false;
}

}  // namespace

TEST_CASE("Swift identifiers and numbers are tokenized", "[ide][swift]") {
    using ide::swift_identifier;
    using ide::swift_number;
    CHECK(consumed(swift_identifier, "contentView.body") == 11);
    CHECK(consumed(swift_identifier, "_private2 = 1") == 9);
    CHECK(consumed(swift_identifier, "$0 + 1") == 2);
    CHECK(consumed(swift_identifier, "9lives") == 0);
    CHECK(consumed(swift_identifier, "") == 0);

    CHECK(consumed(swift_number, "42") == 2);
    CHECK(consumed(swift_number, "1_000_000 ") == 9);
    CHECK(consumed(swift_number, "3.14)") == 4);
    CHECK(consumed(swift_number, "1.5e-3,") == 6);
    CHECK(consumed(swift_number, "0xFF_AA]") == 7);
    CHECK(consumed(swift_number, "0b1010 ") == 6);
    CHECK(consumed(swift_number, "0x1.8p3 ") == 7);
    // The dot belongs to what follows, not to the number.
    CHECK(consumed(swift_number, "0..<5") == 1);
    CHECK(consumed(swift_number, "1.description") == 1);
    CHECK(consumed(swift_number, "2e") == 1);
    CHECK(consumed(swift_number, "x1") == 0);

    CHECK(ide::swift_punctuation('{'));
    CHECK(ide::swift_punctuation('@'));
    CHECK_FALSE(ide::swift_punctuation('a'));
    CHECK_FALSE(ide::swift_punctuation('_'));

    const TextEditor::Language* swift = ide::swift_language();
    REQUIRE(swift != nullptr);
    CHECK(swift->name == "Swift");
    CHECK(swift->keywords.contains("guard"));
    CHECK(swift->declarations.contains("struct"));
    CHECK(swift->identifiers.contains("VStack"));
    CHECK(swift->singleLineComment == "//");
    CHECK(ide::swift_language() == swift);  // one shared definition
}

TEST_CASE("the navigator tree hides build output and sorts folders first", "[ide]") {
    const test::TempDir dir("winx_tree");
    const fs::path root = dir.path() / "Hello";
    build::create_project(root, "Hello");
    write_text_file(root / ".build" / "debug" / "junk.o", "x");
    write_text_file(root / ".git" / "HEAD", "x");
    write_text_file(root / "Hello.app" / "Info.plist", "x");
    write_text_file(root / "Resources" / "b.txt", "x");
    write_text_file(root / "Resources" / "A.txt", "x");
    write_text_file(root / "zeta.txt", "x");

    const ide::FileNode tree = ide::scan_project(root);
    CHECK(tree.name == "Hello");
    CHECK(tree.directory);
    std::vector<std::string> names;
    for (const ide::FileNode& child : tree.children) names.push_back(child.name);
    CHECK(names == std::vector<std::string>{"Resources", "Sources", ".gitignore", "Package.swift",
                                            "xtool.yml", "zeta.txt"});
    const ide::FileNode& resources = tree.children[0];
    REQUIRE(resources.children.size() == 2);
    CHECK(resources.children[0].name == "A.txt");  // case-insensitive order
    CHECK(resources.children[1].name == "b.txt");
    const ide::FileNode& sources = tree.children[1];
    REQUIRE(sources.children.size() == 1);
    CHECK(sources.children[0].children.size() == 2);
}

TEST_CASE("the workspace builds in the background and reports back", "[ide]") {
    const test::TempDir dir("winx_workspace");
    const fs::path project = dir.path() / "Hello";
    build::create_project(project, "Hello");

    // Point every per-user location and the toolchain at test stand-ins.
    const fs::path home = dir.path() / "home";
    const fs::path bundle = home / "sdk" / build::kSdkBundleName;
    fs::create_directories(bundle / "Developer" / "Platforms" / "iPhoneOS.platform" / "Developer" /
                           "SDKs" / "iPhoneOS18.2.sdk");
    write_text_file(bundle / "swift-sdk.json", build::make_swift_sdk_json("iPhoneOS18.2.sdk").dump());
    const nlohmann::json dump = {
        {"name", "Hello"},
        {"platforms", nlohmann::json::array({{{"platformName", "ios"}, {"version", "17.0"}}})},
        {"products",
         nlohmann::json::array({{{"name", "Hello"},
                                 {"type", {{"library", nlohmann::json::array({"automatic"})}}}}})}};
    write_text_file(dir.path() / "dump.json", dump.dump());
    write_file(dir.path() / "product.bin", test::simple_macho());

    const ScopedEnv env_home("WINX_HOME", to_utf8(home.wstring()));
    const ScopedEnv env_swift("WINX_SWIFT", WINX_FAKE_SWIFT_PATH);
    const ScopedEnv env_dump("WINX_FAKE_SWIFT_DUMP", to_utf8((dir.path() / "dump.json").wstring()));
    const ScopedEnv env_product("WINX_FAKE_SWIFT_PRODUCT",
                                to_utf8((dir.path() / "product.bin").wstring()));

    ide::Workspace workspace;
    CHECK_FALSE(workspace.has_project());
    CHECK(workspace.open_project(dir.path() / "missing") == "The folder does not exist.");
    CHECK_FALSE(workspace.open_project(dir.path()).empty());  // no Package.swift
    REQUIRE(workspace.open_project(project).empty());
    CHECK(workspace.scheme() == "Hello");
    CHECK(workspace.config().bundle_id == "com.example.Hello");
    CHECK(workspace.tree().children.size() == 4);

    SECTION("a successful build") {
        workspace.start(ide::RunMode::Build);
        CHECK(workspace.running());
        REQUIRE(wait_until_idle(workspace));
        INFO(workspace.last_result());
        CHECK(workspace.last_succeeded());
        CHECK(workspace.diagnostics().empty());
        const auto& log = workspace.build_log();
        const auto has = [&](ide::ConsoleLine::Kind kind, std::string_view text) {
            return std::any_of(log.begin(), log.end(), [&](const ide::ConsoleLine& line) {
                return line.kind == kind && line.text.find(text) != std::string::npos;
            });
        };
        CHECK(has(ide::ConsoleLine::Kind::Stage, "Building"));
        CHECK(has(ide::ConsoleLine::Kind::Stage, "Packaging"));
        CHECK(has(ide::ConsoleLine::Kind::Plain, "Build complete!"));
        CHECK(has(ide::ConsoleLine::Kind::Success, "com.example.Hello"));
        CHECK(fs::exists(project / ".build" / "winx" / "products" / "Hello.app" / "Info.plist"));
    }
    SECTION("a failed build fills the issue list") {
        const ScopedEnv fail("WINX_FAKE_SWIFT_FAIL", "1");
        workspace.start(ide::RunMode::Build);
        REQUIRE(wait_until_idle(workspace));
        CHECK_FALSE(workspace.last_succeeded());
        CHECK(workspace.last_result() == "Failed");
        REQUIRE(workspace.diagnostics().size() == 2);
        CHECK(workspace.diagnostics()[0].line == 7);
        CHECK(std::any_of(workspace.build_log().begin(), workspace.build_log().end(),
                          [](const ide::ConsoleLine& line) {
                              return line.kind == ide::ConsoleLine::Kind::Error &&
                                     line.text.find("cannot find 'Texty'") != std::string::npos;
                          }));
    }
    SECTION("Run without a device explains itself instead of starting") {
        if (workspace.devices().empty()) {
            workspace.start(ide::RunMode::Run);
            CHECK_FALSE(workspace.running());
            CHECK(workspace.last_result() == "No device");
            REQUIRE_FALSE(workspace.build_log().empty());
            CHECK(workspace.build_log().back().kind == ide::ConsoleLine::Kind::Error);
        }
    }
    SECTION("settings edited in the inspector are written to xtool.yml") {
        workspace.config().bundle_id = "org.sample.Renamed";
        CHECK(workspace.save_config().empty());
        CHECK(build::ProjectConfig::load(project).bundle_id == "org.sample.Renamed");
    }
    SECTION("new files appear in the navigator without reopening") {
        write_text_file(project / "Notes.md", "hello");
        bool seen = false;
        for (int i = 0; i < 100 && !seen; ++i) {
            workspace.poll();
            const auto& children = workspace.tree().children;
            seen = std::any_of(children.begin(), children.end(),
                               [](const ide::FileNode& node) { return node.name == "Notes.md"; });
            if (!seen) std::this_thread::sleep_for(50ms);
        }
        CHECK(seen);
    }
}
