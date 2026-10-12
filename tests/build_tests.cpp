#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include <lzma.h>
#include <miniz.h>
#include <nlohmann/json.hpp>

#include "fake_device.hpp"
#include "support.hpp"
#include "winx/archive.hpp"
#include "winx/bundler.hpp"
#include "winx/codesign.hpp"
#include "winx/device_services.hpp"
#include "winx/files.hpp"
#include "winx/identity.hpp"
#include "winx/pipeline.hpp"
#include "winx/plist.hpp"
#include "winx/process.hpp"
#include "winx/project.hpp"
#include "winx/sdk.hpp"
#include "winx/swiftpm.hpp"
#include "winx/text.hpp"

using namespace winx;
using namespace std::chrono_literals;
using build::Bytes;
using nlohmann::json;
namespace fs = std::filesystem;

namespace {

const fs::path kFakeSwift = WINX_FAKE_SWIFT_PATH;

// Sets an environment variable for the lifetime of the object.
class ScopedEnv {
public:
    ScopedEnv(const char* name, const std::string& value) : name_(name) {
        _putenv_s(name, value.c_str());
    }
    ~ScopedEnv() { _putenv_s(name_.c_str(), ""); }
    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;

private:
    std::string name_;
};

Bytes bytes_of(std::string_view text) { return Bytes(text.begin(), text.end()); }

void append(Bytes& out, std::string_view text) { out.insert(out.end(), text.begin(), text.end()); }

void append_be(Bytes& out, std::uint64_t value, int size) {
    for (int i = size - 1; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

// One "odc" cpio entry.
void cpio_entry(Bytes& out, const std::string& name, unsigned mode, const Bytes& data = {}) {
    char header[77];
    std::snprintf(header, sizeof(header), "070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011llo", 0u,
                  0u, mode, 0u, 0u, 1u, 0u, 0u, static_cast<unsigned>(name.size() + 1),
                  static_cast<unsigned long long>(data.size()));
    append(out, std::string_view(header, 76));
    append(out, name);
    out.push_back(0);
    out.insert(out.end(), data.begin(), data.end());
}

constexpr unsigned kFile = 0100644;
constexpr unsigned kDir = 0040755;
constexpr unsigned kLink = 0120777;

Bytes xz_compress(const Bytes& input) {
    Bytes out(input.size() + 1024);
    std::size_t position = 0;
    REQUIRE(lzma_easy_buffer_encode(6, LZMA_CHECK_CRC64, nullptr, input.data(), input.size(),
                                    out.data(), &position, out.size()) == LZMA_OK);
    out.resize(position);
    return out;
}

// Wraps a byte stream as pbzx: the first part stored raw, the rest as xz.
Bytes pbzx_wrap(const Bytes& stream, std::size_t split) {
    const Bytes first(stream.begin(), stream.begin() + static_cast<std::ptrdiff_t>(split));
    const Bytes second(stream.begin() + static_cast<std::ptrdiff_t>(split), stream.end());
    const Bytes compressed = xz_compress(second);
    Bytes out = bytes_of("pbzx");
    append_be(out, 0x1000000, 8);       // chunks follow
    append_be(out, 0x1000000, 8);       // not the last chunk
    append_be(out, first.size(), 8);
    out.insert(out.end(), first.begin(), first.end());
    append_be(out, second.size(), 8);   // last chunk: bit 24 clear
    append_be(out, compressed.size(), 8);
    out.insert(out.end(), compressed.begin(), compressed.end());
    return out;
}

// A minimal xar file with "Content" and "Metadata" members.
void write_xip(const fs::path& path, const Bytes& content) {
    const std::string toc = std::format(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><xar><toc>"
        "<file id=\"1\"><data><length>{0}</length><offset>0</offset><size>{0}</size>"
        "<encoding style=\"application/octet-stream\"/></data><name>Content</name></file>"
        "<file id=\"2\"><data><length>3</length><offset>{0}</offset><size>3</size>"
        "<encoding style=\"application/octet-stream\"/></data><name>Metadata</name></file>"
        "</toc></xar>",
        content.size());
    Bytes compressed(mz_compressBound(static_cast<mz_ulong>(toc.size())));
    mz_ulong compressed_size = static_cast<mz_ulong>(compressed.size());
    REQUIRE(mz_compress(compressed.data(), &compressed_size,
                        reinterpret_cast<const unsigned char*>(toc.data()),
                        static_cast<mz_ulong>(toc.size())) == MZ_OK);
    compressed.resize(compressed_size);

    Bytes out = bytes_of("xar!");
    append_be(out, 28, 2);
    append_be(out, 1, 2);
    append_be(out, compressed.size(), 8);
    append_be(out, toc.size(), 8);
    append_be(out, 1, 4);
    out.insert(out.end(), compressed.begin(), compressed.end());
    out.insert(out.end(), content.begin(), content.end());
    append(out, "end");
    write_file(path, out);
}

const std::string kDeveloper = "./Xcode.app/Contents/Developer/";
const std::string kSdk = kDeveloper + "Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS18.2.sdk/";
const std::string kToolchain = kDeveloper + "Toolchains/XcodeDefault.xctoolchain/usr/";

json package_dump(const std::string& name = "Hello") {
    return {{"name", name},
            {"platforms", json::array({{{"platformName", "ios"}, {"version", "17.0"}},
                                       {{"platformName", "macos"}, {"version", "14.0"}}})},
            {"products",
             json::array({{{"name", name}, {"type", {{"library", json::array({"automatic"})}}}},
                          {{"name", "tool"}, {"type", {{"executable", nullptr}}}}})}};
}

// A directory that find_installed_sdk accepts, without any real SDK content.
void write_stub_sdk(const fs::path& sdk_dir) {
    const fs::path bundle = sdk_dir / build::kSdkBundleName;
    fs::create_directories(bundle / "Developer" / "Platforms" / "iPhoneOS.platform" / "Developer" /
                           "SDKs" / "iPhoneOS18.2.sdk");
    write_text_file(bundle / "swift-sdk.json", build::make_swift_sdk_json("iPhoneOS18.2.sdk").dump());
}

}  // namespace

TEST_CASE("binary plists round-trip through the writer and reader", "[plist][binary]") {
    plist::Array many;
    for (int i = 0; i < 300; ++i) many.emplace_back(i);  // forces two-byte object references
    const plist::Value original = plist::Dict{
        {"CFBundleIdentifier", "com.example.hello"},
        {"UIDeviceFamily", plist::Array{1, 2}},
        {"LSRequiresIPhoneOS", true},
        {"Hidden", false},
        {"Negative", -5},
        {"Big", 5000000000},
        {"Ratio", 0.5},
        {"When", plist::Date{700000000.0}},
        {"Blob", plist::Data{{0, 1, 2, 255}}},
        {"Name", "Zo\xC3\xAB \xF0\x9F\x98\x80"},  // non-ASCII, including a surrogate pair
        {"LongText", std::string(40, 'x')},        // length needs an extended count
        {"Empty", plist::Dict{}},
        {"Many", std::move(many)},
        {"Nested", plist::Dict{{"UILaunchScreen", plist::Dict{}}, {"List", plist::Array{"a", "b"}}}},
    };
    const std::vector<std::uint8_t> binary = plist::to_binary(original);
    CHECK(std::string(binary.begin(), binary.begin() + 8) == "bplist00");
    CHECK(plist::parse_binary(binary) == original);
    CHECK(plist::parse(binary) == original);
    CHECK_THROWS_AS(plist::to_binary(plist::Value{}), std::invalid_argument);
}

TEST_CASE("child processes are run with captured, line-split output", "[process]") {
    const fs::path cmd = process::find_on_path(L"cmd.exe").value();

    std::vector<std::string> lines;
    process::Options options;
    options.on_line = [&](std::string_view line) { lines.emplace_back(line); };
    options.environment = {{"WINX_TEST_VALUE", "from parent"}};
    const process::Result result =
        process::run(cmd, {"/d", "/c", "echo first& echo %WINX_TEST_VALUE%& exit 3"}, options);
    CHECK(result.exit_code == 3);
    CHECK_FALSE(result.ok());
    CHECK_FALSE(result.cancelled);
    REQUIRE(lines.size() == 2);
    CHECK(lines[0] == "first");
    CHECK(lines[1] == "from parent");
    CHECK(result.output.find("from parent") != std::string::npos);

    CHECK_THROWS_AS(process::run("C:\\no\\such\\program.exe", {}), process::ProcessError);
    CHECK_FALSE(process::find_on_path(L"winx-definitely-missing.exe").has_value());

    CHECK(process::quote_argument("plain") == "plain");
    CHECK(process::quote_argument("has space") == "\"has space\"");
    CHECK(process::quote_argument("") == "\"\"");
    CHECK(process::quote_argument("say \"hi\"") == "\"say \\\"hi\\\"\"");
    CHECK(process::quote_argument("C:\\dir with space\\") == "\"C:\\dir with space\\\\\"");
}

TEST_CASE("a running child process tree can be cancelled", "[process]") {
    const fs::path cmd = process::find_on_path(L"cmd.exe").value();
    std::stop_source stop;
    process::Options options;
    options.stop = stop.get_token();
    std::thread canceller([&] {
        std::this_thread::sleep_for(300ms);
        stop.request_stop();
    });
    const auto started = std::chrono::steady_clock::now();
    // ping is a grandchild here, so this also checks that the job kills the tree.
    const process::Result result = process::run(cmd, {"/d", "/c", "ping -n 30 127.0.0.1"}, options);
    canceller.join();
    CHECK(result.cancelled);
    CHECK(std::chrono::steady_clock::now() - started < 10s);
}

TEST_CASE("cpio entries are read through a mixed pbzx stream", "[archive]") {
    Bytes cpio;
    const Bytes large = crypto::random_bytes(200 * 1024);
    cpio_entry(cpio, "./dir", kDir);
    cpio_entry(cpio, "./dir/a.txt", kFile, bytes_of("alpha"));
    cpio_entry(cpio, "./dir/link", kLink, bytes_of("a.txt"));
    cpio_entry(cpio, "./dir/big.bin", kFile, large);
    cpio_entry(cpio, "./dir/skipped.txt", kFile, bytes_of("never read"));
    cpio_entry(cpio, "./dir/z.txt", kFile, bytes_of("omega"));
    cpio_entry(cpio, "TRAILER!!!", 0);

    // Split in the middle of the large file so one entry spans both chunks.
    build::MemorySource memory(pbzx_wrap(cpio, 100 * 1024));
    build::PbzxSource pbzx(memory);
    build::CpioReader reader(pbzx);

    build::ArchiveEntry entry;
    std::vector<std::string> seen;
    Bytes big;
    std::string last;
    while (reader.next(entry)) {
        seen.push_back(entry.path);
        if (entry.path == "dir/big.bin") {
            CHECK(entry.size == large.size());
            reader.read_data([&](build::ByteView chunk) {
                big.insert(big.end(), chunk.begin(), chunk.end());
            });
        } else if (entry.path == "dir/link") {
            CHECK(entry.type == build::ArchiveEntry::Type::Symlink);
            CHECK(entry.link_target == "a.txt");
        } else if (entry.path == "dir/z.txt") {
            reader.read_data([&](build::ByteView chunk) { last.append(chunk.begin(), chunk.end()); });
        } else if (entry.path == "dir") {
            CHECK(entry.type == build::ArchiveEntry::Type::Directory);
        }
        // Everything else is skipped without reading its data.
    }
    CHECK(seen == std::vector<std::string>{"dir", "dir/a.txt", "dir/link", "dir/big.bin",
                                           "dir/skipped.txt", "dir/z.txt"});
    CHECK(big == large);
    CHECK(last == "omega");

    build::MemorySource garbage(bytes_of("not a pbzx stream at all"));
    CHECK_THROWS_AS(build::PbzxSource(garbage), build::ArchiveError);
    build::MemorySource truncated(Bytes(cpio.begin(), cpio.begin() + 100));
    build::CpioReader broken(truncated);
    CHECK(broken.next(entry));
    CHECK_THROWS_AS(broken.next(entry), build::ArchiveError);
}

TEST_CASE("SDK paths are selected and checked for Windows", "[sdk]") {
    std::string relative;
    const std::string developer = "Xcode.app/Contents/Developer/";
    CHECK(build::select_sdk_path(developer + "Platforms/iPhoneOS.platform/Info.plist", relative));
    CHECK(relative == "Developer/Platforms/iPhoneOS.platform/Info.plist");
    CHECK(build::select_sdk_path(
        "Xcode-beta.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/x",
        relative));
    CHECK(build::select_sdk_path(
        developer + "Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/iphoneos/libswiftCore.dylib",
        relative));
    CHECK(build::select_sdk_path(
        developer + "Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/17/lib/darwin/libclang_rt.ios.a",
        relative));

    for (const char* unwanted :
         {"Platforms/MacOSX.platform/Info.plist", "Platforms/iPhoneOS.platform/Developer/usr/bin/x",
          "Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc",
          "Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx/libswiftCore.dylib",
          "Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/iphoneos/prebuilt-modules/x",
          "Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/17/include/stddef.h",
          "Toolchains/XcodeDefault.xctoolchain/usr/lib/sourcekitd.framework/x", "usr/bin/xcodebuild"}) {
        CAPTURE(unwanted);
        CHECK_FALSE(build::select_sdk_path(developer + unwanted, relative));
    }
    CHECK_FALSE(build::select_sdk_path("Other/Contents/Developer/Platforms/iPhoneOS.platform/Info.plist",
                                       relative));

    CHECK(build::windows_path_problem("usr/include/stdio.h").empty());
    CHECK_FALSE(build::windows_path_problem("usr/include/aux.h").empty());
    CHECK_FALSE(build::windows_path_problem("usr/share/man/a:b.3").empty());
    CHECK_FALSE(build::windows_path_problem("usr/trailing./x").empty());
    CHECK_FALSE(build::windows_path_problem("NUL").empty());
    CHECK(build::windows_path_problem("usr/include/auxiliary.h").empty());
}

TEST_CASE("an SDK bundle is built from an Xcode.xip", "[sdk]") {
    const test::TempDir dir("winx_sdk");
    const Bytes uikit = crypto::random_bytes(200 * 1024);

    Bytes cpio;
    cpio_entry(cpio, "./Xcode.app", kDir);
    cpio_entry(cpio, kDeveloper + "Platforms/iPhoneOS.platform/Info.plist", kFile, bytes_of("platform"));
    cpio_entry(cpio, kDeveloper + "Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS18.2.sdk", kDir);
    // The convenience link appears before the directory it points into is populated.
    cpio_entry(cpio, kDeveloper + "Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk", kLink,
               bytes_of("iPhoneOS18.2.sdk"));
    cpio_entry(cpio, kSdk + "SDKSettings.json", kFile, bytes_of("{\"Version\":\"18.2\"}"));
    cpio_entry(cpio, kSdk + "usr/lib/libSystem.tbd", kLink, bytes_of("libSystem.B.tbd"));
    cpio_entry(cpio, kSdk + "usr/lib/libSystem.B.tbd", kFile, bytes_of("tbd contents"));
    // Twelve levels up from a directory eight levels deep leaves the bundle.
    cpio_entry(cpio, kSdk + "usr/lib/escape", kLink,
               bytes_of("../../../../../../../../../../../../outside"));
    cpio_entry(cpio, kSdk + "usr/lib/dangling", kLink, bytes_of("missing.tbd"));
    cpio_entry(cpio, kSdk + "usr/include/aux.h", kFile, bytes_of("reserved name"));
    cpio_entry(cpio, kSdk + "usr/share/man/a:b.3", kFile, bytes_of("colon"));
    cpio_entry(cpio, kSdk + "usr/include/Case.h", kFile, bytes_of("upper"));
    cpio_entry(cpio, kSdk + "usr/include/case.h", kFile, bytes_of("lower"));
    cpio_entry(cpio, kSdk + "System/Library/Frameworks/UIKit.framework/UIKit.tbd", kFile, uikit);
    cpio_entry(cpio, kDeveloper + "Platforms/MacOSX.platform/Info.plist", kFile, bytes_of("mac"));
    cpio_entry(cpio, kToolchain + "lib/swift/iphoneos/libswiftCore.dylib", kFile, bytes_of("core"));
    cpio_entry(cpio, kToolchain + "lib/swift/macosx/libswiftCore.dylib", kFile, bytes_of("mac core"));
    cpio_entry(cpio, kToolchain + "lib/clang/17/include/stddef.h", kFile, bytes_of("header"));
    cpio_entry(cpio, kToolchain + "lib/clang/17/lib/darwin/libclang_rt.ios.a", kFile, bytes_of("rt"));
    cpio_entry(cpio, kToolchain + "bin/swiftc", kFile, bytes_of("compiler"));
    cpio_entry(cpio, "TRAILER!!!", 0);

    const fs::path xip = dir.path() / "Xcode.xip";
    write_xip(xip, pbzx_wrap(cpio, cpio.size() / 2));

    const auto members = build::read_xar_members(xip);
    REQUIRE(members.size() == 2);
    CHECK(members[0].name == "Content");
    CHECK(members[0].encoding == "application/octet-stream");
    CHECK(members[1].name == "Metadata");
    CHECK(members[1].length == 3);

    // A stand-in toolchain directory and linker shim.
    const fs::path toolchain_bin = dir.path() / "toolchain" / "usr" / "bin";
    write_text_file(toolchain_bin / "lld.exe", "real lld");
    write_text_file(toolchain_bin / "llvm-libtool-darwin.exe", "libtool");
    write_text_file(dir.path() / "shim.exe", "shim");

    build::SdkInstallOptions options;
    options.xip = xip;
    options.sdk_dir = dir.path() / "sdk";
    options.toolchain = build::Toolchain{toolchain_bin / "swift.exe", toolchain_bin, "Swift 6.4", 6, 4};
    options.linker_shim = dir.path() / "shim.exe";
    std::vector<std::string> log;
    options.log = [&](const std::string& line) { log.push_back(line); };
    std::uint64_t last_done = 0;
    std::uint64_t last_total = 0;
    options.progress = [&](std::uint64_t done, std::uint64_t total) {
        last_done = done;
        last_total = total;
    };
    const build::SdkInstallReport report = build::install_sdk(options);

    const fs::path bundle = dir.path() / "sdk" / build::kSdkBundleName;
    const fs::path platform = bundle / "Developer" / "Platforms" / "iPhoneOS.platform";
    const fs::path sdk = platform / "Developer" / "SDKs" / "iPhoneOS18.2.sdk";
    const fs::path toolchain_lib = bundle / "Developer" / "Toolchains" / "XcodeDefault.xctoolchain" / "usr" / "lib";
    CHECK(report.sdk.sdk_name == "iPhoneOS18.2.sdk");
    CHECK(report.sdk.version == "18.2");
    CHECK(report.sdk.bundle == bundle);
    CHECK(last_done == last_total);
    CHECK(last_total > 0);
    CHECK_FALSE(log.empty());

    // Wanted content is present and intact.
    CHECK(read_text_file(platform / "Info.plist") == "platform");
    CHECK(read_file(sdk / "System" / "Library" / "Frameworks" / "UIKit.framework" / "UIKit.tbd") == uikit);
    CHECK(read_text_file(toolchain_lib / "swift" / "iphoneos" / "libswiftCore.dylib") == "core");
    CHECK(read_text_file(toolchain_lib / "clang" / "17" / "lib" / "darwin" / "libclang_rt.ios.a") == "rt");
    CHECK(report.files == 7);  // Info.plist, SDKSettings, libSystem.B, Case.h, UIKit, swiftCore, clang_rt

    // Unwanted content is not written at all.
    CHECK_FALSE(fs::exists(bundle / "Developer" / "Platforms" / "MacOSX.platform"));
    CHECK_FALSE(fs::exists(toolchain_lib / "swift" / "macosx"));
    CHECK_FALSE(fs::exists(toolchain_lib / "clang" / "17" / "include"));
    CHECK_FALSE(fs::exists(bundle / "Developer" / "Toolchains" / "XcodeDefault.xctoolchain" / "usr" / "bin"));

    // Links work whether they were made as links or as copies.
    CHECK(read_text_file(sdk / "usr" / "lib" / "libSystem.tbd") == "tbd contents");
    CHECK(read_text_file(platform / "Developer" / "SDKs" / "iPhoneOS.sdk" / "SDKSettings.json") ==
          "{\"Version\":\"18.2\"}");
    CHECK(report.links_as_links + report.links_as_copies == 2);

    // What Windows cannot hold is reported, not silently dropped.
    const auto skipped_with = [&](std::string_view text) {
        return std::count_if(report.skipped.begin(), report.skipped.end(), [&](const std::string& line) {
            return line.find(text) != std::string::npos;
        });
    };
    CHECK(report.skipped.size() == 5);
    CHECK(skipped_with("aux.h") == 1);
    CHECK(skipped_with("a:b.3") == 1);
    CHECK(skipped_with("differs only by case") == 1);
    CHECK(skipped_with("points outside the SDK") == 1);
    CHECK(skipped_with("dangling") == 1);
    CHECK(read_text_file(sdk / "usr" / "include" / "Case.h") == "upper");

    // Toolset: the shim fronts the real linker.
    CHECK(read_text_file(bundle / "toolset" / "bin" / "ld64.lld.exe") == "shim");
    CHECK(read_text_file(bundle / "toolset" / "bin" / "orig" / "ld64.lld.exe") == "real lld");
    CHECK(read_text_file(bundle / "toolset" / "bin" / "llvm-lib.exe") == "libtool");
    CHECK(report.missing_tools.empty());

    // Bundle metadata, as SwiftPM reads it.
    const json info = json::parse(read_text_file(bundle / "info.json").value());
    CHECK(info["artifacts"]["darwin"]["type"] == "swiftSDK");
    CHECK(info["artifacts"]["darwin"]["variants"][0]["supportedTriples"][0] ==
          "x86_64-unknown-windows-msvc");
    const json swift_sdk = json::parse(read_text_file(bundle / "swift-sdk.json").value());
    const json& triple = swift_sdk["targetTriples"]["arm64-apple-ios"];
    CHECK(triple["sdkRootPath"] ==
          "Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS18.2.sdk");
    CHECK(triple["swiftResourcesPath"] ==
          "Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift");
    CHECK(triple["toolsetPaths"][0] == "toolset.json");
    const json toolset = json::parse(read_text_file(bundle / "toolset.json").value());
    CHECK(toolset["rootPath"] == "toolset/bin");
    CHECK(toolset["linker"]["path"] == "ld64.lld.exe");
    CHECK(toolset["swiftCompiler"]["extraCLIOptions"][2] == "-use-ld=lld");

    const auto found = build::find_installed_sdk(dir.path() / "sdk");
    REQUIRE(found.has_value());
    CHECK(found->sdk_name == "iPhoneOS18.2.sdk");
    CHECK_FALSE(build::find_installed_sdk(dir.path() / "nowhere").has_value());

    SECTION("missing tools are reported") {
        options.toolchain.reset();
        options.linker_shim = dir.path() / "no-shim.exe";
        const build::SdkInstallReport second = build::install_sdk(options);
        CHECK(second.missing_tools.size() == 2);
        CHECK(second.sdk.sdk_name == "iPhoneOS18.2.sdk");  // a reinstall replaces the old bundle
    }
    SECTION("files that are not an Xcode archive are refused") {
        write_text_file(dir.path() / "not.xip", "plain text");
        options.xip = dir.path() / "not.xip";
        CHECK_THROWS_AS(build::install_sdk(options), build::ArchiveError);

        Bytes empty;
        cpio_entry(empty, "./Readme.txt", kFile, bytes_of("no sdk here"));
        cpio_entry(empty, "TRAILER!!!", 0);
        write_xip(dir.path() / "other.xip", pbzx_wrap(empty, 10));
        options.xip = dir.path() / "other.xip";
        CHECK_THROWS_AS(build::install_sdk(options), build::ArchiveError);
        CHECK_FALSE(build::find_installed_sdk(dir.path() / "sdk").has_value());
    }
}

TEST_CASE("xtool.yml is parsed, validated and written back", "[project]") {
    const build::ProjectConfig config = build::ProjectConfig::parse(
        "version: 1\n"
        "bundleID: com.example.Hello\n"
        "product: Hello\n"
        "infoPath: Support/Info.plist\n"
        "entitlementsPath: App.entitlements\n"
        "iconPath: Resources/AppIcon.png\n"
        "resources:\n"
        "  - Resources/data.json\n"
        "  - Resources/Images\n"
        "extensions:\n"
        "  - product: Widget\n"
        "    infoPath: Support/Widget-Info.plist\n"
        "    bundleID: com.example.Hello.Widget\n");
    CHECK(config.version == 1);
    CHECK(config.bundle_id == "com.example.Hello");
    CHECK(config.product == "Hello");
    CHECK(config.icon_path == "Resources/AppIcon.png");
    CHECK(config.resources == std::vector<std::string>{"Resources/data.json", "Resources/Images"});
    REQUIRE(config.extensions.size() == 1);
    CHECK(config.extensions[0].product == "Widget");
    CHECK(config.bundle_id_for("Anything") == "com.example.Hello");

    const build::ProjectConfig again = build::ProjectConfig::parse(config.to_yaml());
    CHECK(again.bundle_id == config.bundle_id);
    CHECK(again.resources == config.resources);
    CHECK(again.extensions[0].info_path == "Support/Widget-Info.plist");

    const build::ProjectConfig by_org = build::ProjectConfig::parse("version: 1\norgID: com.example\n");
    CHECK(by_org.bundle_id_for("My_App") == "com.example.My-App");

    using build::ProjectError;
    CHECK_THROWS_AS(build::ProjectConfig::parse("bundleID: x"), ProjectError);            // no version
    CHECK_THROWS_AS(build::ProjectConfig::parse("version: 2\nbundleID: x"), ProjectError);
    CHECK_THROWS_AS(build::ProjectConfig::parse("version: 1\n"), ProjectError);           // no IDs
    CHECK_THROWS_AS(build::ProjectConfig::parse("version: 1\nbundleID: x\niconPath: a.jpg"),
                    ProjectError);
    CHECK_THROWS_AS(build::ProjectConfig::parse("version: 1\nbundleID: x\nresources: nope"),
                    ProjectError);
    CHECK_THROWS_AS(build::ProjectConfig::parse("version: [1\n"), ProjectError);
    CHECK_THROWS_AS(build::ProjectConfig::parse("just text"), ProjectError);
    CHECK_THROWS_AS(build::ProjectConfig::load("C:\\no\\such\\project"), ProjectError);
}

TEST_CASE("the package manifest decides which product becomes the app", "[project]") {
    const build::PackageInfo info = build::parse_package_dump(package_dump().dump());
    CHECK(info.name == "Hello");
    CHECK(info.library_products == std::vector<std::string>{"Hello"});
    CHECK(info.ios_deployment_target == "17.0");

    build::ProjectConfig config;
    CHECK(build::select_product(config, info) == "Hello");
    config.product = "Missing";
    CHECK_THROWS_AS(build::select_product(config, info), build::ProjectError);

    build::PackageInfo two = info;
    two.library_products.push_back("Other");
    config.product.clear();
    CHECK_THROWS_AS(build::select_product(config, two), build::ProjectError);
    config.product = "Other";
    CHECK(build::select_product(config, two) == "Other");

    build::PackageInfo none = info;
    none.library_products.clear();
    config.product.clear();
    CHECK_THROWS_AS(build::select_product(config, none), build::ProjectError);
    CHECK_THROWS_AS(build::parse_package_dump("not json"), build::ProjectError);
}

TEST_CASE("winx new writes an xtool-compatible project", "[project]") {
    const test::TempDir dir("winx_new");
    const fs::path project = dir.path() / "Hello";
    build::create_project(project, "Hello", "org.sample");

    const std::string manifest = read_text_file(project / "Package.swift").value();
    CHECK(manifest.starts_with("// swift-tools-version: 6.0\n"));
    CHECK(manifest.find(".library(\n            name: \"Hello\"") != std::string::npos);
    CHECK(read_text_file(project / "Sources" / "Hello" / "HelloApp.swift")
              .value()
              .find("@main\nstruct HelloApp: App {") != std::string::npos);
    CHECK(fs::exists(project / "Sources" / "Hello" / "ContentView.swift"));
    CHECK(build::ProjectConfig::load(project).bundle_id == "org.sample.Hello");

    CHECK_THROWS_AS(build::create_project(project, "Hello"), build::ProjectError);  // exists
    CHECK_THROWS_AS(build::create_project(dir.path() / "bad", "1bad"), build::ProjectError);
    CHECK(build::is_valid_project_name("My_App2"));
    CHECK_FALSE(build::is_valid_project_name("my app"));
    CHECK_FALSE(build::is_valid_project_name(""));
}

TEST_CASE("toolchain output is understood", "[swiftpm]") {
    CHECK(build::parse_swift_version("Swift version 6.4 (swift-6.4-RELEASE)\nTarget: x") ==
          std::pair{6, 4});
    CHECK(build::parse_swift_version("compnerd.org Swift version 6.4.1-dev (LLVM abc)") ==
          std::pair{6, 4});
    CHECK(build::parse_swift_version("Swift version 5.10") == std::pair{5, 10});
    CHECK_FALSE(build::parse_swift_version("clang version 17").has_value());

    const auto error = build::parse_diagnostic(
        "C:\\src\\Hello\\Sources\\Hello\\ContentView.swift:7:13: error: cannot find 'Texty' in scope");
    REQUIRE(error.has_value());
    CHECK(error->file == "C:\\src\\Hello\\Sources\\Hello\\ContentView.swift");
    CHECK(error->line == 7);
    CHECK(error->column == 13);
    CHECK(error->severity == build::Diagnostic::Severity::Error);
    CHECK(error->message == "cannot find 'Texty' in scope");

    const auto warning = build::parse_diagnostic("/tmp/x.swift:1:2: warning: unused: value");
    REQUIRE(warning.has_value());
    CHECK(warning->severity == build::Diagnostic::Severity::Warning);
    CHECK(warning->message == "unused: value");
    CHECK(build::parse_diagnostic("a.c:3:1: note: declared here")->severity ==
          build::Diagnostic::Severity::Note);
    CHECK_FALSE(build::parse_diagnostic("error: fatalError").has_value());
    CHECK_FALSE(build::parse_diagnostic("Building for debugging...").has_value());
    CHECK_FALSE(build::parse_diagnostic("[3/7] Compiling Hello ContentView.swift").has_value());

    build::PackageInfo package;
    package.ios_deployment_target = "16.4";
    const std::string manifest = build::wrapper_manifest(package, "Hello", "../../..");
    CHECK(manifest.find("platforms: [.iOS(\"16.4\")]") != std::string::npos);
    CHECK(manifest.find(".package(name: \"RootPackage\", path: \"../../..\")") != std::string::npos);
    CHECK(manifest.find("name: \"Hello-App\"") != std::string::npos);
    CHECK(manifest.find(".product(name: \"Hello\", package: \"RootPackage\")") != std::string::npos);
    CHECK(manifest.find("@executable_path/Frameworks") != std::string::npos);
}

TEST_CASE("the SwiftPM driver builds through the toolchain", "[swiftpm]") {
    const test::TempDir dir("winx_build");
    const fs::path project = dir.path() / "Hello";
    build::create_project(project, "Hello");
    write_stub_sdk(dir.path() / "sdk");
    write_text_file(dir.path() / "dump.json", package_dump().dump());
    const Bytes product = test::simple_macho();
    write_file(dir.path() / "product.bin", product);
    const fs::path log = dir.path() / "swift.log";

    const ScopedEnv dump("WINX_FAKE_SWIFT_DUMP", to_utf8((dir.path() / "dump.json").wstring()));
    const ScopedEnv binary("WINX_FAKE_SWIFT_PRODUCT", to_utf8((dir.path() / "product.bin").wstring()));
    const ScopedEnv record("WINX_FAKE_SWIFT_LOG", to_utf8(log.wstring()));

    build::BuildRequest request;
    request.project_dir = project;
    request.config = build::ProjectConfig::load(project);
    request.toolchain = build::find_toolchain(kFakeSwift);
    request.sdk_bundles_dir = dir.path() / "sdk";
    std::vector<std::string> output;
    request.on_output = [&](std::string_view line) { output.emplace_back(line); };
    CHECK(request.toolchain.major == 6);
    CHECK(request.toolchain.minor == 4);
    CHECK(request.toolchain.version_text == "Swift version 6.4 (swift-fake-RELEASE)");

    SECTION("a successful build yields the linked executable") {
        const build::BuildResult result = build::build_package(request);
        REQUIRE(result.success);
        CHECK(result.product == "Hello");
        CHECK(result.package.ios_deployment_target == "17.0");
        CHECK(read_file(result.executable) == product);
        CHECK(result.executable.filename() == "Hello-App");
        CHECK(result.diagnostics.empty());
        CHECK(std::find(output.begin(), output.end(), "Build complete!") != output.end());

        // The wrapper package was generated next to the project's build directory.
        const fs::path wrapper = project / ".build" / "winx" / "package";
        CHECK(read_text_file(wrapper / "Package.swift").value().find("Hello-winx") != std::string::npos);
        CHECK(fs::exists(wrapper / "Sources" / "Hello-App" / "stub.c"));

        const std::string invocations = read_text_file(log).value();
        CHECK(invocations.find("package\tdump-package") != std::string::npos);
        CHECK(invocations.find("--swift-sdk\tarm64-apple-ios") != std::string::npos);
        CHECK(invocations.find("--configuration\tdebug") != std::string::npos);
        CHECK(invocations.find("--product\tHello-App") != std::string::npos);
        CHECK(invocations.find("--swift-sdks-path\t" + to_utf8((dir.path() / "sdk").wstring())) !=
              std::string::npos);
    }
    SECTION("compiler errors are collected as diagnostics") {
        const ScopedEnv fail("WINX_FAKE_SWIFT_FAIL", "1");
        std::vector<build::Diagnostic> live;
        request.on_diagnostic = [&](const build::Diagnostic& diagnostic) { live.push_back(diagnostic); };
        const build::BuildResult result = build::build_package(request);
        CHECK_FALSE(result.success);
        CHECK(result.exit_code == 1);
        REQUIRE(result.diagnostics.size() == 2);
        CHECK(result.diagnostics[0].line == 7);
        CHECK(result.diagnostics[0].message == "cannot find 'Texty' in scope");
        CHECK(result.diagnostics[1].severity == build::Diagnostic::Severity::Warning);
        CHECK(live.size() == 2);
    }
    SECTION("release builds ask for the release configuration") {
        request.release = true;
        CHECK(build::build_package(request).success);
        CHECK(read_text_file(log).value().find("--configuration\trelease") != std::string::npos);
    }
    SECTION("a toolchain that is too old is refused before building") {
        const ScopedEnv old("WINX_FAKE_SWIFT_VERSION", "6.2");
        request.toolchain = build::find_toolchain(kFakeSwift);
        CHECK_THROWS_AS(build::build_package(request), build::BuildError);
    }
    SECTION("a missing SDK is reported before building") {
        request.sdk_bundles_dir = dir.path() / "no-sdk";
        CHECK_THROWS_AS(build::build_package(request), build::BuildError);
    }
    SECTION("a missing toolchain explains how to install one") {
        try {
            build::find_toolchain(dir.path() / "missing-swift.exe");
            FAIL("expected BuildError");
        } catch (const build::BuildError& error) {
            CHECK(std::string(error.what()).find("swift.org") != std::string::npos);
        }
    }
}

TEST_CASE("images are written, measured and scaled", "[bundler]") {
    const test::TempDir dir("winx_images");
    std::vector<std::uint8_t> pixels(64 * 64 * 4);
    for (std::size_t i = 0; i < pixels.size(); i += 4) {
        pixels[i] = 255;      // blue
        pixels[i + 3] = 255;  // opaque
    }
    build::write_png(dir.path() / "icon.png", 64, 64, pixels);
    CHECK(build::image_size(dir.path() / "icon.png") == std::pair{64u, 64u});
    CHECK(read_file(dir.path() / "icon.png").value()[1] == 'P');  // \x89PNG

    build::scale_png(dir.path() / "icon.png", dir.path() / "out" / "big.png", 180);
    CHECK(build::image_size(dir.path() / "out" / "big.png") == std::pair{180u, 180u});

    CHECK_THROWS_AS(build::write_png(dir.path() / "bad.png", 2, 2, std::vector<std::uint8_t>(3)),
                    build::ProjectError);
    write_text_file(dir.path() / "not-an-image.png", "text");
    CHECK_THROWS_AS(build::image_size(dir.path() / "not-an-image.png"), build::ProjectError);
}

TEST_CASE("an app bundle is assembled from build products", "[bundler]") {
    const test::TempDir dir("winx_bundle_build");
    const fs::path project = dir.path() / "Hello";
    build::create_project(project, "Hello");
    const Bytes executable = test::simple_macho();
    const fs::path bin = dir.path() / "bin";
    write_file(bin / "Hello-App", executable);
    write_text_file(bin / "Hello_Hello.bundle" / "strings.json", "{}");
    write_text_file(bin / "libExtra.dylib", "dylib");
    write_text_file(bin / "Hello.build" / "ignored.o", "object");

    std::vector<std::uint8_t> pixels(256 * 256 * 4, 200);
    build::write_png(project / "Resources" / "AppIcon.png", 256, 256, pixels);
    write_text_file(project / "Resources" / "data.json", "[1]");
    write_text_file(project / "Resources" / "Images" / "a.txt", "a");
    write_text_file(project / "Support" / "Info.plist",
                    plist::to_xml(plist::Dict{{"CFBundleDisplayName", "Hello There"},
                                              {"NSCameraUsageDescription", "For scanning"},
                                              {"CFBundleExecutable", "WrongName"}}));

    build::BundleRequest request;
    request.project_dir = project;
    request.config = build::ProjectConfig::load(project);
    request.config.icon_path = "Resources/AppIcon.png";
    request.config.info_path = "Support/Info.plist";
    request.config.resources = {"Resources/data.json", "Resources/Images"};
    request.product = "Hello";
    request.deployment_target = "17.0";
    request.sdk_version = "18.2";
    request.executable = bin / "Hello-App";
    request.bin_dir = bin;
    request.output_dir = dir.path() / "products";

    const build::BundleResult result = build::assemble_bundle(request);
    const fs::path& app = result.bundle;
    CHECK(app == dir.path() / "products" / "Hello.app");
    CHECK(result.bundle_id == "com.example.Hello");
    CHECK(result.warnings.empty());
    CHECK(read_file(app / "Hello") == executable);
    CHECK(read_text_file(app / "PkgInfo") == "APPL????");

    const std::vector<std::uint8_t> info_bytes = read_file(app / "Info.plist").value();
    CHECK(std::string(info_bytes.begin(), info_bytes.begin() + 6) == "bplist");  // binary on device
    const plist::Value info = plist::parse(info_bytes);
    CHECK(info.string_at("CFBundleIdentifier") == "com.example.Hello");
    CHECK(info.string_at("CFBundleExecutable") == "Hello");  // not overridable
    CHECK(info.string_at("CFBundleDisplayName") == "Hello There");
    CHECK(info.string_at("NSCameraUsageDescription") == "For scanning");
    CHECK(info.string_at("MinimumOSVersion") == "17.0");
    CHECK(info.string_at("DTSDKName") == "iphoneos18.2");
    CHECK(info.bool_at("LSRequiresIPhoneOS") == true);
    CHECK(info.find("UIDeviceFamily")->as_array() == plist::Array{1, 2});
    CHECK(info.find("UILaunchScreen")->as_dict().empty());
    const plist::Value* icons = info.find("CFBundleIcons");
    REQUIRE(icons != nullptr);
    CHECK(icons->find("CFBundlePrimaryIcon")->find("CFBundleIconFiles")->as_array() ==
          plist::Array{"AppIcon60x60"});
    CHECK(info.find("CFBundleIcons~ipad") != nullptr);

    CHECK(build::image_size(app / "AppIcon60x60@2x.png") == std::pair{120u, 120u});
    CHECK(build::image_size(app / "AppIcon60x60@3x.png") == std::pair{180u, 180u});
    CHECK(build::image_size(app / "AppIcon76x76@2x~ipad.png") == std::pair{152u, 152u});
    CHECK(build::image_size(app / "AppIcon83.5x83.5@2x~ipad.png") == std::pair{167u, 167u});

    CHECK(read_text_file(app / "data.json") == "[1]");
    CHECK(read_text_file(app / "Images" / "a.txt") == "a");
    CHECK(read_text_file(app / "Hello_Hello.bundle" / "strings.json") == "{}");
    CHECK(read_text_file(app / "Frameworks" / "libExtra.dylib") == "dylib");
    CHECK_FALSE(fs::exists(app / "Hello.build"));

    SECTION("missing inputs are named") {
        request.config.resources = {"Resources/nope.json"};
        CHECK_THROWS_AS(build::assemble_bundle(request), build::ProjectError);
        request.config.resources.clear();
        request.config.icon_path = "Resources/none.png";
        CHECK_THROWS_AS(build::assemble_bundle(request), build::ProjectError);
    }
    SECTION("unsupported features produce warnings, not silence") {
        build::ExtensionConfig extension;
        extension.product = "Widget";
        request.config.extensions.push_back(extension);
        build::write_png(project / "Resources" / "AppIcon.png", 64, 32, std::vector<std::uint8_t>(64 * 32 * 4, 9));
        const build::BundleResult warned = build::assemble_bundle(request);
        CHECK(warned.warnings.size() == 3);  // not square, too small, extensions
    }
}

TEST_CASE("the pipeline builds, signs and installs a project", "[pipeline]") {
    const test::TempDir dir("winx_pipeline");
    const fs::path project = dir.path() / "Hello";
    build::create_project(project, "Hello");
    write_stub_sdk(dir.path() / "sdk");
    write_text_file(dir.path() / "dump.json", package_dump().dump());
    write_file(dir.path() / "product.bin", test::simple_macho());
    write_text_file(project / "App.entitlements",
                    plist::to_xml(plist::Dict{{"com.apple.developer.extra", true},
                                              {"application-identifier", "EVIL.other.app"}}));
    build::ProjectConfig config = build::ProjectConfig::load(project);
    config.entitlements_path = "App.entitlements";
    config.save(project);

    const ScopedEnv dump("WINX_FAKE_SWIFT_DUMP", to_utf8((dir.path() / "dump.json").wstring()));
    const ScopedEnv binary("WINX_FAKE_SWIFT_PRODUCT", to_utf8((dir.path() / "product.bin").wstring()));

    // Signing identity and a device, both local stand-ins.
    const auth::RsaKey key = auth::RsaKey::create();
    const Bytes certificate = auth::make_self_signed_certificate(
        key, "CN=\"Apple Development: Test (ABCDE12345)\", OU=TEAM123456");
    test::FakeDevice fake;

    std::vector<std::string> stages;
    std::vector<engine::Event> events;
    engine::PipelineOptions options;
    options.project_dir = project;
    options.swift = kFakeSwift;
    options.sdk_dir = dir.path() / "sdk";
    options.resolve_device = [&](const std::string& udid) {
        CHECK(udid.empty());
        return engine::TargetDevice{fake.udid(), "Fake iPhone"};
    };
    std::string provisioned_bundle;
    options.provision = [&](const std::string& bundle_id, const engine::TargetDevice& device,
                            const std::function<void(const std::string&)>& log) {
        provisioned_bundle = bundle_id;
        CHECK(device.udid == fake.udid());
        log("provisioning " + bundle_id);
        engine::SigningMaterial material;
        material.credentials.certificate = certificate;
        material.credentials.private_key = key.handle();
        material.credentials.common_name = "Apple Development: Test (ABCDE12345)";
        material.credentials.team_id = "TEAM123456";
        material.provisioning_profile = {'p', 'r', 'o', 'f'};
        material.entitlements = plist::Dict{{"application-identifier", "TEAM123456." + bundle_id},
                                            {"get-task-allow", true}};
        return material;
    };
    options.install_bundle = [&](const fs::path& bundle, const engine::TargetDevice& device,
                                 const std::function<void(const std::string&, int)>& progress) {
        device::DeviceConnection connection =
            device::DeviceConnection::open(fake.endpoint(), device.udid);
        device::install_app(connection, bundle, progress);
    };
    const engine::EventSink sink = [&](const engine::Event& event) {
        events.push_back(event);
        if (event.kind == engine::Event::Kind::Stage) stages.push_back(event.text);
    };

    SECTION("the full run ends with the app on the device") {
        const engine::PipelineResult result = engine::run_pipeline(options, sink);
        INFO(result.error);
        REQUIRE(result.success);
        CHECK(result.bundle_id == "com.example.Hello");
        CHECK(result.product == "Hello");
        CHECK(provisioned_bundle == "com.example.Hello");
        CHECK(stages == std::vector<std::string>{"Preparing", "Building", "Packaging", "Provisioning",
                                                 "Signing", "Installing"});

        // The bundle on disk is signed and consistent.
        CHECK(codesign::verify_bundle(result.bundle).empty());
        CHECK(read_file(result.bundle / "embedded.mobileprovision") == Bytes{'p', 'r', 'o', 'f'});
        const auto signature = codesign::read_signature(read_file(result.bundle / "Hello").value());
        REQUIRE(signature.has_value());
        CHECK(signature->code_directories[0].identifier == "com.example.Hello");
        CHECK(signature->code_directories[0].team_id == "TEAM123456");
        const plist::Value entitlements = plist::parse(signature->entitlements);
        // The project's entitlements add keys but cannot change the app's identity.
        CHECK(entitlements.bool_at("com.apple.developer.extra") == true);
        CHECK(entitlements.string_at("application-identifier") == "TEAM123456.com.example.Hello");

        // And the device received exactly that bundle.
        const std::lock_guard lock(fake.mutex);
        CHECK(fake.installed_bundle_ids.back() == "com.example.Hello");
        CHECK(fake.staged_at_install.at("PublicStaging/Hello.app/Hello") ==
              read_file(result.bundle / "Hello").value());
        CHECK(std::any_of(events.begin(), events.end(), [](const engine::Event& event) {
            return event.kind == engine::Event::Kind::Progress && event.text == "Complete";
        }));
    }
    SECTION("build only stops before provisioning") {
        options.sign = false;
        const engine::PipelineResult result = engine::run_pipeline(options, sink);
        REQUIRE(result.success);
        CHECK(stages == std::vector<std::string>{"Preparing", "Building", "Packaging"});
        CHECK(provisioned_bundle.empty());
        CHECK(fs::exists(result.bundle / "Info.plist"));
        CHECK_FALSE(fs::exists(result.bundle / "_CodeSignature"));
    }
    SECTION("a failed build reports its diagnostics and goes no further") {
        const ScopedEnv fail("WINX_FAKE_SWIFT_FAIL", "1");
        const engine::PipelineResult result = engine::run_pipeline(options, sink);
        CHECK_FALSE(result.success);
        CHECK(result.error == "the build failed with 1 error(s)");
        CHECK(result.diagnostics.size() == 2);
        CHECK(stages == std::vector<std::string>{"Preparing", "Building"});
        CHECK(std::count_if(events.begin(), events.end(), [](const engine::Event& event) {
                  return event.kind == engine::Event::Kind::Diagnostic;
              }) == 2);
    }
    SECTION("a device-side failure is reported as the result") {
        {
            const std::lock_guard lock(fake.mutex);
            fake.install_error = "ApplicationVerificationFailed";
        }
        const engine::PipelineResult result = engine::run_pipeline(options, sink);
        CHECK_FALSE(result.success);
        CHECK(result.error.find("ApplicationVerificationFailed") != std::string::npos);
        CHECK(stages.back() == "Installing");
    }
    SECTION("problems before the build are reported without throwing") {
        options.sdk_dir = dir.path() / "no-sdk";
        const engine::PipelineResult result = engine::run_pipeline(options, sink);
        CHECK_FALSE(result.success);
        CHECK(result.error.find("winx sdk install") != std::string::npos);

        options.project_dir = dir.path() / "not-a-project";
        CHECK(engine::run_pipeline(options, sink).error.find("xtool.yml") != std::string::npos);
    }
}
