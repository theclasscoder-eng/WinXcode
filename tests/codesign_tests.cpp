#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "support.hpp"
#include "winx/codesign.hpp"
#include "winx/der.hpp"
#include "winx/files.hpp"
#include "winx/identity.hpp"
#include "winx/macho.hpp"
#include "winx/plist.hpp"

using namespace winx;
using codesign::Bytes;
using codesign::ByteView;

namespace {

void put_le32(Bytes& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

void put_le64(Bytes& out, std::uint64_t value) {
    put_le32(out, static_cast<std::uint32_t>(value));
    put_le32(out, static_cast<std::uint32_t>(value >> 32));
}

void put_name(Bytes& out, std::string_view name) {
    for (std::size_t i = 0; i < 16; ++i) out.push_back(i < name.size() ? name[i] : 0);
}

struct MachOShape {
    std::uint32_t cpu_type = codesign::kCpuTypeArm64;
    std::uint32_t file_type = codesign::kFileTypeExecute;
    std::uint32_t section_offset = 0x4000;  // where __text starts; the gap before it is header padding
    std::uint32_t linkedit_size = 0x230;
};

// A structurally valid 64-bit Mach-O with one __TEXT segment holding one
// section and a __LINKEDIT segment at the end, filled with noise.
Bytes make_macho(const MachOShape& shape = {}) {
    constexpr std::uint64_t kTextSize = 0x8000;
    Bytes out;
    put_le32(out, codesign::kMachHeaderMagic64);
    put_le32(out, shape.cpu_type);
    put_le32(out, 0);  // cpusubtype
    put_le32(out, shape.file_type);
    put_le32(out, 2);  // ncmds
    put_le32(out, 72 + 80 + 72);
    put_le32(out, 0);  // flags
    put_le32(out, 0);  // reserved

    put_le32(out, codesign::kLoadCommandSegment64);
    put_le32(out, 72 + 80);
    put_name(out, "__TEXT");
    put_le64(out, 0x100000000);  // vmaddr
    put_le64(out, kTextSize);    // vmsize
    put_le64(out, 0);            // fileoff
    put_le64(out, kTextSize);    // filesize
    put_le32(out, 5);            // maxprot
    put_le32(out, 5);            // initprot
    put_le32(out, 1);            // nsects
    put_le32(out, 0);            // flags
    put_name(out, "__text");
    put_name(out, "__TEXT");
    put_le64(out, 0x100000000 + shape.section_offset);
    put_le64(out, 0x1000);
    put_le32(out, shape.section_offset);
    put_le32(out, 2);  // align
    put_le32(out, 0);
    put_le32(out, 0);
    put_le32(out, 0x80000400);  // regular, pure instructions
    put_le32(out, 0);
    put_le32(out, 0);
    put_le32(out, 0);

    put_le32(out, codesign::kLoadCommandSegment64);
    put_le32(out, 72);
    put_name(out, "__LINKEDIT");
    put_le64(out, 0x100000000 + kTextSize);
    put_le64(out, 0x4000);
    put_le64(out, kTextSize);
    put_le64(out, shape.linkedit_size);
    put_le32(out, 1);
    put_le32(out, 1);
    put_le32(out, 0);
    put_le32(out, 0);

    out.resize(shape.section_offset, 0);
    const Bytes noise = crypto::random_bytes(kTextSize - shape.section_offset + shape.linkedit_size);
    out.insert(out.end(), noise.begin(), noise.end());
    return out;
}

struct TestIdentity {
    auth::RsaKey key = auth::RsaKey::create();
    codesign::SigningCredentials credentials;

    TestIdentity() {
        credentials.certificate = auth::make_self_signed_certificate(
            key, "CN=\"Apple Development: Test User (ABCDE12345)\", OU=TEAM123456");
        credentials.private_key = key.handle();
        credentials.chain = {
            auth::make_self_signed_certificate(key, "CN=Stand-in Intermediate")};
        credentials.common_name = "Apple Development: Test User (ABCDE12345)";
        credentials.team_id = "TEAM123456";
    }
};

bool contains(ByteView haystack, ByteView needle) {
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) !=
           haystack.end();
}

plist::Value sample_entitlements() {
    return plist::Dict{{"application-identifier", "TEAM123456.com.example.app"},
                       {"com.apple.developer.team-identifier", "TEAM123456"},
                       {"get-task-allow", true},
                       {"keychain-access-groups", plist::Array{"TEAM123456.com.example.app"}}};
}

void write_bytes(const std::filesystem::path& path, const Bytes& bytes) { write_file(path, bytes); }

}  // namespace

TEST_CASE("DER primitives use minimal encodings", "[der]") {
    CHECK(der::integer(1) == Bytes{0x02, 0x01, 0x01});
    CHECK(der::integer(127) == Bytes{0x02, 0x01, 0x7F});
    CHECK(der::integer(128) == Bytes{0x02, 0x02, 0x00, 0x80});
    CHECK(der::integer(-1) == Bytes{0x02, 0x01, 0xFF});
    CHECK(der::integer(-129) == Bytes{0x02, 0x02, 0xFF, 0x7F});
    CHECK(der::integer(0) == Bytes{0x02, 0x01, 0x00});
    CHECK(der::boolean(true) == Bytes{0x01, 0x01, 0xFF});
    CHECK(der::utf8_string("ab") == Bytes{0x0C, 0x02, 'a', 'b'});
    CHECK(der::object_identifier("1.2.840.113635.100.9.1") ==
          Bytes{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x09, 0x01});
    CHECK(der::object_identifier("2.16.840.1.101.3.4.2.1") ==
          Bytes{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01});
    CHECK_THROWS_AS(der::object_identifier("1"), std::invalid_argument);

    // Long-form lengths.
    const Bytes medium = der::octet_string(Bytes(200, 0xAA));
    CHECK(medium[1] == 0x81);
    CHECK(medium[2] == 200);
    const Bytes large = der::octet_string(Bytes(300, 0xAA));
    CHECK(large[1] == 0x82);
    CHECK(large[2] == 0x01);
    CHECK(large[3] == 0x2C);

    const Bytes sequence = der::sequence({der::integer(5), der::utf8_string("x"), large});
    der::Reader outer(sequence);
    const der::Element whole = outer.read();
    CHECK(whole.tag == der::kSequence);
    CHECK(outer.at_end());
    der::Reader inner(whole.content);
    CHECK(inner.read().content.size() == 1);
    CHECK(inner.read().tag == der::kUtf8String);
    CHECK(inner.read().content.size() == 300);
    CHECK(inner.at_end());
    der::Reader truncated(ByteView(sequence).subspan(0, 10));
    CHECK_THROWS_AS(truncated.read(), der::DecodeError);
}

TEST_CASE("entitlements encode to Apple's DER form", "[codesign]") {
    const plist::Value entitlements =
        plist::Dict{{"get-task-allow", true}, {"application-identifier", "T.b"}};
    Bytes expected = {0x70, 0x39, 0x02, 0x01, 0x01, 0xB0, 0x34, 0x30, 0x1D, 0x0C, 0x16};
    const std::string first_key = "application-identifier";
    expected.insert(expected.end(), first_key.begin(), first_key.end());
    expected.insert(expected.end(), {0x0C, 0x03, 'T', '.', 'b', 0x30, 0x13, 0x0C, 0x0E});
    const std::string second_key = "get-task-allow";
    expected.insert(expected.end(), second_key.begin(), second_key.end());
    expected.insert(expected.end(), {0x01, 0x01, 0xFF});
    // Keys are sorted regardless of the order in the plist.
    CHECK(codesign::encode_der_entitlements(entitlements) == expected);

    const plist::Value nested = plist::Dict{{"n", 5}, {"a", plist::Array{"x", "y"}}};
    const Bytes encoded = codesign::encode_der_entitlements(nested);
    const Bytes array = {0x30, 0x06, 0x0C, 0x01, 'x', 0x0C, 0x01, 'y'};
    CHECK(contains(encoded, array));
    CHECK(contains(encoded, Bytes{0x0C, 0x01, 'n', 0x02, 0x01, 0x05}));

    CHECK_THROWS_AS(codesign::encode_der_entitlements(plist::Value("not a dict")),
                    codesign::SignError);
    CHECK_THROWS_AS(codesign::encode_der_entitlements(plist::Dict{{"real", 1.5}}),
                    codesign::SignError);
}

TEST_CASE("requirements blobs follow the designated-requirement layout", "[codesign]") {
    const codesign::SigningCredentials ad_hoc;
    CHECK(codesign::encode_requirements("com.example.app", ad_hoc) ==
          Bytes{0xFA, 0xDE, 0x0C, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00});

    const TestIdentity identity;
    const Bytes blob = codesign::encode_requirements("com.example.app", identity.credentials);
    CHECK(codesign::read_be32(blob, 0) == 0xFADE0C01);
    CHECK(codesign::read_be32(blob, 4) == blob.size());
    CHECK(codesign::read_be32(blob, 8) == 1);    // one requirement
    CHECK(codesign::read_be32(blob, 12) == 3);   // designated
    CHECK(codesign::read_be32(blob, 16) == 20);  // offset of the requirement
    CHECK(codesign::read_be32(blob, 20) == 0xFADE0C00);
    CHECK(codesign::read_be32(blob, 28) == 1);  // expression form
    CHECK(codesign::read_be32(blob, 32) == 6);  // opAnd
    CHECK(blob.size() % 4 == 0);
    CHECK(contains(blob, crypto::as_bytes("com.example.app")));
    CHECK(contains(blob, crypto::as_bytes("subject.CN")));
    CHECK(contains(blob, crypto::as_bytes("Apple Development: Test User (ABCDE12345)")));
    // The WWDR marker OID 1.2.840.113635.100.6.2.1.
    CHECK(contains(blob, Bytes{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x06, 0x02, 0x01}));
}

TEST_CASE("an unsigned Mach-O gains a self-consistent ad hoc signature", "[codesign]") {
    const Bytes original = make_macho();
    const codesign::MachOSlice before = codesign::MachOSlice::parse(original);
    REQUIRE_FALSE(before.signature_command_offset.has_value());
    REQUIRE(before.find_segment("__LINKEDIT") != nullptr);
    CHECK(before.first_section_offset == 0x4000);

    codesign::MachOSignOptions options;
    options.identifier = "com.example.tool";
    const Bytes signed_image = codesign::sign_macho(original, options, {});

    const codesign::MachOSlice after = codesign::MachOSlice::parse(signed_image);
    REQUIRE(after.signature_command_offset.has_value());
    CHECK(after.command_count == before.command_count + 1);
    CHECK(after.commands_size == before.commands_size + 16);
    CHECK(after.signature_offset == original.size());  // already a multiple of 16
    CHECK(static_cast<std::size_t>(after.signature_offset) + after.signature_size ==
          signed_image.size());
    const codesign::Segment* linkedit = after.find_segment("__LINKEDIT");
    CHECK(linkedit->file_offset + linkedit->file_size == signed_image.size());
    CHECK(linkedit->vm_size % 0x4000 == 0);
    CHECK(linkedit->vm_size >= linkedit->file_size);
    // Nothing but the header fields and load commands changed in the code.
    CHECK(std::equal(original.begin() + 0x4000, original.end(), signed_image.begin() + 0x4000));

    const auto signature = codesign::read_signature(signed_image);
    REQUIRE(signature.has_value());
    REQUIRE(signature->code_directories.size() == 2);
    const codesign::CodeDirectoryInfo& sha1 = signature->code_directories[0];
    const codesign::CodeDirectoryInfo& sha256 = signature->code_directories[1];
    CHECK(sha1.slot == codesign::kSlotCodeDirectory);
    CHECK(sha1.hash_type == 1);
    CHECK(sha1.hash_size == 20);
    CHECK(sha256.slot == codesign::kSlotAlternateCodeDirectories);
    CHECK(sha256.hash_type == 2);
    CHECK(sha256.hash_size == 32);
    for (const codesign::CodeDirectoryInfo& directory : signature->code_directories) {
        CHECK(directory.version == 0x20400);
        CHECK(directory.flags == codesign::kCodeDirectoryFlagAdHoc);
        CHECK(directory.identifier == "com.example.tool");
        CHECK(directory.team_id.empty());
        CHECK(directory.page_shift == 12);
        CHECK(directory.code_limit == original.size());
        CHECK(directory.code_hashes.size() == (original.size() + 4095) / 4096);
        CHECK(directory.special_hashes.size() == 2);
        CHECK(directory.exec_segment_base == 0);
        CHECK(directory.exec_segment_limit == 0x8000);
        CHECK(directory.exec_segment_flags == codesign::kExecSegMainBinary);
    }
    CHECK(signature->cms.empty());
    CHECK(signature->entitlements.empty());
    CHECK(codesign::verify_macho(signed_image).empty());

    SECTION("changing a code byte is detected") {
        Bytes tampered = signed_image;
        tampered[0x5000] ^= 0x01;
        const auto problems = codesign::verify_macho(tampered);
        REQUIRE_FALSE(problems.empty());
        CHECK(problems.front().find("page 5") != std::string::npos);
    }
    SECTION("signing again replaces the signature in place") {
        options.identifier = "com.example.renamed";
        const Bytes again = codesign::sign_macho(signed_image, options, {});
        const codesign::MachOSlice replaced = codesign::MachOSlice::parse(again);
        CHECK(replaced.command_count == after.command_count);
        CHECK(replaced.signature_offset == after.signature_offset);
        CHECK(codesign::read_signature(again)->code_directories[0].identifier ==
              "com.example.renamed");
        CHECK(codesign::verify_macho(again).empty());
    }
    SECTION("an unsigned file is reported as such") {
        CHECK(codesign::verify_macho(original) ==
              std::vector<std::string>{"the image is not signed"});
        CHECK(codesign::verify_macho(crypto::random_bytes(64)) ==
              std::vector<std::string>{"not a Mach-O file"});
    }
}

TEST_CASE("a certificate signature seals entitlements and bundle hashes", "[codesign]") {
    const TestIdentity identity;
    const Bytes info_plist = {'i', 'n', 'f', 'o'};
    const Bytes code_resources = {'r', 'e', 's'};

    codesign::MachOSignOptions options;
    options.identifier = "com.example.app";
    options.info_plist = info_plist;
    options.code_resources = code_resources;
    options.entitlements = sample_entitlements();
    const Bytes signed_image = codesign::sign_macho(make_macho(), options, identity.credentials);

    CHECK(codesign::verify_macho(signed_image).empty());
    const auto signature = codesign::read_signature(signed_image);
    REQUIRE(signature.has_value());
    REQUIRE(signature->code_directories.size() == 2);

    for (const codesign::CodeDirectoryInfo& directory : signature->code_directories) {
        CHECK(directory.flags == 0);
        CHECK(directory.team_id == "TEAM123456");
        CHECK(directory.exec_segment_flags ==
              (codesign::kExecSegMainBinary | codesign::kExecSegAllowUnsigned));
        REQUIRE(directory.special_hashes.size() == 7);
        CHECK(directory.special_hashes[codesign::kSlotInfoPlist - 1] ==
              crypto::digest(directory.algorithm(), info_plist));
        CHECK(directory.special_hashes[codesign::kSlotResourceDirectory - 1] ==
              crypto::digest(directory.algorithm(), code_resources));
        // Unused slots stay zeroed.
        CHECK(directory.special_hashes[3] == Bytes(directory.hash_size, 0));
        CHECK(directory.special_hashes[5] == Bytes(directory.hash_size, 0));
    }

    CHECK(plist::parse(signature->entitlements) == sample_entitlements());
    CHECK(signature->der_entitlements == codesign::encode_der_entitlements(sample_entitlements()));

    // The CMS covers the primary CodeDirectory and carries Apple's CDHash attributes.
    REQUIRE_FALSE(signature->cms.empty());
    const codesign::CodeDirectoryInfo& primary = signature->code_directories[0];
    CHECK(codesign::verify_cms(signature->cms, primary.blob) ==
          "Apple Development: Test User (ABCDE12345)");
    Bytes altered = primary.blob;
    altered[40] ^= 1;
    CHECK_FALSE(codesign::verify_cms(signature->cms, altered).has_value());
    CHECK(contains(signature->cms, der::object_identifier("1.2.840.113635.100.9.1")));
    CHECK(contains(signature->cms, der::object_identifier("1.2.840.113635.100.9.2")));
    CHECK(contains(signature->cms, crypto::as_bytes("<key>cdhashes</key>")));
    CHECK(contains(signature->cms, signature->code_directories[1].cdhash()));  // full SHA-256
    CHECK(contains(signature->cms, primary.cdhash()));
    CHECK(contains(signature->cms, identity.credentials.certificate));
    CHECK(contains(signature->cms, identity.credentials.chain[0]));

    SECTION("swapping the entitlements blob is detected") {
        Bytes tampered = signed_image;
        const Bytes needle = {'g', 'e', 't', '-', 't', 'a', 's', 'k'};
        const auto position = std::search(tampered.begin() + signature->offset, tampered.end(),
                                          needle.begin(), needle.end());
        REQUIRE(position != tampered.end());
        *position = 'G';
        const auto problems = codesign::verify_macho(tampered);
        REQUIRE_FALSE(problems.empty());
        CHECK(problems.front().find("entitlements") != std::string::npos);
    }
}

TEST_CASE("dylibs are signed without the main-binary flag", "[codesign]") {
    MachOShape shape;
    shape.file_type = codesign::kFileTypeDylib;
    codesign::MachOSignOptions options;
    options.identifier = "libFoo";
    const Bytes signed_image = codesign::sign_macho(make_macho(shape), options, {});
    const auto signature = codesign::read_signature(signed_image);
    CHECK(signature->code_directories[0].exec_segment_flags == 0);
    CHECK(codesign::verify_macho(signed_image).empty());
}

TEST_CASE("images that cannot take a signature are refused", "[codesign]") {
    codesign::MachOSignOptions options;
    options.identifier = "x";

    MachOShape cramped;
    cramped.section_offset = 32 + 72 + 80 + 72 + 8;  // 8 bytes of padding; 16 are needed
    CHECK_THROWS_AS(codesign::sign_macho(make_macho(cramped), options, {}), codesign::SignError);

    Bytes trailing = make_macho();
    trailing.resize(trailing.size() + 64, 0);  // data after __LINKEDIT
    CHECK_THROWS_AS(codesign::sign_macho(trailing, options, {}), codesign::SignError);

    CHECK_THROWS_AS(codesign::sign_macho(crypto::random_bytes(128), options, {}),
                    codesign::SignError);
    options.identifier.clear();
    CHECK_THROWS_AS(codesign::sign_macho(make_macho(), options, {}), codesign::SignError);
    CHECK_THROWS_AS(codesign::MachOSlice::parse(Bytes(16, 0)), codesign::MachOError);
}

TEST_CASE("universal binaries are signed per slice and laid out again", "[codesign]") {
    MachOShape intel;
    intel.cpu_type = 0x01000007;
    const std::vector<Bytes> slices = {make_macho(), make_macho(intel)};

    Bytes fat;
    codesign::append_be32(fat, codesign::kFatMagic);
    codesign::append_be32(fat, 2);
    std::uint32_t offset = 0x4000;
    for (std::size_t i = 0; i < slices.size(); ++i) {
        codesign::append_be32(fat, i == 0 ? codesign::kCpuTypeArm64 : 0x01000007);
        codesign::append_be32(fat, 0);
        codesign::append_be32(fat, offset);
        codesign::append_be32(fat, static_cast<std::uint32_t>(slices[i].size()));
        codesign::append_be32(fat, 14);
        offset += 0xC000;
    }
    fat.resize(0x4000, 0);
    fat.insert(fat.end(), slices[0].begin(), slices[0].end());
    fat.resize(0x10000, 0);
    fat.insert(fat.end(), slices[1].begin(), slices[1].end());
    REQUIRE(codesign::is_fat_macho(fat));

    codesign::MachOSignOptions options;
    options.identifier = "com.example.universal";
    const Bytes signed_fat = codesign::sign_macho(fat, options, {});

    const auto arches = codesign::parse_fat(signed_fat);
    REQUIRE(arches.size() == 2);
    for (const codesign::FatArch& arch : arches) {
        CHECK(arch.offset % 0x4000 == 0);
        CHECK(arch.size > slices[0].size());
        const auto signature =
            codesign::read_signature(ByteView(signed_fat).subspan(arch.offset, arch.size));
        REQUIRE(signature.has_value());
        CHECK(signature->code_directories[0].identifier == "com.example.universal");
    }
    CHECK(arches[1].offset >= arches[0].offset + arches[0].size);
    CHECK(codesign::verify_macho(signed_fat).empty());
}

TEST_CASE("a bundle is sealed, signed inside-out and verifiable", "[codesign][bundle]") {
    const test::TempDir dir("winx_bundle");
    const std::filesystem::path app = dir.path() / "Hello.app";
    const auto info_plist = [](const std::string& identifier, const std::string& executable) {
        const std::string xml = plist::to_xml(plist::Dict{{"CFBundleIdentifier", identifier},
                                                          {"CFBundleExecutable", executable},
                                                          {"CFBundleName", executable}});
        return Bytes(xml.begin(), xml.end());
    };
    MachOShape dylib;
    dylib.file_type = codesign::kFileTypeDylib;

    write_bytes(app / "Info.plist", info_plist("com.example.hello", "Hello"));
    write_bytes(app / "Hello", make_macho());
    write_bytes(app / "PkgInfo", Bytes{'A', 'P', 'P', 'L', '?', '?', '?', '?'});
    write_bytes(app / "icon.png", crypto::random_bytes(300));
    write_bytes(app / "en.lproj" / "Localizable.strings", Bytes{'"', 'a', '"', '=', '"', 'b', '"', ';'});
    write_bytes(app / "Frameworks" / "libFoo.dylib", make_macho(dylib));
    write_bytes(app / "Frameworks" / "Bar.framework" / "Info.plist",
                info_plist("com.example.bar", "Bar"));
    write_bytes(app / "Frameworks" / "Bar.framework" / "Bar", make_macho(dylib));
    write_bytes(app / "PlugIns" / "Widget.appex" / "Info.plist",
                info_plist("com.example.hello.widget", "Widget"));
    write_bytes(app / "PlugIns" / "Widget.appex" / "Widget", make_macho());

    const TestIdentity identity;
    const Bytes profile = {'p', 'r', 'o', 'f', 'i', 'l', 'e'};
    std::vector<std::string> log;
    codesign::BundleSignOptions options;
    options.entitlements = sample_entitlements();
    options.provisioning_profile = profile;
    options.log = [&](const std::string& line) { log.push_back(line); };
    codesign::sign_bundle(app, identity.credentials, options);

    CHECK(codesign::verify_bundle(app).empty());
    CHECK(read_file(app / "embedded.mobileprovision") == profile);
    CHECK(read_file(app / "PlugIns" / "Widget.appex" / "embedded.mobileprovision") == profile);
    CHECK_FALSE(std::filesystem::exists(app / "Frameworks" / "Bar.framework" /
                                        "embedded.mobileprovision"));
    // Nested code is signed before the app that seals it.
    REQUIRE(log.size() == 4);
    CHECK(log.back() == "Signing Hello.app (com.example.hello)");

    const plist::Value seal =
        plist::parse(read_file(app / "_CodeSignature" / "CodeResources").value());
    const plist::Value* files = seal.find("files");
    const plist::Value* files2 = seal.find("files2");
    REQUIRE(files != nullptr);
    REQUIRE(files2 != nullptr);
    CHECK(seal.find("rules") != nullptr);
    CHECK(seal.find("rules2") != nullptr);
    // The executable is never sealed; Info.plist and PkgInfo only in the v1 list.
    CHECK(files->find("Hello") == nullptr);
    CHECK(files2->find("Hello") == nullptr);
    CHECK(files->find("Info.plist") != nullptr);
    CHECK(files2->find("Info.plist") == nullptr);
    CHECK(files2->find("PkgInfo") == nullptr);
    CHECK(files2->find("_CodeSignature/CodeResources") == nullptr);
    REQUIRE(files2->find("icon.png") != nullptr);
    CHECK(files2->find("icon.png")->data_at("hash2")->bytes ==
          crypto::sha256(read_file(app / "icon.png").value()));
    CHECK(files2->find("icon.png")->data_at("hash")->bytes.size() == 20);
    CHECK(files->find("icon.png")->is<plist::Data>());
    CHECK(files2->find("embedded.mobileprovision") != nullptr);
    CHECK(files2->find("en.lproj/Localizable.strings")->bool_at("optional") == true);
    CHECK(files->find("en.lproj/Localizable.strings")->bool_at("optional") == true);
    // Nested code is sealed with the hashes it has after it was signed.
    CHECK(files2->find("Frameworks/libFoo.dylib")->data_at("hash2")->bytes ==
          crypto::sha256(read_file(app / "Frameworks" / "libFoo.dylib").value()));
    CHECK(files2->find("Frameworks/Bar.framework/_CodeSignature/CodeResources") != nullptr);

    // The extension is signed for its own bundle identifier.
    const auto widget = codesign::read_signature(
        read_file(app / "PlugIns" / "Widget.appex" / "Widget").value());
    REQUIRE(widget.has_value());
    CHECK(widget->code_directories[0].identifier == "com.example.hello.widget");
    CHECK(plist::parse(widget->entitlements).string_at("application-identifier") ==
          "TEAM123456.com.example.hello.widget");
    const auto framework = codesign::read_signature(
        read_file(app / "Frameworks" / "Bar.framework" / "Bar").value());
    CHECK(framework->code_directories[0].identifier == "com.example.bar");
    CHECK(framework->entitlements.empty());

    SECTION("signing twice is stable") {
        codesign::sign_bundle(app, identity.credentials, options);
        CHECK(codesign::verify_bundle(app).empty());
    }
    SECTION("a modified resource is reported") {
        write_bytes(app / "icon.png", crypto::random_bytes(300));
        const auto problems = codesign::verify_bundle(app);
        REQUIRE(problems.size() == 1);
        CHECK(problems[0] == "Hello.app: modified file: icon.png");
    }
    SECTION("an added file is reported") {
        write_bytes(app / "extra.txt", Bytes{'x'});
        const auto problems = codesign::verify_bundle(app);
        REQUIRE(problems.size() == 1);
        CHECK(problems[0] == "Hello.app: unsealed file: extra.txt");
    }
    SECTION("a removed file is reported") {
        std::filesystem::remove(app / "icon.png");
        const auto problems = codesign::verify_bundle(app);
        REQUIRE(problems.size() == 1);
        CHECK(problems[0] == "Hello.app: sealed file is missing: icon.png");
    }
    SECTION("an edited Info.plist is reported") {
        write_bytes(app / "Info.plist", info_plist("com.example.hello", "Hello"));
        // Same content as before: still valid.
        CHECK(codesign::verify_bundle(app).empty());
        Bytes edited = info_plist("com.example.hello", "Hello");
        edited.push_back('\n');
        write_bytes(app / "Info.plist", edited);
        const auto problems = codesign::verify_bundle(app);
        REQUIRE_FALSE(problems.empty());
        CHECK(problems[0].find("Info.plist does not match") != std::string::npos);
    }
    SECTION("a tampered nested library is reported") {
        Bytes library = read_file(app / "Frameworks" / "libFoo.dylib").value();
        library[0x5000] ^= 1;
        write_bytes(app / "Frameworks" / "libFoo.dylib", library);
        const auto problems = codesign::verify_bundle(app);
        // One page-hash failure per CodeDirectory, plus the app's seal over the file.
        REQUIRE(problems.size() == 3);
        CHECK(problems[0].find("Frameworks/libFoo.dylib") != std::string::npos);
        CHECK(problems[2] == "Hello.app: modified file: Frameworks/libFoo.dylib");
    }
}

TEST_CASE("bundles without the required Info.plist keys are refused", "[codesign][bundle]") {
    const test::TempDir dir("winx_badbundle");
    const std::filesystem::path app = dir.path() / "Bad.app";
    CHECK_THROWS_AS(codesign::read_bundle_info(app), codesign::SignError);
    const std::string xml = plist::to_xml(plist::Dict{{"CFBundleIdentifier", "com.example.bad"}});
    write_bytes(app / "Info.plist", Bytes(xml.begin(), xml.end()));
    CHECK_THROWS_AS(codesign::read_bundle_info(app), codesign::SignError);
    CHECK_FALSE(codesign::verify_bundle(app).empty());
}
