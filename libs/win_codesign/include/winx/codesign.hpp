#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "winx/crypto.hpp"
#include "winx/macho.hpp"
#include "winx/plist.hpp"

// Apple code signatures, produced with Windows crypto only: SHA hashing
// through CNG and the CMS signature through crypt32 with a CNG private key.
namespace winx::codesign {

class SignError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Who signs. With an empty certificate the result is an ad hoc signature
// (hashes only, no CMS), which is useful for tests and simulators but is not
// accepted by a retail device.
struct SigningCredentials {
    Bytes certificate;               // leaf certificate, DER
    std::uintptr_t private_key = 0;  // NCRYPT_KEY_HANDLE matching the certificate
    std::vector<Bytes> chain;        // Apple WWDR intermediate and Apple Root CA, DER
    std::string common_name;         // subject CN, used in the designated requirement
    std::string team_id;             // subject OU

    bool ad_hoc() const noexcept { return certificate.empty(); }
};

struct MachOSignOptions {
    // Bundle identifier for a bundle's main binary, file stem for a bare dylib.
    std::string identifier;
    // Exact bytes of the bundle's Info.plist and CodeResources; empty when the
    // binary is not a bundle's main executable.
    Bytes info_plist;
    Bytes code_resources;
    std::optional<plist::Value> entitlements;
};

// Signs a thin or universal Mach-O, replacing any existing signature, and
// returns the new file contents.
Bytes sign_macho(ByteView image, const MachOSignOptions& options,
                 const SigningCredentials& credentials);

// ---- Building blocks, exposed for tests ----------------------------------

// Apple's DER entitlements encoding (slot 7).
Bytes encode_der_entitlements(const plist::Value& entitlements);
// Requirements blob (slot 2) with the designated requirement Xcode generates
// for development certificates; an empty set for ad hoc signatures.
Bytes encode_requirements(const std::string& identifier, const SigningCredentials& credentials);

// ---- Inspection ----------------------------------------------------------

inline constexpr std::uint32_t kSlotCodeDirectory = 0;
inline constexpr std::uint32_t kSlotInfoPlist = 1;
inline constexpr std::uint32_t kSlotRequirements = 2;
inline constexpr std::uint32_t kSlotResourceDirectory = 3;
inline constexpr std::uint32_t kSlotEntitlements = 5;
inline constexpr std::uint32_t kSlotDerEntitlements = 7;
inline constexpr std::uint32_t kSlotAlternateCodeDirectories = 0x1000;
inline constexpr std::uint32_t kSlotCmsSignature = 0x10000;

inline constexpr std::uint32_t kCodeDirectoryFlagAdHoc = 0x2;
inline constexpr std::uint64_t kExecSegMainBinary = 0x1;
inline constexpr std::uint64_t kExecSegAllowUnsigned = 0x10;

struct CodeDirectoryInfo {
    std::uint32_t slot = 0;
    std::uint32_t version = 0;
    std::uint32_t flags = 0;
    std::uint32_t code_limit = 0;
    std::uint8_t hash_type = 0;  // 1 = SHA-1, 2 = SHA-256
    std::uint8_t hash_size = 0;
    std::uint8_t page_shift = 0;
    std::string identifier;
    std::string team_id;
    std::uint64_t exec_segment_base = 0;
    std::uint64_t exec_segment_limit = 0;
    std::uint64_t exec_segment_flags = 0;
    // special_hashes[n - 1] is the hash for special slot n.
    std::vector<Bytes> special_hashes;
    std::vector<Bytes> code_hashes;
    Bytes blob;  // the whole CodeDirectory, as hashed for the CDHash

    crypto::HashAlgorithm algorithm() const;
    Bytes cdhash() const;
};

struct SignatureInfo {
    std::vector<CodeDirectoryInfo> code_directories;  // primary first
    Bytes requirements;      // whole blob
    Bytes entitlements;      // XML payload, without the blob header
    Bytes der_entitlements;  // DER payload
    Bytes cms;               // CMS payload; empty for ad hoc
    std::uint32_t offset = 0;
    std::uint32_t size = 0;
};

// Signature of a thin image, or nullopt if it has none.
std::optional<SignatureInfo> read_signature(ByteView thin_image);

// Structural and cryptographic self-check of a thin or universal Mach-O.
// Returns a description of every inconsistency; an empty list means the page
// hashes, special slots and (if present) the CMS signature over the primary
// CodeDirectory all agree. This does not evaluate Apple's trust chain.
std::vector<std::string> verify_macho(ByteView image);

// Subject common name of the certificate that produced the CMS signature
// over `content`, or nullopt if the signature does not verify.
std::optional<std::string> verify_cms(ByteView cms, ByteView content);

// ---- Bundles -------------------------------------------------------------

struct BundleSignOptions {
    std::optional<plist::Value> entitlements;
    // Written to embedded.mobileprovision when not empty.
    Bytes provisioning_profile;
    std::function<void(const std::string&)> log;
};

struct BundleInfo {
    std::string identifier;
    std::string executable;
    Bytes info_plist;  // raw file contents
};

BundleInfo read_bundle_info(const std::filesystem::path& bundle);

// Contents for _CodeSignature/CodeResources: SHA-1 and SHA-256 of every
// sealed file, with the rules Xcode uses for iOS bundles.
Bytes build_code_resources(const std::filesystem::path& bundle, const std::string& executable);

// Signs nested frameworks, dylibs and app extensions first, then seals the
// bundle's resources and signs its main executable.
void sign_bundle(const std::filesystem::path& bundle, const SigningCredentials& credentials,
                 const BundleSignOptions& options);

// Re-derives everything sign_bundle wrote and reports mismatches.
std::vector<std::string> verify_bundle(const std::filesystem::path& bundle);

}  // namespace winx::codesign
