#pragma once

#include <filesystem>
#include <string>
#include <string_view>

#include "winx/crypto.hpp"
#include "winx/keys.hpp"

// Helpers shared by the test files. Nothing here touches the network or the
// user's real state.
namespace winx::test {

// A fresh directory under %TEMP%, removed on destruction.
class TempDir {
public:
    explicit TempDir(std::string_view name);
    ~TempDir();
    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

// PKCS#8 PEM for a newly generated P-256 key, as App Store Connect issues.
std::string generate_p8();

// Certificate for the public key in `csr_pem`, signed by `ca_key`.
crypto::Bytes issue_certificate(std::string_view csr_pem, const auth::RsaKey& ca_key,
                                std::string_view subject);

// CMS SignedData with no signers around `content`: structurally what a
// .mobileprovision file is, minus Apple's signature.
crypto::Bytes wrap_in_cms(crypto::ByteView content);

// True if the PKCS#10 request carries a valid self-signature.
bool csr_signature_valid(std::string_view csr_pem);

// A structurally valid arm64 Mach-O executable filled with noise: enough for
// the signer and for anything that only moves binaries around.
crypto::Bytes simple_macho();

// PKCS#8 "PRIVATE KEY" PEM of a key created with exportable = true.
std::string export_private_key_pem(const auth::RsaKey& key);
// The same key re-wrapped as a PKCS#1 "RSA PRIVATE KEY" block, the form older
// pairing records use.
std::string to_pkcs1_pem(std::string_view pkcs8_pem);

}  // namespace winx::test
