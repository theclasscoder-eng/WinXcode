#pragma once

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include "winx/crypto.hpp"
#include "winx/keys.hpp"

// Signing identities: an Apple Development certificate plus the CNG private
// key it was issued for.
namespace winx::auth {

struct CertificateInfo {
    std::string common_name;
    std::string organizational_unit;  // the team ID on Apple certificates
    std::string organization;
    std::string serial_hex;  // uppercase, as App Store Connect reports it
    std::string sha1_hex;    // uppercase thumbprint of the DER encoding
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
};

CertificateInfo describe_certificate(crypto::ByteView der);

// PKCS#10 request signed with SHA-256/RSA, PEM encoded.
std::string make_csr_pem(const RsaKey& key, std::string_view common_name);

// For tests and offline experiments. `subject` is an X.500 string such as
// "CN=Test, OU=TEAM123456".
crypto::Bytes make_self_signed_certificate(const RsaKey& key, std::string_view subject,
                                           int valid_days = 365);

bool certificate_matches_key(crypto::ByteView certificate_der, const RsaKey& key);

class SigningIdentity {
public:
    SigningIdentity(crypto::Bytes certificate_der, RsaKey key);

    const crypto::Bytes& certificate() const noexcept { return certificate_; }
    const CertificateInfo& info() const noexcept { return info_; }
    const RsaKey& key() const noexcept { return key_; }

private:
    crypto::Bytes certificate_;
    CertificateInfo info_;
    RsaKey key_;
};

// Keeps one identity per account. The private key stays in CNG under a name
// derived from the account; the certificate and its Apple resource ID are
// written to `directory`.
class IdentityStore {
public:
    explicit IdentityStore(std::filesystem::path directory);

    struct Pending {
        std::wstring key_name;
        std::string csr_pem;
    };
    struct Stored {
        SigningIdentity identity;
        std::string remote_id;
    };

    // Creates a fresh key for the account and returns a CSR for it.
    Pending begin(std::string_view account);
    // Stores the certificate Apple issued for a pending key.
    SigningIdentity complete(std::string_view account, const Pending& pending,
                             crypto::ByteView certificate_der, std::string_view remote_id);
    std::optional<Stored> load(std::string_view account) const;
    void remove(std::string_view account);

private:
    std::filesystem::path record_path(std::string_view account) const;
    std::filesystem::path directory_;
};

}  // namespace winx::auth
