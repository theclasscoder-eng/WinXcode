#include "winx/apple_id.hpp"

#include <windows.h>

#include <wincrypt.h>

#include "winx/files.hpp"

namespace winx::auth {
namespace {

// SHA-256 of Apple Root CA (CN=Apple Root CA, valid to 2035-02-09), as
// published at https://www.apple.com/certificateauthority/.
constexpr std::string_view kAppleRootSha256 =
    "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024";
constexpr const char* kRootUrl = "https://www.apple.com/appleca/AppleIncRootCertificate.cer";
constexpr const char* kWwdrUrl = "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer";

bool signed_by(crypto::ByteView child_der, crypto::ByteView issuer_der) {
    PCCERT_CONTEXT child = CertCreateCertificateContext(X509_ASN_ENCODING, child_der.data(),
                                                        static_cast<DWORD>(child_der.size()));
    PCCERT_CONTEXT issuer = CertCreateCertificateContext(X509_ASN_ENCODING, issuer_der.data(),
                                                         static_cast<DWORD>(issuer_der.size()));
    bool ok = false;
    if (child && issuer) {
        ok = CryptVerifyCertificateSignatureEx(
                 0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
                 const_cast<void*>(static_cast<const void*>(child)),
                 CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
                 const_cast<void*>(static_cast<const void*>(issuer)), 0, nullptr) != FALSE;
    }
    if (child) CertFreeCertificateContext(child);
    if (issuer) CertFreeCertificateContext(issuer);
    return ok;
}

template <class Validator>
crypto::Bytes cached_or_download(const http::Sender& sender, const std::filesystem::path& file,
                                 const char* url, Validator valid, const char* what) {
    if (auto cached = read_file(file); cached && valid(*cached)) return std::move(*cached);

    http::Request request;
    request.url = url;
    const http::Response response = sender(request);
    if (!response.ok()) {
        throw AppleIdError(std::string("cannot download ") + what + " from apple.com");
    }
    crypto::Bytes der(response.body.begin(), response.body.end());
    if (!valid(der)) {
        throw AppleIdError(std::string("the downloaded ") + what +
                           " failed verification and was discarded");
    }
    write_file(file, der);
    return der;
}

}  // namespace

bool is_apple_root_ca(crypto::ByteView der) {
    return crypto::to_hex(crypto::sha256(der)) == kAppleRootSha256;
}

AppleCertificates load_apple_certificates(const http::Sender& sender,
                                          const std::filesystem::path& cache_dir) {
    AppleCertificates certificates;
    certificates.root = cached_or_download(
        sender, cache_dir / L"AppleRootCA.cer", kRootUrl,
        [](const crypto::Bytes& der) { return is_apple_root_ca(der); }, "Apple Root CA");
    certificates.wwdr_g3 = cached_or_download(
        sender, cache_dir / L"AppleWWDRCAG3.cer", kWwdrUrl,
        [&](const crypto::Bytes& der) { return signed_by(der, certificates.root); },
        "Apple WWDR intermediate certificate");
    return certificates;
}

std::string_view apple_id_warning() {
    return "Signing in with an Apple ID and password\n"
           "\n"
           "  * This uses the sign-in protocol that Xcode uses, reconstructed by third parties.\n"
           "    Apple does not document or sanction it. Apple may flag, lock or restrict an\n"
           "    account that signs in this way. Consider using a secondary Apple ID.\n"
           "  * Machine-identity headers (\"anisette\") are obtained from a remote server that\n"
           "    Apple does not run. That server never receives your Apple ID or password, but\n"
           "    it does issue and see the machine identity used for the sign-in.\n"
           "  * Your password is used once to derive a proof and is never stored. The resulting\n"
           "    session token is stored encrypted for your Windows user account.\n"
           "  * Free accounts: profiles expire after 7 days, at most 3 apps per device and 10\n"
           "    new app IDs per week, and no push, iCloud or similar entitlements.\n"
           "  * Requesting a development certificate can require revoking one that Xcode,\n"
           "    AltStore or Sideloadly created, which stops apps signed with it from launching.\n"
           "    WinXcode never revokes a certificate without asking.\n"
           "\n"
           "For Apple's documented path, use an App Store Connect API key instead.\n";
}

std::string_view api_key_warning() {
    return "Using an App Store Connect API key\n"
           "\n"
           "  * The key grants access to your whole developer team with the role it was created\n"
           "    with. It is imported into the Windows key store as non-exportable.\n"
           "  * Registering a device uses one of the team's 100 device slots per product type\n"
           "    for the membership year; slots cannot be freed until renewal.\n"
           "  * WinXcode never revokes a certificate without asking.\n";
}

}  // namespace winx::auth
