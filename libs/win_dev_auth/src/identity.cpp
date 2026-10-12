#include "winx/identity.hpp"

#include <windows.h>

#include <ncrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "winx/base64.hpp"
#include "winx/files.hpp"
#include "winx/text.hpp"

namespace winx::auth {
namespace {

using nlohmann::json;

class CertContext {
public:
    explicit CertContext(crypto::ByteView der)
        : context_(CertCreateCertificateContext(X509_ASN_ENCODING, der.data(),
                                                static_cast<DWORD>(der.size()))) {
        if (!context_) throw KeyError("not a valid X.509 certificate");
    }
    ~CertContext() { CertFreeCertificateContext(context_); }
    CertContext(const CertContext&) = delete;
    CertContext& operator=(const CertContext&) = delete;
    PCCERT_CONTEXT get() const { return context_; }

private:
    PCCERT_CONTEXT context_;
};

std::string name_attribute(PCCERT_CONTEXT context, const char* oid) {
    const DWORD size = CertGetNameStringW(context, CERT_NAME_ATTR_TYPE, 0,
                                          const_cast<char*>(oid), nullptr, 0);
    if (size <= 1) return {};
    std::wstring text(size, L'\0');
    CertGetNameStringW(context, CERT_NAME_ATTR_TYPE, 0, const_cast<char*>(oid), text.data(), size);
    text.resize(size - 1);
    return to_utf8(text);
}

std::chrono::system_clock::time_point from_filetime(const FILETIME& time) {
    // FILETIME counts 100 ns ticks from 1601-01-01.
    const std::uint64_t ticks = (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) |
                                time.dwLowDateTime;
    constexpr std::uint64_t kUnixEpoch = 116444736000000000ULL;
    const auto seconds = static_cast<std::int64_t>((ticks - kUnixEpoch) / 10000000ULL);
    return std::chrono::system_clock::time_point(std::chrono::seconds(seconds));
}

crypto::Bytes encode_name(std::string_view subject) {
    const std::wstring wide = to_wide(subject);
    DWORD size = 0;
    if (!CertStrToNameW(X509_ASN_ENCODING, wide.c_str(), CERT_X500_NAME_STR, nullptr, nullptr,
                        &size, nullptr)) {
        throw KeyError("invalid certificate subject");
    }
    crypto::Bytes name(size);
    if (!CertStrToNameW(X509_ASN_ENCODING, wide.c_str(), CERT_X500_NAME_STR, nullptr, name.data(),
                        &size, nullptr)) {
        throw KeyError("invalid certificate subject");
    }
    name.resize(size);
    return name;
}

// The key name must be stable per account and safe as a CNG container name.
std::wstring key_name_for(std::string_view account, std::string_view suffix) {
    std::string safe;
    for (const char c : account) {
        const bool keep = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                          (c >= 'A' && c <= 'Z') || c == '-' || c == '.';
        safe += keep ? c : '_';
    }
    return to_wide("WinXcode Signing " + safe + " " + std::string(suffix));
}

}  // namespace

CertificateInfo describe_certificate(crypto::ByteView der) {
    const CertContext context(der);
    CertificateInfo info;
    info.common_name = name_attribute(context.get(), szOID_COMMON_NAME);
    info.organizational_unit = name_attribute(context.get(), szOID_ORGANIZATIONAL_UNIT_NAME);
    info.organization = name_attribute(context.get(), szOID_ORGANIZATION_NAME);

    // CryptoAPI stores the serial number little-endian.
    const CRYPT_INTEGER_BLOB& serial = context.get()->pCertInfo->SerialNumber;
    crypto::Bytes serial_bytes(serial.pbData, serial.pbData + serial.cbData);
    std::reverse(serial_bytes.begin(), serial_bytes.end());
    info.serial_hex = crypto::to_hex(serial_bytes, true);
    info.sha1_hex = crypto::to_hex(crypto::sha1(der), true);
    info.not_before = from_filetime(context.get()->pCertInfo->NotBefore);
    info.not_after = from_filetime(context.get()->pCertInfo->NotAfter);
    return info;
}

std::string make_csr_pem(const RsaKey& key, std::string_view common_name) {
    std::string subject = "CN=\"";
    for (const char c : common_name) {
        if (c == '"') subject += '"';  // X.500 strings double embedded quotes
        subject += c;
    }
    subject += '"';
    crypto::Bytes name = encode_name(subject);

    const crypto::Bytes spki_der = key.public_key_info();
    DWORD spki_size = 0;
    CERT_PUBLIC_KEY_INFO* spki = nullptr;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, spki_der.data(),
                             static_cast<DWORD>(spki_der.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr,
                             &spki, &spki_size)) {
        throw KeyError("cannot decode the public key");
    }

    CERT_REQUEST_INFO request{};
    request.dwVersion = CERT_REQUEST_V1;
    request.Subject.pbData = name.data();
    request.Subject.cbData = static_cast<DWORD>(name.size());
    request.SubjectPublicKeyInfo = *spki;

    CRYPT_ALGORITHM_IDENTIFIER algorithm{};
    char sha256_rsa[] = szOID_RSA_SHA256RSA;
    algorithm.pszObjId = sha256_rsa;

    DWORD size = 0;
    BOOL ok = CryptSignAndEncodeCertificate(key.handle(), 0, X509_ASN_ENCODING,
                                            X509_CERT_REQUEST_TO_BE_SIGNED, &request, &algorithm,
                                            nullptr, nullptr, &size);
    crypto::Bytes der(size);
    if (ok) {
        ok = CryptSignAndEncodeCertificate(key.handle(), 0, X509_ASN_ENCODING,
                                           X509_CERT_REQUEST_TO_BE_SIGNED, &request, &algorithm,
                                           nullptr, der.data(), &size);
    }
    LocalFree(spki);
    if (!ok) throw KeyError("cannot sign the certificate request");
    der.resize(size);
    return pem_encode("CERTIFICATE REQUEST", der);
}

crypto::Bytes make_self_signed_certificate(const RsaKey& key, std::string_view subject,
                                           int valid_days) {
    // Built by hand rather than with CertCreateSelfSignCertificate, which
    // blocks when handed an unnamed CNG key.
    crypto::Bytes name = encode_name(subject);
    const crypto::Bytes spki_der = key.public_key_info();
    DWORD spki_size = 0;
    CERT_PUBLIC_KEY_INFO* spki = nullptr;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, spki_der.data(),
                             static_cast<DWORD>(spki_der.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr,
                             &spki, &spki_size)) {
        throw KeyError("cannot decode the public key");
    }
    crypto::Bytes serial = crypto::random_bytes(8);
    serial.back() &= 0x7F;  // little-endian; keep the integer positive

    CERT_INFO info{};
    info.dwVersion = CERT_V3;
    info.SerialNumber = {static_cast<DWORD>(serial.size()), serial.data()};
    char sha256_rsa[] = szOID_RSA_SHA256RSA;
    info.SignatureAlgorithm.pszObjId = sha256_rsa;
    info.Issuer = {static_cast<DWORD>(name.size()), name.data()};
    info.Subject = info.Issuer;
    info.SubjectPublicKeyInfo = *spki;

    SYSTEMTIME now{};
    GetSystemTime(&now);
    SystemTimeToFileTime(&now, &info.NotBefore);
    ULARGE_INTEGER end;
    end.LowPart = info.NotBefore.dwLowDateTime;
    end.HighPart = info.NotBefore.dwHighDateTime;
    end.QuadPart += static_cast<ULONGLONG>(valid_days) * 24 * 3600 * 10000000ULL;
    info.NotAfter = {end.LowPart, end.HighPart};

    CRYPT_ALGORITHM_IDENTIFIER algorithm{};
    algorithm.pszObjId = sha256_rsa;
    DWORD size = 0;
    BOOL ok = CryptSignAndEncodeCertificate(key.handle(), 0, X509_ASN_ENCODING,
                                            X509_CERT_TO_BE_SIGNED, &info, &algorithm, nullptr,
                                            nullptr, &size);
    crypto::Bytes der(size);
    if (ok) {
        ok = CryptSignAndEncodeCertificate(key.handle(), 0, X509_ASN_ENCODING,
                                           X509_CERT_TO_BE_SIGNED, &info, &algorithm, nullptr,
                                           der.data(), &size);
    }
    LocalFree(spki);
    if (!ok) throw KeyError("cannot create a self-signed certificate");
    der.resize(size);
    return der;
}

bool certificate_matches_key(crypto::ByteView certificate_der, const RsaKey& key) {
    const CertContext context(certificate_der);
    const crypto::Bytes spki_der = key.public_key_info();
    DWORD size = 0;
    CERT_PUBLIC_KEY_INFO* spki = nullptr;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, spki_der.data(),
                             static_cast<DWORD>(spki_der.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr,
                             &spki, &size)) {
        return false;
    }
    const bool same = CertComparePublicKeyInfo(
                          X509_ASN_ENCODING, &context.get()->pCertInfo->SubjectPublicKeyInfo,
                          spki) != FALSE;
    LocalFree(spki);
    return same;
}

SigningIdentity::SigningIdentity(crypto::Bytes certificate_der, RsaKey key)
    : certificate_(std::move(certificate_der)),
      info_(describe_certificate(certificate_)),
      key_(std::move(key)) {
    if (!certificate_matches_key(certificate_, key_)) {
        throw KeyError("the certificate was not issued for this private key");
    }
}

IdentityStore::IdentityStore(std::filesystem::path directory) : directory_(std::move(directory)) {}

std::filesystem::path IdentityStore::record_path(std::string_view account) const {
    std::string safe;
    for (const char c : account) {
        const bool keep = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                          (c >= 'A' && c <= 'Z') || c == '-' || c == '.';
        safe += keep ? c : '_';
    }
    return directory_ / to_wide("identity-" + safe + ".json");
}

IdentityStore::Pending IdentityStore::begin(std::string_view account) {
    // A random suffix keeps an in-flight key from clobbering the stored one.
    const std::string suffix = crypto::to_hex(crypto::random_bytes(4));
    Pending pending;
    pending.key_name = key_name_for(account, suffix);
    const RsaKey key = RsaKey::create(pending.key_name);
    pending.csr_pem = make_csr_pem(key, "WinXcode " + std::string(account));
    return pending;
}

SigningIdentity IdentityStore::complete(std::string_view account, const Pending& pending,
                                        crypto::ByteView certificate_der,
                                        std::string_view remote_id) {
    SigningIdentity identity(crypto::Bytes(certificate_der.begin(), certificate_der.end()),
                             RsaKey::open(pending.key_name));
    // Drop the key of any identity this one replaces.
    if (const auto previous = read_text_file(record_path(account))) {
        const json old = json::parse(*previous, nullptr, false);
        if (old.is_object() && old.contains("keyName")) {
            const std::wstring old_key = to_wide(old["keyName"].get<std::string>());
            if (old_key != pending.key_name) RsaKey::remove(old_key);
        }
    }
    const json record = {{"keyName", to_utf8(pending.key_name)},
                         {"certificate", base64_encode(certificate_der)},
                         {"remoteId", remote_id}};
    write_text_file(record_path(account), record.dump(2));
    return identity;
}

std::optional<IdentityStore::Stored> IdentityStore::load(std::string_view account) const {
    const auto text = read_text_file(record_path(account));
    if (!text) return std::nullopt;
    const json record = json::parse(*text, nullptr, false);
    if (!record.is_object() || !record.contains("keyName") || !record.contains("certificate")) {
        return std::nullopt;
    }
    auto certificate = base64_decode(record["certificate"].get<std::string>());
    if (!certificate) return std::nullopt;
    try {
        SigningIdentity identity(std::move(*certificate),
                                 RsaKey::open(to_wide(record["keyName"].get<std::string>())));
        return Stored{std::move(identity), record.value("remoteId", std::string{})};
    } catch (const KeyError&) {
        // The key was deleted outside WinXcode; the record is no longer usable.
        return std::nullopt;
    }
}

void IdentityStore::remove(std::string_view account) {
    const auto path = record_path(account);
    if (const auto text = read_text_file(path)) {
        const json record = json::parse(*text, nullptr, false);
        if (record.is_object() && record.contains("keyName")) {
            RsaKey::remove(to_wide(record["keyName"].get<std::string>()));
        }
    }
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

}  // namespace winx::auth
