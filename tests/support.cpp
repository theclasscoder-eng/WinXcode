#include "support.hpp"

#include <windows.h>

#include <ncrypt.h>
#include <wincrypt.h>

#include <stdexcept>

#include "winx/files.hpp"
#include "winx/text.hpp"

namespace winx::test {
namespace {

crypto::Bytes encode_name(std::string_view subject) {
    const std::wstring wide = to_wide(subject);
    DWORD size = 0;
    CertStrToNameW(X509_ASN_ENCODING, wide.c_str(), CERT_X500_NAME_STR, nullptr, nullptr, &size,
                   nullptr);
    crypto::Bytes name(size);
    if (!CertStrToNameW(X509_ASN_ENCODING, wide.c_str(), CERT_X500_NAME_STR, nullptr, name.data(),
                        &size, nullptr)) {
        throw std::runtime_error("bad subject");
    }
    name.resize(size);
    return name;
}

CERT_REQUEST_INFO* decode_csr(std::string_view csr_pem) {
    const auto der = pem_decode(csr_pem, "CERTIFICATE REQUEST");
    if (!der) throw std::runtime_error("not a CSR");
    CERT_REQUEST_INFO* info = nullptr;
    DWORD size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED, der->data(),
                             static_cast<DWORD>(der->size()), CRYPT_DECODE_ALLOC_FLAG, nullptr,
                             &info, &size)) {
        throw std::runtime_error("cannot decode CSR");
    }
    return info;
}

}  // namespace

TempDir::TempDir(std::string_view name) {
    path_ = std::filesystem::temp_directory_path() /
            to_wide(std::string(name) + "_" + crypto::to_hex(crypto::random_bytes(4)));
    std::filesystem::create_directories(path_);
}

TempDir::~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
}

std::string generate_p8() {
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS ||
        NCryptCreatePersistedKey(provider, &key, NCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0, 0) !=
            ERROR_SUCCESS) {
        throw std::runtime_error("cannot create a test EC key");
    }
    DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&policy),
                      sizeof(policy), 0);
    NCryptFinalizeKey(key, 0);

    DWORD size = 0;
    NCryptExportKey(key, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr, nullptr, 0, &size, 0);
    crypto::Bytes der(size);
    const SECURITY_STATUS status = NCryptExportKey(key, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr,
                                                   der.data(), size, &size, 0);
    NCryptFreeObject(key);
    NCryptFreeObject(provider);
    if (status != ERROR_SUCCESS) throw std::runtime_error("cannot export the test EC key");
    der.resize(size);
    return pem_encode("PRIVATE KEY", der);
}

crypto::Bytes issue_certificate(std::string_view csr_pem, const auth::RsaKey& ca_key,
                                std::string_view subject) {
    CERT_REQUEST_INFO* request = decode_csr(csr_pem);
    crypto::Bytes issuer = encode_name("CN=WinXcode Test CA");
    crypto::Bytes subject_name = encode_name(subject);
    crypto::Bytes serial = crypto::random_bytes(8);
    serial.back() &= 0x7F;  // keep the little-endian integer positive

    CERT_INFO info{};
    info.dwVersion = CERT_V3;
    info.SerialNumber = {static_cast<DWORD>(serial.size()), serial.data()};
    char sha256_rsa[] = szOID_RSA_SHA256RSA;
    info.SignatureAlgorithm.pszObjId = sha256_rsa;
    info.Issuer = {static_cast<DWORD>(issuer.size()), issuer.data()};
    info.Subject = {static_cast<DWORD>(subject_name.size()), subject_name.data()};
    info.SubjectPublicKeyInfo = request->SubjectPublicKeyInfo;

    SYSTEMTIME now{};
    GetSystemTime(&now);
    SystemTimeToFileTime(&now, &info.NotBefore);
    ULARGE_INTEGER end;
    end.LowPart = info.NotBefore.dwLowDateTime;
    end.HighPart = info.NotBefore.dwHighDateTime;
    end.QuadPart += 365ULL * 24 * 3600 * 10000000ULL;
    info.NotAfter = {end.LowPart, end.HighPart};

    CRYPT_ALGORITHM_IDENTIFIER algorithm{};
    algorithm.pszObjId = sha256_rsa;
    DWORD size = 0;
    CryptSignAndEncodeCertificate(ca_key.handle(), 0, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED,
                                  &info, &algorithm, nullptr, nullptr, &size);
    crypto::Bytes der(size);
    const BOOL ok = CryptSignAndEncodeCertificate(ca_key.handle(), 0, X509_ASN_ENCODING,
                                                  X509_CERT_TO_BE_SIGNED, &info, &algorithm,
                                                  nullptr, der.data(), &size);
    LocalFree(request);
    if (!ok) throw std::runtime_error("cannot issue a test certificate");
    der.resize(size);
    return der;
}

crypto::Bytes wrap_in_cms(crypto::ByteView content) {
    CMSG_SIGNED_ENCODE_INFO info{};
    info.cbSize = sizeof(info);
    HCRYPTMSG message = CryptMsgOpenToEncode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                             CMSG_SIGNED, &info, nullptr, nullptr);
    if (!message) throw std::runtime_error("cannot open CMS encoder");
    crypto::Bytes out;
    if (CryptMsgUpdate(message, content.data(), static_cast<DWORD>(content.size()), TRUE)) {
        DWORD size = 0;
        CryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0, nullptr, &size);
        out.resize(size);
        CryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0, out.data(), &size);
        out.resize(size);
    }
    CryptMsgClose(message);
    if (out.empty()) throw std::runtime_error("cannot encode CMS");
    return out;
}

crypto::Bytes simple_macho() {
    crypto::Bytes out;
    const auto u32 = [&](std::uint32_t value) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    };
    const auto u64 = [&](std::uint64_t value) {
        u32(static_cast<std::uint32_t>(value));
        u32(static_cast<std::uint32_t>(value >> 32));
    };
    const auto name = [&](std::string_view text) {
        for (std::size_t i = 0; i < 16; ++i) out.push_back(i < text.size() ? text[i] : 0);
    };
    constexpr std::uint64_t kTextSize = 0x8000;
    constexpr std::uint32_t kSectionOffset = 0x4000;
    constexpr std::uint64_t kLinkeditSize = 0x200;

    u32(0xFEEDFACF);  // MH_MAGIC_64
    u32(0x0100000C);  // arm64
    u32(0);
    u32(2);           // MH_EXECUTE
    u32(2);           // two load commands
    u32(72 + 80 + 72);
    u32(0);
    u32(0);

    u32(0x19);  // LC_SEGMENT_64
    u32(72 + 80);
    name("__TEXT");
    u64(0x100000000);
    u64(kTextSize);
    u64(0);
    u64(kTextSize);
    u32(5);
    u32(5);
    u32(1);
    u32(0);
    name("__text");
    name("__TEXT");
    u64(0x100000000 + kSectionOffset);
    u64(0x1000);
    u32(kSectionOffset);
    u32(2);
    u32(0);
    u32(0);
    u32(0x80000400);
    u32(0);
    u32(0);
    u32(0);

    u32(0x19);
    u32(72);
    name("__LINKEDIT");
    u64(0x100000000 + kTextSize);
    u64(0x4000);
    u64(kTextSize);
    u64(kLinkeditSize);
    u32(1);
    u32(1);
    u32(0);
    u32(0);

    out.resize(kSectionOffset, 0);
    const crypto::Bytes noise = crypto::random_bytes(kTextSize - kSectionOffset + kLinkeditSize);
    out.insert(out.end(), noise.begin(), noise.end());
    return out;
}

std::string export_private_key_pem(const auth::RsaKey& key) {
    DWORD size = 0;
    NCryptExportKey(key.handle(), 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr, nullptr, 0, &size, 0);
    crypto::Bytes der(size);
    if (NCryptExportKey(key.handle(), 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr, der.data(), size,
                        &size, 0) != ERROR_SUCCESS) {
        throw std::runtime_error("cannot export the test RSA key; was it created exportable?");
    }
    der.resize(size);
    return pem_encode("PRIVATE KEY", der);
}

std::string to_pkcs1_pem(std::string_view pkcs8_pem) {
    const auto der = pem_decode(pkcs8_pem, "PRIVATE KEY");
    if (!der) throw std::runtime_error("not a PKCS#8 key");
    CRYPT_PRIVATE_KEY_INFO* info = nullptr;
    DWORD size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, der->data(),
                             static_cast<DWORD>(der->size()), CRYPT_DECODE_ALLOC_FLAG, nullptr,
                             &info, &size)) {
        throw std::runtime_error("cannot decode PKCS#8");
    }
    const crypto::Bytes inner(info->PrivateKey.pbData,
                              info->PrivateKey.pbData + info->PrivateKey.cbData);
    LocalFree(info);
    return pem_encode("RSA PRIVATE KEY", inner);
}

bool csr_signature_valid(std::string_view csr_pem) {
    const auto der = pem_decode(csr_pem, "CERTIFICATE REQUEST");
    if (!der) return false;
    CERT_REQUEST_INFO* request = decode_csr(csr_pem);
    CRYPT_DATA_BLOB blob{static_cast<DWORD>(der->size()), const_cast<BYTE*>(der->data())};
    const BOOL ok = CryptVerifyCertificateSignatureEx(
        0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &blob,
        CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY, &request->SubjectPublicKeyInfo, 0, nullptr);
    LocalFree(request);
    return ok != FALSE;
}

}  // namespace winx::test
