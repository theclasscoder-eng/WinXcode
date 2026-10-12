#include "winx/keys.hpp"

#include <windows.h>

#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <format>
#include <memory>

#include <nlohmann/json.hpp>

#include "winx/base64.hpp"
#include "winx/files.hpp"

namespace winx::auth {
namespace {

void check(SECURITY_STATUS status, const char* what) {
    if (status != ERROR_SUCCESS) {
        throw KeyError(std::format("{} failed (0x{:08X})", what, static_cast<unsigned>(status)));
    }
}

class StorageProvider {
public:
    StorageProvider() {
        check(NCryptOpenStorageProvider(&handle_, MS_KEY_STORAGE_PROVIDER, 0),
              "NCryptOpenStorageProvider");
    }
    ~StorageProvider() { NCryptFreeObject(handle_); }
    StorageProvider(const StorageProvider&) = delete;
    StorageProvider& operator=(const StorageProvider&) = delete;
    NCRYPT_PROV_HANDLE get() const { return handle_; }

private:
    NCRYPT_PROV_HANDLE handle_ = 0;
};

struct LocalFreeDeleter {
    void operator()(void* pointer) const { LocalFree(pointer); }
};

template <class T>
std::unique_ptr<T, LocalFreeDeleter> decode_object(LPCSTR type, const BYTE* data, DWORD size,
                                                   const char* what) {
    T* decoded = nullptr;
    DWORD decoded_size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, type, data, size, CRYPT_DECODE_ALLOC_FLAG, nullptr,
                             &decoded, &decoded_size)) {
        throw KeyError(std::format("cannot decode {}", what));
    }
    return std::unique_ptr<T, LocalFreeDeleter>(decoded);
}

std::uintptr_t open_key(std::wstring_view name) {
    const StorageProvider provider;
    NCRYPT_KEY_HANDLE key = 0;
    const std::wstring name_text(name);
    const SECURITY_STATUS status = NCryptOpenKey(provider.get(), &key, name_text.c_str(), 0, 0);
    if (status == NTE_BAD_KEYSET) throw KeyError("the stored key no longer exists");
    check(status, "NCryptOpenKey");
    return key;
}

bool remove_key(std::wstring_view name) {
    const StorageProvider provider;
    NCRYPT_KEY_HANDLE key = 0;
    const std::wstring name_text(name);
    if (NCryptOpenKey(provider.get(), &key, name_text.c_str(), 0, 0) != ERROR_SUCCESS) return false;
    // NCryptDeleteKey frees the handle on success.
    if (NCryptDeleteKey(key, 0) != ERROR_SUCCESS) {
        NCryptFreeObject(key);
        return false;
    }
    return true;
}

}  // namespace

EcSigningKey EcSigningKey::import_p8(std::string_view pem, std::wstring_view persist_name) {
    const auto der = pem_decode(pem, "PRIVATE KEY");
    if (!der) throw KeyError("the .p8 file does not contain a PRIVATE KEY block");

    const auto info = decode_object<CRYPT_PRIVATE_KEY_INFO>(
        PKCS_PRIVATE_KEY_INFO, der->data(), static_cast<DWORD>(der->size()), "PKCS#8 key");
    if (std::string_view(info->Algorithm.pszObjId) != szOID_ECC_PUBLIC_KEY) {
        throw KeyError("the .p8 key is not an elliptic-curve key");
    }
    const auto ec = decode_object<CRYPT_ECC_PRIVATE_KEY_INFO>(
        X509_ECC_PRIVATE_KEY, info->PrivateKey.pbData, info->PrivateKey.cbData, "EC private key");

    constexpr std::size_t kCoordinate = 32;
    if (ec->PrivateKey.cbData == 0 || ec->PrivateKey.cbData > kCoordinate) {
        throw KeyError("the .p8 key is not a P-256 key");
    }
    if (ec->PublicKey.cbData != 1 + 2 * kCoordinate || ec->PublicKey.pbData[0] != 0x04) {
        throw KeyError("the .p8 key does not carry an uncompressed P-256 public key");
    }

    // BCRYPT_ECCKEY_BLOB followed by X, Y and the private scalar.
    crypto::Bytes blob(sizeof(BCRYPT_ECCKEY_BLOB) + 3 * kCoordinate, 0);
    auto* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
    header->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
    header->cbKey = static_cast<ULONG>(kCoordinate);
    BYTE* cursor = blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
    std::copy_n(ec->PublicKey.pbData + 1, 2 * kCoordinate, cursor);
    cursor += 2 * kCoordinate;
    // Left-pad the scalar in case leading zero bytes were dropped.
    std::copy_n(ec->PrivateKey.pbData, ec->PrivateKey.cbData,
                cursor + (kCoordinate - ec->PrivateKey.cbData));

    const StorageProvider provider;
    const std::wstring name(persist_name);
    NCRYPT_KEY_HANDLE key = 0;
    check(NCryptCreatePersistedKey(provider.get(), &key, NCRYPT_ECDSA_P256_ALGORITHM,
                                   name.empty() ? nullptr : name.c_str(), 0,
                                   name.empty() ? 0 : NCRYPT_OVERWRITE_KEY_FLAG),
          "NCryptCreatePersistedKey");
    SECURITY_STATUS status = NCryptSetProperty(key, BCRYPT_ECCPRIVATE_BLOB, blob.data(),
                                               static_cast<DWORD>(blob.size()), 0);
    if (status == ERROR_SUCCESS) status = NCryptFinalizeKey(key, 0);
    SecureZeroMemory(blob.data(), blob.size());
    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(key);
        check(status, "importing the .p8 key");
    }
    return EcSigningKey(key);
}

EcSigningKey EcSigningKey::open(std::wstring_view name) { return EcSigningKey(open_key(name)); }

bool EcSigningKey::remove(std::wstring_view name) { return remove_key(name); }

EcSigningKey::EcSigningKey(EcSigningKey&& other) noexcept
    : handle_(std::exchange(other.handle_, 0)) {}

EcSigningKey& EcSigningKey::operator=(EcSigningKey&& other) noexcept {
    if (this != &other) {
        if (handle_) NCryptFreeObject(handle_);
        handle_ = std::exchange(other.handle_, 0);
    }
    return *this;
}

EcSigningKey::~EcSigningKey() {
    if (handle_) NCryptFreeObject(handle_);
}

crypto::Bytes EcSigningKey::sign(crypto::ByteView message) const {
    crypto::Bytes hash = crypto::sha256(message);
    crypto::Bytes signature(64);
    DWORD written = 0;
    check(NCryptSignHash(handle_, nullptr, hash.data(), static_cast<DWORD>(hash.size()),
                         signature.data(), static_cast<DWORD>(signature.size()), &written, 0),
          "NCryptSignHash");
    signature.resize(written);
    return signature;
}

bool EcSigningKey::verify(crypto::ByteView message, crypto::ByteView signature) const {
    crypto::Bytes hash = crypto::sha256(message);
    return NCryptVerifySignature(handle_, nullptr, hash.data(), static_cast<DWORD>(hash.size()),
                                 const_cast<PBYTE>(signature.data()),
                                 static_cast<DWORD>(signature.size()), 0) == ERROR_SUCCESS;
}

RsaKey RsaKey::create(std::wstring_view persist_name, bool exportable) {
    const StorageProvider provider;
    std::wstring name(persist_name);
    NCRYPT_KEY_HANDLE key = 0;
    check(NCryptCreatePersistedKey(provider.get(), &key, NCRYPT_RSA_ALGORITHM,
                                   name.empty() ? nullptr : name.c_str(), 0,
                                   name.empty() ? 0 : NCRYPT_OVERWRITE_KEY_FLAG),
          "NCryptCreatePersistedKey");
    DWORD bits = 2048;
    DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
    DWORD policy = exportable ? NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG : 0;
    SECURITY_STATUS status = NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY,
                                               reinterpret_cast<PBYTE>(&bits), sizeof(bits), 0);
    if (status == ERROR_SUCCESS) {
        status = NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&usage),
                                   sizeof(usage), 0);
    }
    if (status == ERROR_SUCCESS) {
        status = NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY,
                                   reinterpret_cast<PBYTE>(&policy), sizeof(policy), 0);
    }
    if (status == ERROR_SUCCESS) status = NCryptFinalizeKey(key, 0);
    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(key);
        check(status, "creating the RSA key");
    }
    return RsaKey(key, std::move(name));
}

RsaKey RsaKey::open(std::wstring_view name) { return RsaKey(open_key(name), std::wstring(name)); }

bool RsaKey::remove(std::wstring_view name) { return remove_key(name); }

RsaKey::RsaKey(RsaKey&& other) noexcept
    : handle_(std::exchange(other.handle_, 0)), name_(std::move(other.name_)) {}

RsaKey& RsaKey::operator=(RsaKey&& other) noexcept {
    if (this != &other) {
        if (handle_) NCryptFreeObject(handle_);
        handle_ = std::exchange(other.handle_, 0);
        name_ = std::move(other.name_);
    }
    return *this;
}

RsaKey::~RsaKey() {
    if (handle_) NCryptFreeObject(handle_);
}

crypto::Bytes RsaKey::public_key_info() const {
    DWORD size = 0;
    char rsa_oid[] = szOID_RSA_RSA;
    if (!CryptExportPublicKeyInfoEx(handle_, 0, X509_ASN_ENCODING, rsa_oid, 0, nullptr, nullptr,
                                    &size)) {
        throw KeyError("cannot export the public key");
    }
    crypto::Bytes buffer(size);
    auto* info = reinterpret_cast<CERT_PUBLIC_KEY_INFO*>(buffer.data());
    if (!CryptExportPublicKeyInfoEx(handle_, 0, X509_ASN_ENCODING, rsa_oid, 0, nullptr, info,
                                    &size)) {
        throw KeyError("cannot export the public key");
    }
    DWORD encoded_size = 0;
    BYTE* encoded = nullptr;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, info, CRYPT_ENCODE_ALLOC_FLAG,
                             nullptr, &encoded, &encoded_size)) {
        throw KeyError("cannot encode the public key");
    }
    crypto::Bytes der(encoded, encoded + encoded_size);
    LocalFree(encoded);
    return der;
}

std::string base64url_encode(crypto::ByteView data) {
    std::string text = base64_encode(data);
    while (!text.empty() && text.back() == '=') text.pop_back();
    std::replace(text.begin(), text.end(), '+', '-');
    std::replace(text.begin(), text.end(), '/', '_');
    return text;
}

std::optional<crypto::Bytes> base64url_decode(std::string_view text) {
    std::string standard(text);
    std::replace(standard.begin(), standard.end(), '-', '+');
    std::replace(standard.begin(), standard.end(), '_', '/');
    return base64_decode(standard);
}

std::string make_asc_token(const EcSigningKey& key, std::string_view key_id,
                           std::string_view issuer_id, std::chrono::system_clock::time_point now,
                           std::chrono::seconds lifetime) {
    using nlohmann::json;
    const auto issued =
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    const json header = {{"alg", "ES256"}, {"kid", key_id}, {"typ", "JWT"}};
    const json claims = {{"iss", issuer_id},
                         {"iat", issued},
                         {"exp", issued + lifetime.count()},
                         {"aud", "appstoreconnect-v1"}};
    const std::string signing_input = base64url_encode(crypto::as_bytes(header.dump())) + "." +
                                      base64url_encode(crypto::as_bytes(claims.dump()));
    const crypto::Bytes signature = key.sign(crypto::as_bytes(signing_input));
    return signing_input + "." + base64url_encode(signature);
}

}  // namespace winx::auth
