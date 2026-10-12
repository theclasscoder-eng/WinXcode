#include "winx/tls.hpp"

#define SECURITY_WIN32
#include <windows.h>

#include <ncrypt.h>
#include <schannel.h>
#include <security.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <format>

#include "winx/files.hpp"

namespace winx::device {
namespace {

constexpr std::size_t kReadChunk = 16 * 1024;

std::string status_text(SECURITY_STATUS status) {
    switch (status) {
        case SEC_E_UNTRUSTED_ROOT: return "the peer's certificate chain is not trusted";
        case SEC_E_CERT_UNKNOWN: return "the peer rejected or sent an unusable certificate";
        case SEC_E_ILLEGAL_MESSAGE: return "the peer sent a malformed TLS message";
        case SEC_E_ALGORITHM_MISMATCH: return "no cipher suite or protocol version in common";
        case SEC_E_NO_CREDENTIALS: return "the private key for the certificate is not usable";
        case SEC_E_UNKNOWN_CREDENTIALS: return "the certificate has no usable private key";
        case SEC_E_INTERNAL_ERROR: return "SChannel internal error";
        case SEC_E_DECRYPT_FAILURE: return "a TLS record failed to decrypt";
        case SEC_E_WRONG_PRINCIPAL: return "the certificate does not match the server name";
        default: return "SChannel error";
    }
}

[[noreturn]] void fail(const char* what, SECURITY_STATUS status) {
    throw TlsError(std::format("{}: {} (0x{:08X})", what, status_text(status),
                               static_cast<unsigned>(status)));
}

bool same_bytes(const crypto::Bytes& a, const crypto::Bytes& b) { return a == b; }

bool signed_by(PCCERT_CONTEXT child, const crypto::Bytes& issuer_der) {
    PCCERT_CONTEXT issuer = CertCreateCertificateContext(X509_ASN_ENCODING, issuer_der.data(),
                                                         static_cast<DWORD>(issuer_der.size()));
    if (!issuer) return false;
    const bool ok = CryptVerifyCertificateSignatureEx(
                        0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
                        const_cast<void*>(static_cast<const void*>(child)),
                        CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
                        const_cast<void*>(static_cast<const void*>(issuer)), 0, nullptr) != FALSE;
    CertFreeCertificateContext(issuer);
    return ok;
}

}  // namespace

void import_rsa_private_key(std::string_view pem, std::wstring_view key_name) {
    crypto::Bytes pkcs1;
    for (PemBlock& block : pem_decode_all(pem)) {
        if (block.label == "RSA PRIVATE KEY") {
            pkcs1 = std::move(block.der);
            break;
        }
        if (block.label == "PRIVATE KEY") {
            CRYPT_PRIVATE_KEY_INFO* info = nullptr;
            DWORD size = 0;
            if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, block.der.data(),
                                     static_cast<DWORD>(block.der.size()), CRYPT_DECODE_ALLOC_FLAG,
                                     nullptr, &info, &size)) {
                throw TlsError("the private key is not valid PKCS#8");
            }
            pkcs1.assign(info->PrivateKey.pbData, info->PrivateKey.pbData + info->PrivateKey.cbData);
            SecureZeroMemory(info, size);
            LocalFree(info);
            break;
        }
    }
    if (pkcs1.empty()) throw TlsError("no RSA private key found in the PEM data");

    BYTE* blob = nullptr;
    DWORD blob_size = 0;
    const BOOL decoded =
        CryptDecodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PRIVATE_KEY_BLOB, pkcs1.data(),
                            static_cast<DWORD>(pkcs1.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr,
                            &blob, &blob_size);
    SecureZeroMemory(pkcs1.data(), pkcs1.size());
    if (!decoded) throw TlsError("the private key is not a valid RSA key");

    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    const std::wstring name(key_name);
    SECURITY_STATUS status = NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0);
    if (status == ERROR_SUCCESS) {
        status = NCryptCreatePersistedKey(provider, &key, NCRYPT_RSA_ALGORITHM, name.c_str(), 0,
                                          NCRYPT_OVERWRITE_KEY_FLAG);
    }
    if (status == ERROR_SUCCESS) {
        status = NCryptSetProperty(key, BCRYPT_RSAPRIVATE_BLOB, blob, blob_size, 0);
    }
    if (status == ERROR_SUCCESS) {
        DWORD usage = NCRYPT_ALLOW_ALL_USAGES;
        status = NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&usage),
                                   sizeof(usage), 0);
    }
    if (status == ERROR_SUCCESS) status = NCryptFinalizeKey(key, 0);
    SecureZeroMemory(blob, blob_size);
    LocalFree(blob);
    if (key) NCryptFreeObject(key);
    if (provider) NCryptFreeObject(provider);
    if (status != ERROR_SUCCESS) {
        throw TlsError(std::format("cannot import the private key (0x{:08X})",
                                   static_cast<unsigned>(status)));
    }
}

bool remove_private_key(std::wstring_view key_name) {
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    const std::wstring name(key_name);
    bool removed = false;
    if (NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS) {
        if (NCryptOpenKey(provider, &key, name.c_str(), 0, 0) == ERROR_SUCCESS) {
            removed = NCryptDeleteKey(key, 0) == ERROR_SUCCESS;
            if (!removed) NCryptFreeObject(key);
        }
        NCryptFreeObject(provider);
    }
    return removed;
}

crypto::Bytes certificate_from_pem(std::string_view pem) {
    auto der = pem_decode(pem, "CERTIFICATE");
    if (!der) throw TlsError("no certificate found in the PEM data");
    return std::move(*der);
}

struct TlsStream::Impl {
    std::unique_ptr<net::Stream> transport;
    CredHandle credentials{};
    bool have_credentials = false;
    CtxtHandle context{};
    bool have_context = false;
    PCCERT_CONTEXT certificate = nullptr;
    SecPkgContext_StreamSizes sizes{};
    crypto::Bytes incoming;   // ciphertext not yet decrypted
    crypto::Bytes plaintext;  // decrypted, not yet handed out
    std::size_t plaintext_offset = 0;
    crypto::Bytes peer_certificate;
    bool closed = false;

    ~Impl() {
        if (have_context) DeleteSecurityContext(&context);
        if (have_credentials) FreeCredentialsHandle(&credentials);
        if (certificate) CertFreeCertificateContext(certificate);
    }

    void read_more() {
        const std::size_t offset = incoming.size();
        incoming.resize(offset + kReadChunk);
        const std::size_t received =
            transport->recv_some(std::span(incoming.data() + offset, kReadChunk));
        incoming.resize(offset + received);
        if (received == 0) throw TlsError("the connection closed during the TLS handshake");
    }

    void acquire_credentials(const TlsOptions& options) {
        SCHANNEL_CRED config{};
        config.dwVersion = SCHANNEL_CRED_VERSION;
        std::wstring key_name;
        std::wstring provider_name = MS_KEY_STORAGE_PROVIDER;
        if (options.identity) {
            certificate = CertCreateCertificateContext(
                X509_ASN_ENCODING, options.identity->certificate.data(),
                static_cast<DWORD>(options.identity->certificate.size()));
            if (!certificate) throw TlsError("the TLS certificate is not valid X.509");
            key_name = options.identity->key_name;
            CRYPT_KEY_PROV_INFO key_info{};
            key_info.pwszContainerName = key_name.data();
            key_info.pwszProvName = provider_name.data();
            key_info.dwProvType = 0;  // CNG
            if (!CertSetCertificateContextProperty(certificate, CERT_KEY_PROV_INFO_PROP_ID, 0,
                                                   &key_info)) {
                throw TlsError("cannot attach the private key to the TLS certificate");
            }
            config.cCreds = 1;
            config.paCred = &certificate;
        }
        if (options.server) {
            config.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;
        } else {
            config.dwFlags = SCH_CRED_NO_DEFAULT_CREDS |
                             (options.system_trust ? SCH_CRED_AUTO_CRED_VALIDATION
                                                   : SCH_CRED_MANUAL_CRED_VALIDATION);
        }
        TimeStamp expiry{};
        wchar_t package[] = UNISP_NAME_W;
        const SECURITY_STATUS status = AcquireCredentialsHandleW(
            nullptr, package, options.server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, nullptr,
            &config, nullptr, nullptr, &credentials, &expiry);
        if (status != SEC_E_OK) fail("cannot set up TLS credentials", status);
        have_credentials = true;
    }

    // Removes the bytes SChannel consumed, keeping any it reported as extra.
    void consume(const SecBuffer& extra) {
        if (extra.BufferType == SECBUFFER_EXTRA && extra.cbBuffer > 0 &&
            extra.cbBuffer <= incoming.size()) {
            incoming.erase(incoming.begin(),
                           incoming.end() - static_cast<std::ptrdiff_t>(extra.cbBuffer));
        } else {
            incoming.clear();
        }
    }

    void send_token(SecBuffer& token) {
        if (token.pvBuffer && token.cbBuffer > 0) {
            transport->send_all(
                std::span(static_cast<const std::uint8_t*>(token.pvBuffer), token.cbBuffer));
        }
        if (token.pvBuffer) FreeContextBuffer(token.pvBuffer);
        token.pvBuffer = nullptr;
    }

    void client_handshake(const TlsOptions& options) {
        DWORD flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                      ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
                      ISC_REQ_USE_SUPPLIED_CREDS;
        if (!options.system_trust) flags |= ISC_REQ_MANUAL_CRED_VALIDATION;
        std::wstring target = options.server_name.empty() ? L"device" : options.server_name;

        bool first = true;
        int credential_retries = 0;
        for (;;) {
            SecBuffer input[2] = {{static_cast<unsigned long>(incoming.size()), SECBUFFER_TOKEN,
                                   incoming.data()},
                                  {0, SECBUFFER_EMPTY, nullptr}};
            SecBufferDesc in_desc{SECBUFFER_VERSION, 2, input};
            SecBuffer output[1] = {{0, SECBUFFER_TOKEN, nullptr}};
            SecBufferDesc out_desc{SECBUFFER_VERSION, 1, output};
            DWORD out_flags = 0;
            const SECURITY_STATUS status = InitializeSecurityContextW(
                &credentials, first ? nullptr : &context, target.data(), flags, 0, 0,
                first ? nullptr : &in_desc, 0, &context, &out_desc, &out_flags, nullptr);
            if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) have_context = true;

            if (status == SEC_E_INCOMPLETE_MESSAGE) {
                read_more();
                continue;
            }
            // The server asked for a certificate and none is configured: offer
            // the same input again, which proceeds without one.
            if (status == SEC_I_INCOMPLETE_CREDENTIALS && ++credential_retries <= 2) continue;
            send_token(output[0]);
            if (!first) consume(input[1]);
            first = false;

            if (status == SEC_E_OK) return;
            if (status == SEC_I_CONTINUE_NEEDED) {
                if (incoming.empty()) read_more();
                continue;
            }
            fail("the TLS handshake failed", status);
        }
    }

    void server_handshake(const TlsOptions& options) {
        DWORD flags = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
                      ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
        if (options.request_client_certificate) flags |= ASC_REQ_MUTUAL_AUTH;

        bool first = true;
        for (;;) {
            if (incoming.empty()) read_more();
            SecBuffer input[2] = {{static_cast<unsigned long>(incoming.size()), SECBUFFER_TOKEN,
                                incoming.data()},
                               {0, SECBUFFER_EMPTY, nullptr}};
            SecBufferDesc in_desc{SECBUFFER_VERSION, 2, input};
            SecBuffer output[1] = {{0, SECBUFFER_TOKEN, nullptr}};
            SecBufferDesc out_desc{SECBUFFER_VERSION, 1, output};
            DWORD out_flags = 0;
            TimeStamp expiry{};
            const SECURITY_STATUS status =
                AcceptSecurityContext(&credentials, first ? nullptr : &context, &in_desc, flags, 0,
                                      &context, &out_desc, &out_flags, &expiry);
            if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) have_context = true;

            if (status == SEC_E_INCOMPLETE_MESSAGE) {
                read_more();
                continue;
            }
            send_token(output[0]);
            consume(input[1]);
            first = false;

            if (status == SEC_E_OK) return;
            if (status == SEC_I_CONTINUE_NEEDED) continue;
            fail("the TLS handshake failed", status);
        }
    }

    void finish_handshake(const TlsOptions& options) {
        SECURITY_STATUS status =
            QueryContextAttributesW(&context, SECPKG_ATTR_STREAM_SIZES, &sizes);
        if (status != SEC_E_OK) fail("cannot query TLS record sizes", status);

        PCCERT_CONTEXT peer = nullptr;
        status = QueryContextAttributesW(&context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer);
        if (status == SEC_E_OK && peer) {
            peer_certificate.assign(peer->pbCertEncoded, peer->pbCertEncoded + peer->cbCertEncoded);
        }

        // With system trust SChannel has already validated the chain and name.
        bool trusted = options.server || options.system_trust;
        if (!trusted && peer) {
            trusted = std::any_of(options.accepted_peers.begin(), options.accepted_peers.end(),
                                  [&](const crypto::Bytes& accepted) {
                                      return same_bytes(accepted, peer_certificate);
                                  }) ||
                      std::any_of(options.accepted_issuers.begin(), options.accepted_issuers.end(),
                                  [&](const crypto::Bytes& issuer) {
                                      return signed_by(peer, issuer);
                                  });
        }
        if (peer) CertFreeCertificateContext(peer);
        if (!trusted) {
            throw TlsError("the peer's TLS certificate is not the one this device was paired with");
        }
    }
};

TlsStream::TlsStream(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

TlsStream::~TlsStream() = default;

std::unique_ptr<TlsStream> TlsStream::handshake(std::unique_ptr<net::Stream> transport,
                                                const TlsOptions& options) {
    if (options.server && !options.identity) throw TlsError("a TLS server needs a certificate");
    auto impl = std::make_unique<Impl>();
    impl->transport = std::move(transport);
    impl->acquire_credentials(options);
    if (options.server) {
        impl->server_handshake(options);
    } else {
        impl->client_handshake(options);
    }
    impl->finish_handshake(options);
    return std::unique_ptr<TlsStream>(new TlsStream(std::move(impl)));
}

const crypto::Bytes& TlsStream::peer_certificate() const noexcept {
    return impl_->peer_certificate;
}

void TlsStream::send_all(std::span<const std::uint8_t> data) {
    Impl& tls = *impl_;
    crypto::Bytes record;
    while (!data.empty()) {
        const std::size_t chunk = std::min<std::size_t>(data.size(), tls.sizes.cbMaximumMessage);
        record.resize(tls.sizes.cbHeader + chunk + tls.sizes.cbTrailer);
        std::copy_n(data.begin(), chunk, record.begin() + tls.sizes.cbHeader);

        SecBuffer buffers[4] = {
            {tls.sizes.cbHeader, SECBUFFER_STREAM_HEADER, record.data()},
            {static_cast<unsigned long>(chunk), SECBUFFER_DATA, record.data() + tls.sizes.cbHeader},
            {tls.sizes.cbTrailer, SECBUFFER_STREAM_TRAILER,
             record.data() + tls.sizes.cbHeader + chunk},
            {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc description{SECBUFFER_VERSION, 4, buffers};
        const SECURITY_STATUS status = EncryptMessage(&tls.context, 0, &description, 0);
        if (status != SEC_E_OK) fail("cannot encrypt a TLS record", status);
        const std::size_t total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        tls.transport->send_all(std::span(record.data(), total));
        data = data.subspan(chunk);
    }
}

std::size_t TlsStream::recv_some(std::span<std::uint8_t> out) {
    Impl& tls = *impl_;
    if (out.empty()) return 0;
    for (;;) {
        if (tls.plaintext_offset < tls.plaintext.size()) {
            const std::size_t count =
                std::min(out.size(), tls.plaintext.size() - tls.plaintext_offset);
            std::copy_n(tls.plaintext.begin() + static_cast<std::ptrdiff_t>(tls.plaintext_offset),
                        count, out.begin());
            tls.plaintext_offset += count;
            if (tls.plaintext_offset == tls.plaintext.size()) {
                tls.plaintext.clear();
                tls.plaintext_offset = 0;
            }
            return count;
        }
        if (tls.closed) return 0;

        if (tls.incoming.empty()) {
            const std::size_t offset = tls.incoming.size();
            tls.incoming.resize(offset + kReadChunk);
            const std::size_t received =
                tls.transport->recv_some(std::span(tls.incoming.data() + offset, kReadChunk));
            tls.incoming.resize(offset + received);
            if (received == 0) {
                tls.closed = true;
                return 0;
            }
        }

        SecBuffer buffers[4] = {
            {static_cast<unsigned long>(tls.incoming.size()), SECBUFFER_DATA, tls.incoming.data()},
            {0, SECBUFFER_EMPTY, nullptr},
            {0, SECBUFFER_EMPTY, nullptr},
            {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc description{SECBUFFER_VERSION, 4, buffers};
        const SECURITY_STATUS status = DecryptMessage(&tls.context, &description, 0, nullptr);

        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            const std::size_t offset = tls.incoming.size();
            tls.incoming.resize(offset + kReadChunk);
            const std::size_t received =
                tls.transport->recv_some(std::span(tls.incoming.data() + offset, kReadChunk));
            tls.incoming.resize(offset + received);
            if (received == 0) {
                tls.closed = true;
                return 0;
            }
            continue;
        }
        if (status == SEC_I_CONTEXT_EXPIRED) {
            tls.closed = true;  // close_notify
            return 0;
        }
        if (status != SEC_E_OK) fail("cannot read from the TLS connection", status);

        const SecBuffer* extra = nullptr;
        for (const SecBuffer& buffer : buffers) {
            if (buffer.BufferType == SECBUFFER_DATA && buffer.cbBuffer > 0) {
                const auto* bytes = static_cast<const std::uint8_t*>(buffer.pvBuffer);
                tls.plaintext.insert(tls.plaintext.end(), bytes, bytes + buffer.cbBuffer);
            } else if (buffer.BufferType == SECBUFFER_EXTRA) {
                extra = &buffer;
            }
        }
        // The decrypted bytes live inside `incoming`, so copy before trimming it.
        if (extra && extra->cbBuffer > 0 && extra->cbBuffer <= tls.incoming.size()) {
            tls.incoming.erase(tls.incoming.begin(),
                               tls.incoming.end() - static_cast<std::ptrdiff_t>(extra->cbBuffer));
        } else {
            tls.incoming.clear();
        }
    }
}

bool TlsStream::wait_readable(std::chrono::milliseconds timeout) {
    Impl& tls = *impl_;
    if (tls.plaintext_offset < tls.plaintext.size() || !tls.incoming.empty() || tls.closed) {
        return true;
    }
    return tls.transport->wait_readable(timeout);
}

}  // namespace winx::device
