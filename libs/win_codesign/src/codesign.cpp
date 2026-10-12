#include "winx/codesign.hpp"

#include <windows.h>

#include <wincrypt.h>

#include <algorithm>
#include <format>

#include "winx/der.hpp"
#include "winx/text.hpp"

namespace winx::codesign {
namespace {

constexpr std::uint32_t kMagicRequirement = 0xFADE0C00;
constexpr std::uint32_t kMagicRequirements = 0xFADE0C01;
constexpr std::uint32_t kMagicCodeDirectory = 0xFADE0C02;
constexpr std::uint32_t kMagicEmbeddedSignature = 0xFADE0CC0;
constexpr std::uint32_t kMagicEntitlements = 0xFADE7171;
constexpr std::uint32_t kMagicDerEntitlements = 0xFADE7172;
constexpr std::uint32_t kMagicBlobWrapper = 0xFADE0B01;

constexpr std::uint32_t kCodeDirectoryVersion = 0x20400;
constexpr std::size_t kCodeDirectoryHeaderSize = 88;
constexpr std::size_t kPageShift = 12;
constexpr std::size_t kPageSize = std::size_t{1} << kPageShift;

constexpr const char* kOidSha1 = "1.3.14.3.2.26";
constexpr const char* kOidSha256 = "2.16.840.1.101.3.4.2.1";
constexpr const char* kOidCdHashesPlist = "1.2.840.113635.100.9.1";
constexpr const char* kOidCdHashes2 = "1.2.840.113635.100.9.2";
// Marks Apple's Worldwide Developer Relations intermediates.
constexpr const char* kOidWwdrIntermediate = "1.2.840.113635.100.6.2.1";

std::size_t align_up(std::size_t value, std::size_t alignment) {
    return (value + alignment - 1) / alignment * alignment;
}

Bytes make_blob(std::uint32_t magic, ByteView payload) {
    Bytes blob;
    blob.reserve(payload.size() + 8);
    append_be32(blob, magic);
    append_be32(blob, static_cast<std::uint32_t>(payload.size() + 8));
    blob.insert(blob.end(), payload.begin(), payload.end());
    return blob;
}

std::uint8_t hash_type_of(crypto::HashAlgorithm algorithm) {
    return algorithm == crypto::HashAlgorithm::Sha1 ? 1 : 2;
}

struct DirectoryInputs {
    std::string identifier;
    std::string team_id;
    std::uint32_t flags = 0;
    std::uint64_t exec_segment_base = 0;
    std::uint64_t exec_segment_limit = 0;
    std::uint64_t exec_segment_flags = 0;
    // Blob contents by special slot number; empty means "not present".
    std::vector<Bytes> special_contents;
};

Bytes build_code_directory(crypto::HashAlgorithm algorithm, ByteView code,
                           const DirectoryInputs& inputs) {
    const std::size_t hash_size = crypto::digest_size(algorithm);
    const std::size_t special_count = inputs.special_contents.size();
    const std::size_t code_count = (code.size() + kPageSize - 1) / kPageSize;

    const std::size_t ident_offset = kCodeDirectoryHeaderSize;
    const std::size_t team_offset =
        inputs.team_id.empty() ? 0 : ident_offset + inputs.identifier.size() + 1;
    const std::size_t strings_end =
        ident_offset + inputs.identifier.size() + 1 +
        (inputs.team_id.empty() ? 0 : inputs.team_id.size() + 1);
    const std::size_t hash_offset = strings_end + special_count * hash_size;
    const std::size_t length = hash_offset + code_count * hash_size;

    Bytes blob;
    blob.reserve(length);
    append_be32(blob, kMagicCodeDirectory);
    append_be32(blob, static_cast<std::uint32_t>(length));
    append_be32(blob, kCodeDirectoryVersion);
    append_be32(blob, inputs.flags);
    append_be32(blob, static_cast<std::uint32_t>(hash_offset));
    append_be32(blob, static_cast<std::uint32_t>(ident_offset));
    append_be32(blob, static_cast<std::uint32_t>(special_count));
    append_be32(blob, static_cast<std::uint32_t>(code_count));
    append_be32(blob, static_cast<std::uint32_t>(code.size()));
    blob.push_back(static_cast<std::uint8_t>(hash_size));
    blob.push_back(hash_type_of(algorithm));
    blob.push_back(0);  // platform
    blob.push_back(static_cast<std::uint8_t>(kPageShift));
    append_be32(blob, 0);  // spare2
    append_be32(blob, 0);  // scatterOffset
    append_be32(blob, static_cast<std::uint32_t>(team_offset));
    append_be32(blob, 0);  // spare3
    append_be64(blob, 0);  // codeLimit64
    append_be64(blob, inputs.exec_segment_base);
    append_be64(blob, inputs.exec_segment_limit);
    append_be64(blob, inputs.exec_segment_flags);

    blob.insert(blob.end(), inputs.identifier.begin(), inputs.identifier.end());
    blob.push_back(0);
    if (!inputs.team_id.empty()) {
        blob.insert(blob.end(), inputs.team_id.begin(), inputs.team_id.end());
        blob.push_back(0);
    }

    // Special slots are stored highest-numbered first, ending at slot 1.
    for (std::size_t slot = special_count; slot >= 1; --slot) {
        const Bytes& content = inputs.special_contents[slot - 1];
        const Bytes hash = content.empty() ? Bytes(hash_size, 0) : crypto::digest(algorithm, content);
        blob.insert(blob.end(), hash.begin(), hash.end());
    }
    for (std::size_t page = 0; page < code_count; ++page) {
        const std::size_t start = page * kPageSize;
        const Bytes hash =
            crypto::digest(algorithm, code.subspan(start, std::min(kPageSize, code.size() - start)));
        blob.insert(blob.end(), hash.begin(), hash.end());
    }
    return blob;
}

// Length-prefixed, zero-padded to a multiple of four.
void append_requirement_data(Bytes& out, ByteView data) {
    append_be32(out, static_cast<std::uint32_t>(data.size()));
    out.insert(out.end(), data.begin(), data.end());
    while (out.size() % 4 != 0) out.push_back(0);
}

void append_requirement_data(Bytes& out, std::string_view text) {
    append_requirement_data(out, crypto::as_bytes(text));
}

struct LocalFreeDeleter {
    void operator()(void* pointer) const { LocalFree(pointer); }
};

Bytes encode_object(LPCSTR type, const void* value, const char* what) {
    BYTE* encoded = nullptr;
    DWORD size = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, type, value, CRYPT_ENCODE_ALLOC_FLAG, nullptr,
                             &encoded, &size)) {
        throw SignError(std::format("cannot encode {}", what));
    }
    Bytes out(encoded, encoded + size);
    LocalFree(encoded);
    return out;
}

struct CdHash {
    crypto::HashAlgorithm algorithm;
    Bytes hash;
};

// CMS SignedData, detached, over the primary CodeDirectory.
Bytes cms_sign(ByteView content, const SigningCredentials& credentials,
               const std::vector<CdHash>& cd_hashes) {
    PCCERT_CONTEXT leaf = CertCreateCertificateContext(
        X509_ASN_ENCODING, credentials.certificate.data(),
        static_cast<DWORD>(credentials.certificate.size()));
    if (!leaf) throw SignError("the signing certificate is not valid X.509");

    // signingTime
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    Bytes signing_time = encode_object(szOID_RSA_signingTime, &now, "the signing time");

    // Apple's CDHash attributes: a plist of 20-byte hashes, and one
    // (algorithm, full hash) pair per CodeDirectory.
    plist::Array truncated;
    std::vector<Bytes> typed_hashes;
    for (const CdHash& entry : cd_hashes) {
        Bytes prefix(entry.hash.begin(), entry.hash.begin() + 20);
        truncated.emplace_back(plist::Data{std::move(prefix)});
        const char* oid = entry.algorithm == crypto::HashAlgorithm::Sha1 ? kOidSha1 : kOidSha256;
        typed_hashes.push_back(
            der::sequence({der::object_identifier(oid), der::octet_string(entry.hash)}));
    }
    // DER requires the members of a SET OF in ascending order.
    std::sort(typed_hashes.begin(), typed_hashes.end());
    const std::string hashes_plist =
        plist::to_xml(plist::Dict{{"cdhashes", std::move(truncated)}});
    Bytes hashes_plist_value = der::octet_string(crypto::as_bytes(hashes_plist));

    CRYPT_ATTR_BLOB time_value{static_cast<DWORD>(signing_time.size()), signing_time.data()};
    CRYPT_ATTR_BLOB plist_value{static_cast<DWORD>(hashes_plist_value.size()),
                                hashes_plist_value.data()};
    std::vector<CRYPT_ATTR_BLOB> typed_values;
    for (Bytes& value : typed_hashes) {
        typed_values.push_back({static_cast<DWORD>(value.size()), value.data()});
    }

    char oid_signing_time[] = szOID_RSA_signingTime;
    std::string oid_plist = kOidCdHashesPlist;
    std::string oid_hashes2 = kOidCdHashes2;
    CRYPT_ATTRIBUTE attributes[3] = {
        {oid_signing_time, 1, &time_value},
        {oid_plist.data(), 1, &plist_value},
        {oid_hashes2.data(), static_cast<DWORD>(typed_values.size()), typed_values.data()},
    };

    CMSG_SIGNER_ENCODE_INFO signer{};
    signer.cbSize = sizeof(signer);
    signer.pCertInfo = leaf->pCertInfo;
    signer.hNCryptKey = credentials.private_key;
    signer.dwKeySpec = CERT_NCRYPT_KEY_SPEC;
    char oid_sha256[] = szOID_NIST_sha256;
    signer.HashAlgorithm.pszObjId = oid_sha256;
    signer.cAuthAttr = 3;
    signer.rgAuthAttr = attributes;

    std::vector<CERT_BLOB> certificates;
    certificates.push_back({static_cast<DWORD>(credentials.certificate.size()),
                            const_cast<BYTE*>(credentials.certificate.data())});
    for (const Bytes& link : credentials.chain) {
        certificates.push_back({static_cast<DWORD>(link.size()), const_cast<BYTE*>(link.data())});
    }

    CMSG_SIGNED_ENCODE_INFO info{};
    info.cbSize = sizeof(info);
    info.cSigners = 1;
    info.rgSigners = &signer;
    info.cCertEncoded = static_cast<DWORD>(certificates.size());
    info.rgCertEncoded = certificates.data();

    Bytes cms;
    HCRYPTMSG message = CryptMsgOpenToEncode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                             CMSG_DETACHED_FLAG, CMSG_SIGNED, &info, nullptr,
                                             nullptr);
    bool ok = message != nullptr;
    if (ok) {
        ok = CryptMsgUpdate(message, content.data(), static_cast<DWORD>(content.size()), TRUE) !=
             FALSE;
        DWORD size = 0;
        ok = ok && CryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0, nullptr, &size);
        if (ok) {
            cms.resize(size);
            ok = CryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0, cms.data(), &size) != FALSE;
            cms.resize(size);
        }
    }
    const DWORD error = GetLastError();
    if (message) CryptMsgClose(message);
    CertFreeCertificateContext(leaf);
    if (!ok) {
        throw SignError("the CMS signature could not be created: " + win32_error_message(error));
    }
    return cms;
}

Bytes encode_der_value(const plist::Value& value) {
    if (const auto* flag = value.get_if<bool>()) return der::boolean(*flag);
    if (const auto* integer = value.get_if<std::int64_t>()) return der::integer(*integer);
    if (const auto* text = value.get_if<std::string>()) return der::utf8_string(*text);
    if (const auto* data = value.get_if<plist::Data>()) return der::octet_string(data->bytes);
    if (const auto* array = value.get_if<plist::Array>()) {
        std::vector<Bytes> items;
        for (const plist::Value& item : *array) items.push_back(encode_der_value(item));
        return der::sequence(items);
    }
    if (const auto* dict = value.get_if<plist::Dict>()) {
        std::vector<const plist::Dict::Item*> sorted;
        for (const auto& item : dict->items()) sorted.push_back(&item);
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto* a, const auto* b) { return a->first < b->first; });
        std::vector<Bytes> entries;
        for (const auto* item : sorted) {
            entries.push_back(
                der::sequence({der::utf8_string(item->first), encode_der_value(item->second)}));
        }
        // Dictionaries are context-specific constructed tag 16.
        return der::encode(0xB0, der::concat(entries));
    }
    throw SignError("entitlements contain a value type that has no DER encoding");
}

Bytes sign_thin(ByteView image, const MachOSignOptions& options,
                const SigningCredentials& credentials) {
    const MachOSlice slice = MachOSlice::parse(image);
    const Segment* linkedit = slice.find_segment("__LINKEDIT");
    const Segment* text = slice.find_segment("__TEXT");
    if (!linkedit || !text) throw SignError("the Mach-O image has no __TEXT or __LINKEDIT segment");

    Bytes out;
    std::size_t code_limit = 0;
    std::size_t command_offset = 0;
    if (slice.signature_command_offset) {
        // Replace the existing signature in place.
        if (static_cast<std::size_t>(slice.signature_offset) + slice.signature_size != image.size()) {
            throw SignError("the existing code signature is not at the end of the image");
        }
        code_limit = slice.signature_offset;
        command_offset = *slice.signature_command_offset;
        out.assign(image.begin(), image.begin() + static_cast<std::ptrdiff_t>(code_limit));
    } else {
        // Append an LC_CODE_SIGNATURE command in the padding after the others.
        command_offset = kMachHeaderSize64 + slice.commands_size;
        if (command_offset + kLinkeditDataCommandSize > slice.first_section_offset) {
            throw SignError(
                "there is no room in the Mach-O header for a code signature load command");
        }
        if (linkedit->file_offset + linkedit->file_size != image.size()) {
            throw SignError("__LINKEDIT is not the last thing in the image");
        }
        out.assign(image.begin(), image.end());
        out.resize(align_up(out.size(), 16), 0);
        code_limit = out.size();
        write_le32(out, command_offset, kLoadCommandCodeSignature);
        write_le32(out, command_offset + 4, static_cast<std::uint32_t>(kLinkeditDataCommandSize));
        write_le32(out, 16, slice.command_count + 1);
        write_le32(out, 20, slice.commands_size + static_cast<std::uint32_t>(kLinkeditDataCommandSize));
    }
    if (code_limit < linkedit->file_offset || code_limit > 0xFFFFFFFFu) {
        throw SignError("the Mach-O image has an unsupported layout");
    }

    // Everything except the CMS blob has a size known up front.
    const Bytes requirements = encode_requirements(options.identifier, credentials);
    Bytes entitlements_blob;
    Bytes der_blob;
    bool get_task_allow = false;
    if (options.entitlements) {
        const std::string xml = plist::to_xml(*options.entitlements);
        entitlements_blob = make_blob(kMagicEntitlements, crypto::as_bytes(xml));
        der_blob = make_blob(kMagicDerEntitlements, encode_der_entitlements(*options.entitlements));
        get_task_allow = options.entitlements->bool_at("get-task-allow").value_or(false);
    }

    DirectoryInputs inputs;
    inputs.identifier = options.identifier;
    inputs.team_id = credentials.team_id;
    inputs.flags = credentials.ad_hoc() ? kCodeDirectoryFlagAdHoc : 0;
    inputs.exec_segment_base = text->file_offset;
    inputs.exec_segment_limit = text->file_size;
    if (slice.file_type == kFileTypeExecute) {
        inputs.exec_segment_flags = kExecSegMainBinary;
        if (get_task_allow) inputs.exec_segment_flags |= kExecSegAllowUnsigned;
    }
    const std::size_t special_count = options.entitlements           ? kSlotDerEntitlements
                                      : !options.code_resources.empty() ? kSlotResourceDirectory
                                                                        : kSlotRequirements;
    inputs.special_contents.assign(special_count, Bytes{});
    inputs.special_contents[kSlotInfoPlist - 1] = options.info_plist;
    inputs.special_contents[kSlotRequirements - 1] = requirements;
    if (special_count >= kSlotResourceDirectory) {
        inputs.special_contents[kSlotResourceDirectory - 1] = options.code_resources;
    }
    if (options.entitlements) {
        inputs.special_contents[kSlotEntitlements - 1] = entitlements_blob;
        inputs.special_contents[kSlotDerEntitlements - 1] = der_blob;
    }

    const std::size_t code_pages = (code_limit + kPageSize - 1) / kPageSize;
    const auto directory_size = [&](std::size_t hash_size) {
        return kCodeDirectoryHeaderSize + inputs.identifier.size() + 1 +
               (inputs.team_id.empty() ? 0 : inputs.team_id.size() + 1) +
               (special_count + code_pages) * hash_size;
    };
    std::size_t cms_reserve = 0;
    if (!credentials.ad_hoc()) {
        cms_reserve = 8 + 2048 + credentials.certificate.size();
        for (const Bytes& link : credentials.chain) cms_reserve += link.size();
    }
    const std::size_t blob_count =
        3 + (options.entitlements ? 2 : 0) + (credentials.ad_hoc() ? 0 : 1);
    const std::size_t signature_size =
        align_up(12 + 8 * blob_count + directory_size(20) + directory_size(32) +
                     requirements.size() + entitlements_blob.size() + der_blob.size() + cms_reserve,
                 16);

    // The load commands are covered by the page hashes, so they must be final
    // before anything is hashed.
    write_le32(out, command_offset + 8, static_cast<std::uint32_t>(code_limit));
    write_le32(out, command_offset + 12, static_cast<std::uint32_t>(signature_size));
    const std::uint64_t linkedit_size = code_limit + signature_size - linkedit->file_offset;
    write_le64(out, linkedit->command_offset + 48, linkedit_size);
    write_le64(out, linkedit->command_offset + 32, align_up(linkedit_size, slice.page_size()));

    const ByteView code(out.data(), code_limit);
    const Bytes sha1_directory = build_code_directory(crypto::HashAlgorithm::Sha1, code, inputs);
    const Bytes sha256_directory =
        build_code_directory(crypto::HashAlgorithm::Sha256, code, inputs);

    struct Entry {
        std::uint32_t slot;
        Bytes blob;
    };
    std::vector<Entry> entries;
    entries.push_back({kSlotCodeDirectory, sha1_directory});
    entries.push_back({kSlotRequirements, requirements});
    if (options.entitlements) {
        entries.push_back({kSlotEntitlements, entitlements_blob});
        entries.push_back({kSlotDerEntitlements, der_blob});
    }
    entries.push_back({kSlotAlternateCodeDirectories, sha256_directory});
    if (!credentials.ad_hoc()) {
        const std::vector<CdHash> hashes = {
            {crypto::HashAlgorithm::Sha1, crypto::sha1(sha1_directory)},
            {crypto::HashAlgorithm::Sha256, crypto::sha256(sha256_directory)}};
        entries.push_back(
            {kSlotCmsSignature, make_blob(kMagicBlobWrapper, cms_sign(sha1_directory, credentials, hashes))});
    }

    Bytes superblob;
    std::size_t offset = 12 + 8 * entries.size();
    std::size_t total = offset;
    for (const Entry& entry : entries) total += entry.blob.size();
    append_be32(superblob, kMagicEmbeddedSignature);
    append_be32(superblob, static_cast<std::uint32_t>(total));
    append_be32(superblob, static_cast<std::uint32_t>(entries.size()));
    for (const Entry& entry : entries) {
        append_be32(superblob, entry.slot);
        append_be32(superblob, static_cast<std::uint32_t>(offset));
        offset += entry.blob.size();
    }
    for (const Entry& entry : entries) {
        superblob.insert(superblob.end(), entry.blob.begin(), entry.blob.end());
    }
    if (superblob.size() > signature_size) {
        throw SignError("the code signature is larger than the space reserved for it");
    }

    out.insert(out.end(), superblob.begin(), superblob.end());
    out.resize(code_limit + signature_size, 0);
    return out;
}

CodeDirectoryInfo parse_code_directory(ByteView blob, std::uint32_t slot) {
    if (blob.size() < 44) throw MachOError("a CodeDirectory is truncated");
    CodeDirectoryInfo info;
    info.slot = slot;
    info.blob.assign(blob.begin(), blob.end());
    info.version = read_be32(blob, 8);
    info.flags = read_be32(blob, 12);
    const std::uint32_t hash_offset = read_be32(blob, 16);
    const std::uint32_t ident_offset = read_be32(blob, 20);
    const std::uint32_t special_count = read_be32(blob, 24);
    const std::uint32_t code_count = read_be32(blob, 28);
    info.code_limit = read_be32(blob, 32);
    info.hash_size = blob[36];
    info.hash_type = blob[37];
    info.page_shift = blob[39];
    std::uint32_t team_offset = 0;
    if (info.version >= 0x20200 && blob.size() >= 56) team_offset = read_be32(blob, 48);
    if (info.version >= 0x20400 && blob.size() >= kCodeDirectoryHeaderSize) {
        info.exec_segment_base = read_be64(blob, 64);
        info.exec_segment_limit = read_be64(blob, 72);
        info.exec_segment_flags = read_be64(blob, 80);
    }

    const auto c_string = [&](std::uint32_t offset) {
        if (offset == 0 || offset >= blob.size()) return std::string{};
        const char* begin = reinterpret_cast<const char*>(blob.data() + offset);
        const char* end = reinterpret_cast<const char*>(blob.data() + blob.size());
        return std::string(begin, std::find(begin, end, '\0'));
    };
    info.identifier = c_string(ident_offset);
    info.team_id = c_string(team_offset);

    const std::size_t hash_size = info.hash_size;
    if (hash_size == 0 || static_cast<std::size_t>(special_count) * hash_size > hash_offset ||
        hash_offset > blob.size() ||
        static_cast<std::size_t>(code_count) > (blob.size() - hash_offset) / hash_size) {
        throw MachOError("a CodeDirectory has inconsistent hash slots");
    }
    for (std::uint32_t slot_number = 1; slot_number <= special_count; ++slot_number) {
        const std::size_t start = hash_offset - static_cast<std::size_t>(slot_number) * hash_size;
        info.special_hashes.emplace_back(blob.begin() + static_cast<std::ptrdiff_t>(start),
                                         blob.begin() + static_cast<std::ptrdiff_t>(start + hash_size));
    }
    for (std::uint32_t page = 0; page < code_count; ++page) {
        const std::size_t start = hash_offset + static_cast<std::size_t>(page) * hash_size;
        info.code_hashes.emplace_back(blob.begin() + static_cast<std::ptrdiff_t>(start),
                                      blob.begin() + static_cast<std::ptrdiff_t>(start + hash_size));
    }
    return info;
}

std::vector<std::string> verify_thin(ByteView image) {
    std::vector<std::string> problems;
    const auto signature = read_signature(image);
    if (!signature) return {"the image is not signed"};
    if (signature->code_directories.empty()) return {"the signature has no CodeDirectory"};

    const MachOSlice slice = MachOSlice::parse(image);
    if (const Segment* linkedit = slice.find_segment("__LINKEDIT")) {
        if (linkedit->file_offset + linkedit->file_size !=
            static_cast<std::uint64_t>(signature->offset) + signature->size) {
            problems.emplace_back("__LINKEDIT does not end where the signature ends");
        }
    }

    for (const CodeDirectoryInfo& directory : signature->code_directories) {
        const std::string label =
            directory.hash_type == 1 ? "SHA-1 CodeDirectory" : "SHA-256 CodeDirectory";
        if (directory.hash_type != 1 && directory.hash_type != 2) {
            problems.push_back("a CodeDirectory uses an unsupported hash type");
            continue;
        }
        if (directory.code_limit != signature->offset) {
            problems.push_back(label + ": the code limit is not the start of the signature");
        }
        const std::size_t page_size = std::size_t{1} << directory.page_shift;
        const std::size_t expected_pages = (directory.code_limit + page_size - 1) / page_size;
        if (directory.code_hashes.size() != expected_pages || directory.code_limit > image.size()) {
            problems.push_back(label + ": wrong number of page hashes");
            continue;
        }
        for (std::size_t page = 0; page < expected_pages; ++page) {
            const std::size_t start = page * page_size;
            const std::size_t length = std::min<std::size_t>(page_size, directory.code_limit - start);
            if (crypto::digest(directory.algorithm(), image.subspan(start, length)) !=
                directory.code_hashes[page]) {
                problems.push_back(std::format("{}: page {} does not match its hash", label, page));
                break;
            }
        }
        const auto check_special = [&](std::uint32_t slot, const Bytes& content, const char* name) {
            const bool sealed = directory.special_hashes.size() >= slot &&
                                std::any_of(directory.special_hashes[slot - 1].begin(),
                                            directory.special_hashes[slot - 1].end(),
                                            [](std::uint8_t b) { return b != 0; });
            if (content.empty()) {
                if (sealed) problems.push_back(std::format("{}: {} is sealed but missing", label, name));
                return;
            }
            if (!sealed || crypto::digest(directory.algorithm(), content) !=
                               directory.special_hashes[slot - 1]) {
                problems.push_back(std::format("{}: {} does not match its hash", label, name));
            }
        };
        check_special(kSlotRequirements, signature->requirements, "the requirements blob");
        check_special(kSlotEntitlements,
                      signature->entitlements.empty()
                          ? Bytes{}
                          : make_blob(kMagicEntitlements, signature->entitlements),
                      "the entitlements blob");
        check_special(kSlotDerEntitlements,
                      signature->der_entitlements.empty()
                          ? Bytes{}
                          : make_blob(kMagicDerEntitlements, signature->der_entitlements),
                      "the DER entitlements blob");
    }

    const CodeDirectoryInfo& primary = signature->code_directories.front();
    const bool ad_hoc = (primary.flags & kCodeDirectoryFlagAdHoc) != 0;
    if (signature->cms.empty()) {
        if (!ad_hoc) problems.emplace_back("the signature has no CMS blob and is not ad hoc");
    } else if (!verify_cms(signature->cms, primary.blob)) {
        problems.emplace_back("the CMS signature does not verify against the CodeDirectory");
    }
    return problems;
}

}  // namespace

crypto::HashAlgorithm CodeDirectoryInfo::algorithm() const {
    return hash_type == 1 ? crypto::HashAlgorithm::Sha1 : crypto::HashAlgorithm::Sha256;
}

Bytes CodeDirectoryInfo::cdhash() const { return crypto::digest(algorithm(), blob); }

Bytes encode_der_entitlements(const plist::Value& entitlements) {
    if (!entitlements.is<plist::Dict>()) throw SignError("entitlements must be a dictionary");
    // [APPLICATION 16] { version INTEGER 1, entitlements }
    return der::encode(0x70, der::concat({der::integer(1), encode_der_value(entitlements)}));
}

Bytes encode_requirements(const std::string& identifier, const SigningCredentials& credentials) {
    Bytes set;
    if (credentials.ad_hoc()) {
        append_be32(set, 0);  // no requirements
        return make_blob(kMagicRequirements, set);
    }

    // identifier "<id>" and anchor apple generic
    //   and certificate leaf[subject.CN] = "<CN>"
    //   and certificate 1[field.1.2.840.113635.100.6.2.1] exists
    constexpr std::uint32_t kOpIdent = 2, kOpAnd = 6, kOpCertField = 11, kOpCertGeneric = 14,
                            kOpAppleGenericAnchor = 15;
    constexpr std::uint32_t kMatchExists = 0, kMatchEqual = 1;
    Bytes expression;
    append_be32(expression, 1);  // expression form
    append_be32(expression, kOpAnd);
    append_be32(expression, kOpAnd);
    append_be32(expression, kOpAnd);
    append_be32(expression, kOpIdent);
    append_requirement_data(expression, identifier);
    append_be32(expression, kOpAppleGenericAnchor);
    append_be32(expression, kOpCertField);
    append_be32(expression, 0);  // leaf certificate
    append_requirement_data(expression, std::string_view("subject.CN"));
    append_be32(expression, kMatchEqual);
    append_requirement_data(expression, credentials.common_name);
    append_be32(expression, kOpCertGeneric);
    append_be32(expression, 1);  // first intermediate
    append_requirement_data(expression, ByteView(der::object_identifier_content(kOidWwdrIntermediate)));
    append_be32(expression, kMatchExists);
    const Bytes requirement = make_blob(kMagicRequirement, expression);

    append_be32(set, 1);   // one requirement
    append_be32(set, 3);   // designated
    append_be32(set, 20);  // offset from the start of the set blob
    set.insert(set.end(), requirement.begin(), requirement.end());
    return make_blob(kMagicRequirements, set);
}

Bytes sign_macho(ByteView image, const MachOSignOptions& options,
                 const SigningCredentials& credentials) {
    if (options.identifier.empty()) throw SignError("a signing identifier is required");
    if (is_thin_macho(image)) return sign_thin(image, options, credentials);
    if (!is_fat_macho(image)) throw SignError("not a Mach-O file");

    // Sign each architecture, then lay the slices out again since their sizes changed.
    std::vector<FatArch> arches = parse_fat(image);
    std::vector<Bytes> slices;
    for (const FatArch& arch : arches) {
        slices.push_back(sign_thin(image.subspan(arch.offset, arch.size), options, credentials));
    }
    std::size_t offset = 8 + arches.size() * 20;
    for (std::size_t i = 0; i < arches.size(); ++i) {
        offset = align_up(offset, std::size_t{1} << arches[i].align);
        arches[i].offset = static_cast<std::uint32_t>(offset);
        arches[i].size = static_cast<std::uint32_t>(slices[i].size());
        offset += slices[i].size();
    }
    Bytes out;
    append_be32(out, kFatMagic);
    append_be32(out, static_cast<std::uint32_t>(arches.size()));
    for (const FatArch& arch : arches) {
        append_be32(out, arch.cpu_type);
        append_be32(out, arch.cpu_subtype);
        append_be32(out, arch.offset);
        append_be32(out, arch.size);
        append_be32(out, arch.align);
    }
    for (std::size_t i = 0; i < arches.size(); ++i) {
        out.resize(arches[i].offset, 0);
        out.insert(out.end(), slices[i].begin(), slices[i].end());
    }
    return out;
}

std::optional<SignatureInfo> read_signature(ByteView thin_image) {
    const MachOSlice slice = MachOSlice::parse(thin_image);
    if (!slice.signature_command_offset) return std::nullopt;
    const ByteView area = thin_image.subspan(slice.signature_offset, slice.signature_size);
    if (area.size() < 12 || read_be32(area, 0) != kMagicEmbeddedSignature) {
        throw MachOError("the code signature is not an embedded signature blob");
    }
    const std::uint32_t length = read_be32(area, 4);
    const std::uint32_t count = read_be32(area, 8);
    if (length > area.size() || count > (length - 12) / 8) {
        throw MachOError("the code signature blob is truncated");
    }

    SignatureInfo info;
    info.offset = slice.signature_offset;
    info.size = slice.signature_size;
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint32_t slot = read_be32(area, 12 + 8 * static_cast<std::size_t>(i));
        const std::uint32_t offset = read_be32(area, 16 + 8 * static_cast<std::size_t>(i));
        if (offset > length || length - offset < 8) throw MachOError("a signature blob is out of range");
        const std::uint32_t blob_length = read_be32(area, offset + 4);
        if (blob_length < 8 || blob_length > length - offset) {
            throw MachOError("a signature blob is out of range");
        }
        const ByteView blob = area.subspan(offset, blob_length);
        const ByteView payload = blob.subspan(8);
        if (slot == kSlotCodeDirectory ||
            (slot >= kSlotAlternateCodeDirectories && slot < kSlotAlternateCodeDirectories + 5)) {
            info.code_directories.push_back(parse_code_directory(blob, slot));
        } else if (slot == kSlotRequirements) {
            info.requirements.assign(blob.begin(), blob.end());
        } else if (slot == kSlotEntitlements) {
            info.entitlements.assign(payload.begin(), payload.end());
        } else if (slot == kSlotDerEntitlements) {
            info.der_entitlements.assign(payload.begin(), payload.end());
        } else if (slot == kSlotCmsSignature) {
            info.cms.assign(payload.begin(), payload.end());
        }
    }
    std::stable_sort(info.code_directories.begin(), info.code_directories.end(),
                     [](const auto& a, const auto& b) { return a.slot < b.slot; });
    return info;
}

std::vector<std::string> verify_macho(ByteView image) {
    try {
        if (is_thin_macho(image)) return verify_thin(image);
        if (!is_fat_macho(image)) return {"not a Mach-O file"};
        std::vector<std::string> problems;
        for (const FatArch& arch : parse_fat(image)) {
            for (std::string& problem : verify_thin(image.subspan(arch.offset, arch.size))) {
                problems.push_back(std::format("cpu {:#x}: {}", arch.cpu_type, problem));
            }
        }
        return problems;
    } catch (const MachOError& error) {
        return {error.what()};
    }
}

std::optional<std::string> verify_cms(ByteView cms, ByteView content) {
    HCRYPTMSG message = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                             CMSG_DETACHED_FLAG, 0, 0, nullptr, nullptr);
    if (!message) return std::nullopt;
    std::optional<std::string> signer;
    if (CryptMsgUpdate(message, cms.data(), static_cast<DWORD>(cms.size()), TRUE) &&
        CryptMsgUpdate(message, content.data(), static_cast<DWORD>(content.size()), TRUE)) {
        DWORD size = 0;
        if (CryptMsgGetParam(message, CMSG_SIGNER_CERT_INFO_PARAM, 0, nullptr, &size)) {
            Bytes buffer(size);
            if (CryptMsgGetParam(message, CMSG_SIGNER_CERT_INFO_PARAM, 0, buffer.data(), &size)) {
                HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MSG, X509_ASN_ENCODING |
                                                 PKCS_7_ASN_ENCODING, 0, 0, message);
                if (store) {
                    PCCERT_CONTEXT certificate = CertGetSubjectCertificateFromStore(
                        store, X509_ASN_ENCODING, reinterpret_cast<PCERT_INFO>(buffer.data()));
                    if (certificate) {
                        if (CryptMsgControl(message, 0, CMSG_CTRL_VERIFY_SIGNATURE,
                                            certificate->pCertInfo)) {
                            wchar_t name[256];
                            const DWORD length = CertGetNameStringW(
                                certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 256);
                            signer = length > 1 ? to_utf8(std::wstring_view(name, length - 1))
                                                : std::string("unknown");
                        }
                        CertFreeCertificateContext(certificate);
                    }
                    CertCloseStore(store, 0);
                }
            }
        }
    }
    CryptMsgClose(message);
    return signer;
}

}  // namespace winx::codesign
