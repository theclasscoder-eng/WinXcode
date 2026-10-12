#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <thread>

#include "support.hpp"
#include "winx/crypto.hpp"
#include "winx/files.hpp"
#include "winx/http.hpp"
#include "winx/socket.hpp"

using namespace winx;
using namespace std::chrono_literals;
using crypto::Bytes;

namespace {

Bytes bytes_of(std::string_view text) { return Bytes(text.begin(), text.end()); }

Bytes unhex(std::string_view text) { return crypto::from_hex(text).value(); }

// Minimal one-shot HTTP/1.1 server on loopback.
class FakeHttpServer {
public:
    explicit FakeHttpServer(std::string response)
        : thread_([this, response = std::move(response)] {
              try {
                  net::Socket socket = listener_.accept();
                  socket.set_timeouts(5s, 5s);
                  std::array<std::uint8_t, 1> byte{};
                  while (request_.find("\r\n\r\n") == std::string::npos) {
                      if (socket.recv_some(byte) == 0) return;
                      request_ += static_cast<char>(byte[0]);
                  }
                  std::size_t length = 0;
                  const auto header = request_.find("Content-Length: ");
                  if (header != std::string::npos) length = std::stoul(request_.substr(header + 16));
                  const std::size_t head_size = request_.size();
                  while (request_.size() - head_size < length) {
                      if (socket.recv_some(byte) == 0) return;
                      request_ += static_cast<char>(byte[0]);
                  }
                  socket.send_all(crypto::as_bytes(response));
              } catch (const std::exception&) {
              }
          }) {}

    ~FakeHttpServer() { join(); }
    void join() {
        if (thread_.joinable()) thread_.join();
    }
    std::string url(std::string_view path) const {
        return "http://127.0.0.1:" + std::to_string(listener_.port()) + std::string(path);
    }
    // Only valid after join().
    const std::string& request() const { return request_; }

private:
    net::TcpListener listener_ = net::TcpListener::bind_loopback();
    std::string request_;
    std::thread thread_;
};

}  // namespace

TEST_CASE("hashes match published vectors", "[crypto]") {
    CHECK(crypto::to_hex(crypto::sha1(crypto::as_bytes("abc"))) ==
          "a9993e364706816aba3e25717850c26c9cd0d89d");
    CHECK(crypto::to_hex(crypto::sha256(crypto::as_bytes("abc"))) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(crypto::to_hex(crypto::sha256({})) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // Incremental hashing gives the same digest as one shot.
    crypto::Hasher hasher(crypto::HashAlgorithm::Sha256);
    hasher.update(std::string_view("a")).update(std::string_view("bc"));
    CHECK(hasher.finish() == crypto::sha256(crypto::as_bytes("abc")));

    // RFC 4231 test case 2.
    CHECK(crypto::to_hex(crypto::hmac_sha256(crypto::as_bytes("Jefe"),
                                             crypto::as_bytes("what do ya want for nothing?"))) ==
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST_CASE("PBKDF2-HMAC-SHA256 matches published vectors", "[crypto]") {
    const auto password = crypto::as_bytes("password");
    const auto salt = crypto::as_bytes("salt");
    CHECK(crypto::to_hex(crypto::pbkdf2_hmac_sha256(password, salt, 1, 32)) ==
          "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    CHECK(crypto::to_hex(crypto::pbkdf2_hmac_sha256(password, salt, 2, 32)) ==
          "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
}

TEST_CASE("AES-CBC round-trips and matches a NIST vector", "[crypto]") {
    // NIST SP 800-38A F.2.1, first block (no padding in the vector, so compare a prefix).
    const Bytes key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
    const Bytes iv = unhex("000102030405060708090a0b0c0d0e0f");
    const Bytes block = unhex("6bc1bee22e409f96e93d7e117393172a");
    const Bytes encrypted = crypto::aes_cbc_encrypt(key, iv, block);
    REQUIRE(encrypted.size() == 32);  // one data block plus a full padding block
    CHECK(crypto::to_hex(crypto::ByteView(encrypted).subspan(0, 16)) ==
          "7649abac8119b246cee98e9b12e9197d");
    CHECK(crypto::aes_cbc_decrypt(key, iv, encrypted) == block);

    const Bytes key256 = crypto::random_bytes(32);
    const Bytes message = bytes_of("a message that is not a multiple of the block size");
    CHECK(crypto::aes_cbc_decrypt(key256, iv, crypto::aes_cbc_encrypt(key256, iv, message)) ==
          message);
    CHECK_THROWS_AS(crypto::aes_cbc_decrypt(crypto::random_bytes(32), iv,
                                            crypto::aes_cbc_encrypt(key256, iv, message)),
                    crypto::CryptoError);
}

TEST_CASE("AES-GCM authenticates, including with a 16-byte nonce", "[crypto]") {
    const Bytes key = crypto::random_bytes(32);
    const Bytes message = bytes_of("token payload");
    const Bytes aad = bytes_of("XYZ");

    for (const std::size_t nonce_size : {std::size_t{12}, std::size_t{16}}) {
        const Bytes nonce = crypto::random_bytes(nonce_size);
        const crypto::GcmSealed sealed = crypto::aes_gcm_encrypt(key, nonce, message, aad);
        CHECK(sealed.tag.size() == 16);
        CHECK(crypto::aes_gcm_decrypt(key, nonce, sealed.ciphertext, sealed.tag, aad) == message);

        Bytes bad_tag = sealed.tag;
        bad_tag[0] ^= 1;
        CHECK_THROWS_AS(crypto::aes_gcm_decrypt(key, nonce, sealed.ciphertext, bad_tag, aad),
                        crypto::CryptoError);
        CHECK_THROWS_AS(
            crypto::aes_gcm_decrypt(key, nonce, sealed.ciphertext, sealed.tag, bytes_of("ABC")),
            crypto::CryptoError);
    }
}

TEST_CASE("hex helpers round-trip", "[crypto]") {
    const Bytes data{0x00, 0x1f, 0xab, 0xff};
    CHECK(crypto::to_hex(data) == "001fabff");
    CHECK(crypto::to_hex(data, true) == "001FABFF");
    CHECK(crypto::from_hex("00 1F ab\nff") == data);
    CHECK_FALSE(crypto::from_hex("abc").has_value());
    CHECK_FALSE(crypto::from_hex("zz").has_value());
    CHECK(crypto::random_bytes(16) != crypto::random_bytes(16));
}

TEST_CASE("files, DPAPI and PEM helpers round-trip", "[files]") {
    const test::TempDir dir("winx_files");
    const auto path = dir.path() / "nested" / "secret.bin";
    const Bytes secret = bytes_of("session token");

    CHECK_FALSE(read_file(path).has_value());
    secure::write_file(path, secret);
    const auto on_disk = read_file(path);
    REQUIRE(on_disk.has_value());
    CHECK(*on_disk != secret);  // stored encrypted
    CHECK(secure::read_file(path) == secret);
    CHECK_THROWS(secure::unprotect(secret));

    write_text_file(dir.path() / "note.txt", "hello");
    CHECK(read_text_file(dir.path() / "note.txt") == "hello");

    const Bytes der = crypto::random_bytes(100);
    const std::string pem = pem_encode("CERTIFICATE", der);
    CHECK(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    CHECK(pem_decode(pem, "CERTIFICATE") == der);
    CHECK_FALSE(pem_decode(pem, "PRIVATE KEY").has_value());
    const auto blocks = pem_decode_all(pem + pem_encode("PRIVATE KEY", secret));
    REQUIRE(blocks.size() == 2);
    CHECK(blocks[1].label == "PRIVATE KEY");
    CHECK(blocks[1].der == secret);
}

TEST_CASE("the HTTP client sends requests and parses responses", "[http]") {
    FakeHttpServer server("HTTP/1.1 201 Created\r\n"
                          "Content-Type: application/json\r\n"
                          "X-Custom: yes\r\n"
                          "Content-Length: 11\r\n"
                          "Connection: close\r\n\r\n"
                          "{\"ok\":true}");
    const http::Client client("winx-tests/1.0");
    http::Request request;
    request.method = "POST";
    request.url = server.url("/v1/things?filter%5Bname%5D=a%20b");
    request.headers = {{"Authorization", "Bearer token"}, {"Content-Type", "application/json"}};
    request.body = "{\"n\":1}";
    const http::Response response = client.send(request);
    server.join();

    CHECK(response.status == 201);
    CHECK(response.ok());
    CHECK(response.body == "{\"ok\":true}");
    CHECK(response.header("x-custom") == "yes");
    CHECK(response.header("content-type") == "application/json");
    CHECK_FALSE(response.header("missing").has_value());

    const std::string& seen = server.request();
    CHECK(seen.starts_with("POST /v1/things?filter%5Bname%5D=a%20b HTTP/1.1\r\n"));
    CHECK(seen.find("Authorization: Bearer token\r\n") != std::string::npos);
    CHECK(seen.find("User-Agent: winx-tests/1.0\r\n") != std::string::npos);
    CHECK(seen.ends_with("\r\n\r\n{\"n\":1}"));
}

TEST_CASE("the HTTP client reports unreachable servers", "[http]") {
    std::uint16_t port = 0;
    { port = net::TcpListener::bind_loopback().port(); }
    const http::Client client;
    http::Request request;
    request.url = "http://127.0.0.1:" + std::to_string(port) + "/";
    request.timeout = 3s;
    CHECK_THROWS_AS(client.send(request), http::HttpError);
    CHECK(http::url_encode("filter[udid]=a b") == "filter%5Budid%5D%3Da%20b");
}
