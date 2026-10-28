// Standalone tests for the C ABI bridge. Built and run by scripts/test-bridge.sh.
// Deliberately does not use XCTest: this machine only has Command Line Tools.

#include "CEncryptMsg.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

int failures = 0;

void Check(bool ok, const char *what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    }
}

using Bytes = std::vector<uint8_t>;

Bytes Encrypt(const std::string &password, const Bytes &plain, em_result *result_out = nullptr) {
    em_session *session = nullptr;
    em_result r = em_session_create(reinterpret_cast<const uint8_t *>(password.data()), password.size(), &session);
    Bytes out;
    if (r == EM_OK) {
        em_buffer buffer = {nullptr, 0};
        r = em_session_encrypt(session, plain.data(), plain.size(), &buffer);
        if (r == EM_OK) out.assign(buffer.data, buffer.data + buffer.length);
        em_buffer_free(&buffer);
    }
    em_session_free(session);
    if (result_out) *result_out = r;
    return out;
}

Bytes Decrypt(const std::string &password, const Bytes &cipher, em_result *result_out = nullptr) {
    em_session *session = nullptr;
    em_result r = em_session_create(reinterpret_cast<const uint8_t *>(password.data()), password.size(), &session);
    Bytes out;
    if (r == EM_OK) {
        em_buffer buffer = {nullptr, 0};
        r = em_session_decrypt(session, cipher.data(), cipher.size(), &buffer);
        if (r == EM_OK) out.assign(buffer.data, buffer.data + buffer.length);
        em_buffer_free(&buffer);
    }
    em_session_free(session);
    if (result_out) *result_out = r;
    return out;
}

Bytes BytesOf(const std::string &s) { return Bytes(s.begin(), s.end()); }

void TestRoundTrip(const std::string &name, const Bytes &plain) {
    const std::string password = "correct horse battery staple 密码 🔐";
    em_result er = EM_OK, dr = EM_OK;
    Bytes cipher = Encrypt(password, plain, &er);
    Check(er == EM_OK, ("encrypt " + name).c_str());
    Check(!cipher.empty(), ("cipher non-empty " + name).c_str());
    Bytes back = Decrypt(password, cipher, &dr);
    Check(dr == EM_OK, ("decrypt " + name).c_str());
    Check(back == plain, ("round trip bytes " + name).c_str());
    if (cipher.size() >= 2) {
        Check((cipher[0] & 0xC0) == 0xC0 && (cipher[0] & 0x3F) == 3, ("SKESK packet first " + name).c_str());
        // Walk the first packet's header to check that the next packet is tag 18.
        size_t pos = 1;
        bool partial = false;
        uint64_t len = 0;
        auto read_len = [&]() -> bool {
            if (pos >= cipher.size()) return false;
            uint8_t c = cipher[pos++];
            partial = false;
            if (c < 192) len = c;
            else if (c < 224) {
                if (pos >= cipher.size()) return false;
                len = (uint64_t(c) - 192) * 256 + cipher[pos++] + 192;
            } else if (c == 255) {
                if (cipher.size() - pos < 4) return false;
                len = (uint64_t(cipher[pos]) << 24) | (uint64_t(cipher[pos + 1]) << 16) |
                      (uint64_t(cipher[pos + 2]) << 8) | cipher[pos + 3];
                pos += 4;
            } else {
                partial = true;
                len = uint64_t(1) << (c & 0x1f);
            }
            return true;
        };
        read_len();
        while (partial) {
            pos += len;
            read_len();
        }
        pos += len;
        Check(pos < cipher.size() && cipher[pos] == 0xD2, ("SEIPD tag 18 follows " + name).c_str());
    }
}

}  // namespace

int main() {
    const std::string unicode =
        "---\n"
        "title: 测试文档 🚀\n"
        "date: 2026-10-28\n"
        "---\n"
        "\n"
        "# 中文标题 with emoji 😀\n"
        "\n"
        "```swift\n"
        "let greeting = \"你好，世界\"\n"
        "```\n"
        "\n"
        "A long paragraph with accents: café, naïve, résumé. 日本語のテキスト。\n";
    TestRoundTrip("unicode+frontmatter+code", BytesOf(unicode));
    TestRoundTrip("empty", Bytes());
    std::string long_text;
    for (int i = 0; i < 12000; ++i) long_text += "line " + std::to_string(i) + " — 长文档 😀\n";
    TestRoundTrip("large", BytesOf(long_text));

    const std::string password = "s3cret-密码";
    em_result er = EM_OK;
    Bytes cipher1 = Encrypt(password, BytesOf(unicode), &er);
    Check(er == EM_OK, "first encryption");
    Bytes cipher2 = Encrypt(password, BytesOf(unicode), &er);
    Check(er == EM_OK, "second encryption");
    Check(cipher1 != cipher2, "same plaintext+password produce different ciphertext (fresh salt/IV)");
    em_result d1 = EM_OK, d2 = EM_OK;
    Check(Decrypt(password, cipher1, &d1) == BytesOf(unicode) && d1 == EM_OK, "first ciphertext decrypts");
    Check(Decrypt(password, cipher2, &d2) == BytesOf(unicode) && d2 == EM_OK, "second ciphertext decrypts");

    em_result wrong = EM_OK;
    Bytes w = Decrypt("wrong password", cipher1, &wrong);
    Check(wrong == EM_ERR_BAD_PASSPHRASE_OR_CORRUPT, "wrong password maps to generic error");
    Check(w.empty(), "wrong password returns no plaintext");

    Bytes tampered = cipher1;
    tampered[tampered.size() - 40] ^= 0x40;
    em_result tm = EM_OK;
    Check(Decrypt(password, tampered, &tm).empty(), "tampered ciphertext returns no plaintext");
    Check(tm == EM_ERR_BAD_PASSPHRASE_OR_CORRUPT, "tampered ciphertext maps to generic error");

    Bytes truncated(cipher1.begin(), cipher1.end() - 10);
    em_result tr = EM_OK;
    Check(Decrypt(password, truncated, &tr).empty(), "truncated ciphertext returns no plaintext");
    Check(tr == EM_ERR_BAD_PASSPHRASE_OR_CORRUPT, "truncated ciphertext maps to generic error");

    // A conventional encrypted packet without MDC: new-format tag 9.
    Bytes no_mdc = {0xC0 | 9, 1, 0};
    em_result nm = EM_OK;
    Check(Decrypt(password, no_mdc, &nm).empty(), "MDC-less packet returns no plaintext");
    Check(nm == EM_ERR_MISSING_INTEGRITY, "MDC-less packet is rejected specifically");

    Bytes public_key = {0xC0 | 1, 1, 0};
    em_result pk = EM_OK;
    Check(Decrypt(password, public_key, &pk).empty(), "public-key packet returns no plaintext");
    Check(pk == EM_ERR_UNSUPPORTED_FORMAT, "public-key packet is unsupported");

    Bytes armor = BytesOf("-----BEGIN PGP MESSAGE-----\n");
    em_result ar = EM_OK;
    Check(Decrypt(password, armor, &ar).empty(), "armor returns no plaintext");
    Check(ar == EM_ERR_UNSUPPORTED_FORMAT, "ASCII armor is unsupported");

    if (failures == 0) {
        std::printf("bridge tests: all checks passed\n");
        return 0;
    }
    std::fprintf(stderr, "bridge tests: %d failure(s)\n", failures);
    return 1;
}
