// Test-only CLI: password from stdin (never argv), then encrypt/decrypt a file
// through the same C ABI the app uses. Not shipped in the .app.

#include "CEncryptMsg.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {
bool ReadFile(const char *path, std::vector<uint8_t> &out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}
bool WriteFile(const char *path, const uint8_t *data, size_t size) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    if (size) out.write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(size));
    return static_cast<bool>(out);
}
}  // namespace

int main(int argc, char **argv) {
    if (argc != 4 || (std::string(argv[1]) != "encrypt" && std::string(argv[1]) != "decrypt")) {
        std::fprintf(stderr, "usage: bridge_cli encrypt|decrypt <in> <out> (password on stdin)\n");
        return 2;
    }
    std::string password;
    if (!std::getline(std::cin, password)) return 2;
    std::vector<uint8_t> input;
    if (!ReadFile(argv[2], input)) {
        std::fprintf(stderr, "cannot read input\n");
        return 2;
    }
    em_session *session = nullptr;
    em_result result = em_session_create(reinterpret_cast<const uint8_t *>(password.data()), password.size(), &session);
    if (result != EM_OK) {
        std::fprintf(stderr, "session: %s\n", em_result_message(result));
        return 1;
    }
    std::fill(password.begin(), password.end(), '\0');
    em_buffer output = {nullptr, 0};
    if (std::string(argv[1]) == "encrypt") {
        result = em_session_encrypt(session, input.data(), input.size(), &output);
    } else {
        result = em_session_decrypt(session, input.data(), input.size(), &output);
    }
    em_session_free(session);
    if (result != EM_OK) {
        std::fprintf(stderr, "crypto: %s\n", em_result_message(result));
        return 1;
    }
    bool ok = WriteFile(argv[3], output.data, output.length);
    em_buffer_free(&output);
    if (!ok) {
        std::fprintf(stderr, "cannot write output\n");
        return 2;
    }
    return 0;
}
