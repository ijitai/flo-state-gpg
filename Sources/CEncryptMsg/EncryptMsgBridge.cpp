// C ABI implementation over evpo/libencryptmsg.
//
// No exception may escape: every exported function catches C++ exceptions and
// converts them to em_result. Plaintext is only handed out after
// MessageReader::Finish succeeded (which verifies the RFC 4880 MDC).

#include "CEncryptMsg.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <string>

#include "encryptmsg/algo_spec.h"
#include "encryptmsg/emsg_exception.h"
#include "encryptmsg/emsg_mem.h"
#include "encryptmsg/message_config.h"
#include "encryptmsg/message_decryption.h"
#include "encryptmsg/message_encryption.h"
#include "encryptmsg/openpgp_conversions.h"

using EncryptMsg::CipherAlgo;
using EncryptMsg::Compression;
using EncryptMsg::EmsgException;
using EncryptMsg::EmsgResult;
using EncryptMsg::EncryptionKey;
using EncryptMsg::HashAlgo;
using EncryptMsg::MessageConfig;
using EncryptMsg::MessageReader;
using EncryptMsg::MessageWriter;
using EncryptMsg::SafeVector;
using EncryptMsg::Salt;

namespace {

// 1,015,808 S2K bytes, encoded by the library's own RFC 4880 conversion.
constexpr size_t kS2KIterations = 1015808;
// 2^16 = 64 KiB partial body lengths (EncryptPad uses the same power).
constexpr uint8_t kPartialLengthPower = 16;

struct Session {
    SafeVector passphrase;
    std::mutex mutex;
};

em_result MapException(const char *what) {
    (void)what;
    return EM_ERR_INTERNAL;
}

em_result MapEmsgResult(EmsgResult result) {
    switch (result) {
    case EmsgResult::UnsupportedPacketType:
    case EmsgResult::UnsupportedAlgo:
    case EmsgResult::UnsupportedS2K:
    case EmsgResult::UnsupportedCompressionAlgo:
        return EM_ERR_UNSUPPORTED_FORMAT;
    case EmsgResult::InvalidPassphrase:
    case EmsgResult::InvalidSurrogateIV:
    case EmsgResult::MDCError:
    case EmsgResult::UnexpectedFormat:
    case EmsgResult::UnexpectedError:
    default:
        // Wrong password and damaged ciphertext are indistinguishable here.
        return EM_ERR_BAD_PASSPHRASE_OR_CORRUPT;
    }
}

void Wipe(void *ptr, size_t length) {
    if (ptr != nullptr && length != 0) {
        volatile uint8_t *p = static_cast<volatile uint8_t *>(ptr);
        for (size_t i = 0; i < length; ++i) p[i] = 0;
    }
}

bool SupportedCipher(uint8_t algo) {
    switch (algo) {
    case 2:  // TripleDES
    case 3:  // CAST5
    case 7:  // AES-128
    case 8:  // AES-192
    case 9:  // AES-256
    case 10: // Twofish
    case 11: // Camellia-128
    case 12: // Camellia-192
    case 13: // Camellia-256
        return true;
    default:
        return false;
    }
}

bool SupportedS2KHash(uint8_t algo) {
    switch (algo) {
    case 2:  // SHA-1
    case 8:  // SHA-256
    case 9:  // SHA-384
    case 10: // SHA-512
    case 11: // SHA-224
        return true;
    default:
        return false;
    }
}

bool ReadNewLength(const uint8_t *data, size_t size, size_t &pos, uint64_t &length,
                   bool &partial) {
    if (pos >= size) return false;
    uint8_t c = data[pos++];
    partial = false;
    if (c < 192) {
        length = c;
    } else if (c < 224) {
        if (pos >= size) return false;
        length = (static_cast<uint64_t>(c) - 192) * 256 + data[pos++] + 192;
    } else if (c == 255) {
        if (size - pos < 4) return false;
        length = (static_cast<uint64_t>(data[pos]) << 24) |
                 (static_cast<uint64_t>(data[pos + 1]) << 16) |
                 (static_cast<uint64_t>(data[pos + 2]) << 8) |
                 static_cast<uint64_t>(data[pos + 3]);
        pos += 4;
    } else {
        partial = true;
        length = static_cast<uint64_t>(1) << (c & 0x1f);
    }
    return true;
}

bool BodyConsumesRest(const uint8_t *data, size_t size, size_t pos, uint64_t length, bool partial) {
    while (true) {
        if (length > size - pos) return false;
        pos += static_cast<size_t>(length);
        if (!partial) return pos == size;
        if (!ReadNewLength(data, size, pos, length, partial)) return false;
    }
}

// Checks the outer OpenPGP packet framing before invoking libencryptmsg:
// requires a symmetric-key session packet (tag 3) followed by an
// integrity-protected data packet (tag 18). Rejects public-key messages,
// ASCII armor and MDC-less tag-9 packets without attempting decryption.
em_result CheckSymmetricMdcMessage(const uint8_t *data, size_t size) {
    static const char kArmor[] = "-----BEGIN PGP";
    if (size >= sizeof(kArmor) - 1 && std::memcmp(data, kArmor, sizeof(kArmor) - 1) == 0) {
        return EM_ERR_UNSUPPORTED_FORMAT;
    }
    if (size < 2) return EM_ERR_BAD_PASSPHRASE_OR_CORRUPT;

    size_t pos = 0;
    bool saw_session_key = false;
    while (pos < size) {
        uint8_t ctb = data[pos++];
        if ((ctb & 0x80) == 0) return EM_ERR_BAD_PASSPHRASE_OR_CORRUPT;

        uint8_t tag = 0;
        bool partial = false;
        uint64_t length = 0;
        if (ctb & 0x40) {
            tag = ctb & 0x3f;
            if (!ReadNewLength(data, size, pos, length, partial)) {
                return EM_ERR_BAD_PASSPHRASE_OR_CORRUPT;
            }
        } else {
            tag = (ctb & 0x3f) >> 2;
            uint8_t length_octets = 1u << (ctb & 0x03);
            if ((ctb & 0x03) == 3) return EM_ERR_UNSUPPORTED_FORMAT;  // indeterminate
            if (size - pos < length_octets) return EM_ERR_BAD_PASSPHRASE_OR_CORRUPT;
            for (uint8_t i = 0; i < length_octets; ++i) {
                length = (length << 8) | data[pos++];
            }
        }

        if (tag == 18) {
            if (!saw_session_key) return EM_ERR_UNSUPPORTED_FORMAT;
            // Require the data packet to consume the file exactly: trailing
            // garbage or a truncated body is a damaged message.
            return BodyConsumesRest(data, size, pos, length, partial)
                       ? EM_OK
                       : EM_ERR_BAD_PASSPHRASE_OR_CORRUPT;
        }
        if (tag == 9) return EM_ERR_MISSING_INTEGRITY;
        if (tag == 1 || tag == 2) return EM_ERR_UNSUPPORTED_FORMAT;
        if (tag != 3 && tag != 10) return EM_ERR_UNSUPPORTED_FORMAT;
        if (tag == 3) {
            saw_session_key = true;
            // RFC 4880 §5.3: version 4, cipher, S2K specifier 3, hash,
            // 8-byte salt, encoded count (13 bytes). Validate the stable
            // fields so genuinely unsupported algorithms are reported as
            // such, before any decryption.
            if (partial || length != 13 || length > size - pos) return EM_ERR_UNSUPPORTED_FORMAT;
            const uint8_t *sk = data + pos;
            if (sk[0] != 4 || sk[2] != 3 || !SupportedCipher(sk[1]) || !SupportedS2KHash(sk[3])) {
                return EM_ERR_UNSUPPORTED_FORMAT;
            }
        }

        // Skip the packet body (marker or session key). Partial lengths may
        // continue with further length headers inside the same packet.
        while (true) {
            if (length > size - pos) return EM_ERR_BAD_PASSPHRASE_OR_CORRUPT;
            pos += static_cast<size_t>(length);
            if (!partial) break;
            if (!ReadNewLength(data, size, pos, length, partial)) {
                return EM_ERR_BAD_PASSPHRASE_OR_CORRUPT;
            }
        }
    }
    return EM_ERR_BAD_PASSPHRASE_OR_CORRUPT;
}

em_result CopyOut(const SafeVector &source, em_buffer *out_buffer) {
    if (out_buffer == nullptr) return EM_ERR_INTERNAL;
    out_buffer->data = nullptr;
    out_buffer->length = 0;
    if (source.empty()) return EM_OK;
    if (source.size() > std::numeric_limits<size_t>::max()) return EM_ERR_OUT_OF_MEMORY;
    uint8_t *copy = static_cast<uint8_t *>(std::malloc(source.size()));
    if (copy == nullptr) return EM_ERR_OUT_OF_MEMORY;
    std::memcpy(copy, source.data(), source.size());
    out_buffer->data = copy;
    out_buffer->length = source.size();
    return EM_OK;
}

MessageConfig DefaultConfig() {
    MessageConfig config;
    config.SetCipherAlgo(CipherAlgo::AES256);
    config.SetHashAlgo(HashAlgo::SHA256);
    config.SetIterations(EncryptMsg::EncodeS2KIterations(kS2KIterations));
    config.SetCompression(Compression::ZLIB);
    config.SetFileName("");
    config.SetFileDate(0);
    config.SetBinary(true);
    config.SetArmor(false);
    config.SetPartialLengthPower(kPartialLengthPower);
    return config;
}

}  // namespace

extern "C" {

em_result em_session_create(const uint8_t *passphrase, size_t passphrase_length,
                            em_session **out_session) {
    if (out_session == nullptr) return EM_ERR_INTERNAL;
    *out_session = nullptr;
    if (passphrase == nullptr && passphrase_length != 0) return EM_ERR_INTERNAL;
    try {
        Session *session = new Session();
        if (passphrase_length != 0) {
            session->passphrase.assign(passphrase, passphrase + passphrase_length);
        }
        *out_session = reinterpret_cast<em_session *>(session);
        return EM_OK;
    } catch (const std::bad_alloc &) {
        return EM_ERR_OUT_OF_MEMORY;
    } catch (...) {
        return EM_ERR_INTERNAL;
    }
}

em_result em_session_clone(em_session *opaque, em_session **out_session) {
    if (opaque == nullptr || out_session == nullptr) return EM_ERR_INTERNAL;
    *out_session = nullptr;
    Session *source = reinterpret_cast<Session *>(opaque);
    try {
        std::lock_guard<std::mutex> lock(source->mutex);
        Session *copy = new Session();
        copy->passphrase = source->passphrase;
        *out_session = reinterpret_cast<em_session *>(copy);
        return EM_OK;
    } catch (const std::bad_alloc &) {
        return EM_ERR_OUT_OF_MEMORY;
    } catch (...) {
        return EM_ERR_INTERNAL;
    }
}

void em_session_free(em_session *opaque) {
    if (opaque == nullptr) return;
    Session *session = reinterpret_cast<Session *>(opaque);
    try {
        Wipe(session->passphrase.data(), session->passphrase.size());
        session->passphrase.clear();
    } catch (...) {
    }
    delete session;
}

em_result em_session_encrypt(em_session *opaque, const uint8_t *plaintext,
                             size_t plaintext_length, em_buffer *out_buffer) {
    if (opaque == nullptr || out_buffer == nullptr) return EM_ERR_INTERNAL;
    out_buffer->data = nullptr;
    out_buffer->length = 0;
    if (plaintext == nullptr && plaintext_length != 0) return EM_ERR_INTERNAL;
    Session *session = reinterpret_cast<Session *>(opaque);
    try {
        std::lock_guard<std::mutex> lock(session->mutex);
        MessageConfig config = DefaultConfig();
        SafeVector buffer;
        if (plaintext_length != 0) {
            buffer.assign(plaintext, plaintext + plaintext_length);
        }
        MessageWriter writer;
        // An empty Salt makes the library generate a fresh random salt;
        // the writer also generates a fresh CFB IV prefix each time.
        writer.Start(session->passphrase, config, Salt());
        writer.Finish(buffer);
        em_result result = CopyOut(buffer, out_buffer);
        Wipe(buffer.data(), buffer.size());
        return result;
    } catch (const EmsgException &e) {
        return MapEmsgResult(e.result);
    } catch (const std::bad_alloc &) {
        return EM_ERR_OUT_OF_MEMORY;
    } catch (...) {
        return MapException("encrypt");
    }
}

em_result em_session_decrypt(em_session *opaque, const uint8_t *ciphertext,
                             size_t ciphertext_length, em_buffer *out_buffer) {
    if (opaque == nullptr || out_buffer == nullptr) return EM_ERR_INTERNAL;
    out_buffer->data = nullptr;
    out_buffer->length = 0;
    if (ciphertext == nullptr && ciphertext_length != 0) return EM_ERR_INTERNAL;

    em_result framing = CheckSymmetricMdcMessage(ciphertext, ciphertext_length);
    if (framing != EM_OK) return framing;

    Session *session = reinterpret_cast<Session *>(opaque);
    try {
        std::lock_guard<std::mutex> lock(session->mutex);
        MessageReader reader;
        reader.Start(session->passphrase);
        SafeVector buffer(ciphertext, ciphertext + ciphertext_length);
        // Finish feeds the complete ciphertext and verifies the MDC before
        // returning; on any exception `buffer` is discarded.
        reader.Finish(buffer);
        em_result result = CopyOut(buffer, out_buffer);
        Wipe(buffer.data(), buffer.size());
        return result;
    } catch (const EmsgException &e) {
        // The outer format was validated above. A failure now can be a wrong
        // password, a damaged ciphertext, or an inner packet that decrypted
        // to nonsense; the library cannot tell these apart reliably.
        (void)e;
        return EM_ERR_BAD_PASSPHRASE_OR_CORRUPT;
    } catch (const std::bad_alloc &) {
        return EM_ERR_OUT_OF_MEMORY;
    } catch (...) {
        return MapException("decrypt");
    }
}

void em_buffer_free(em_buffer *buffer) {
    if (buffer == nullptr) return;
    Wipe(buffer->data, buffer->length);
    std::free(buffer->data);
    buffer->data = nullptr;
    buffer->length = 0;
}

const char *em_result_message(em_result result) {
    switch (result) {
    case EM_OK: return "ok";
    case EM_ERR_BAD_PASSPHRASE_OR_CORRUPT:
        return "the passphrase is incorrect or the file is damaged";
    case EM_ERR_UNSUPPORTED_FORMAT:
        return "unsupported OpenPGP message format";
    case EM_ERR_MISSING_INTEGRITY:
        return "the OpenPGP message has no integrity protection";
    case EM_ERR_INTERNAL: return "internal encryption error";
    case EM_ERR_OUT_OF_MEMORY: return "out of memory";
    default: return "unknown encryption error";
    }
}

}  // extern "C"
