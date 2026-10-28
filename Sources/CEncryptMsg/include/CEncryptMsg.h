/*
 * Thin C ABI around evpo/libencryptmsg (OpenPGP symmetric encryption).
 *
 * The implementation is C++ and catches every exception; no C++ exception or
 * type ever crosses this boundary. Byte buffers are owned by the caller:
 *   - em_session_create copies the passphrase into Botan's secure_vector.
 *   - em_session_encrypt/decrypt allocate `em_buffer.data` with malloc.
 *   - em_buffer_free zeroes and frees it.
 *   - em_session_free zeroes the cached passphrase (Botan secure_vector also
 *     zeroes its own allocation).
 *
 * The app only supports password (symmetric) OpenPGP messages with an
 * integrity-protected data packet (tag 18). Public-key messages, ASCII armor
 * and messages without MDC are rejected explicitly.
 */
#ifndef CENCRYPTMSG_H
#define CENCRYPTMSG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum em_result {
    EM_OK = 0,
    /* Wrong passphrase, corrupt ciphertext, truncation, or a malformed
       message: the library cannot distinguish these reliably. */
    EM_ERR_BAD_PASSPHRASE_OR_CORRUPT = 1,
    /* A well-formed OpenPGP message of a kind this app does not support
       (public-key recipient, ASCII armor, unknown packet/algo/S2K). */
    EM_ERR_UNSUPPORTED_FORMAT = 2,
    /* A conventional encrypted packet (tag 9) without MDC integrity. */
    EM_ERR_MISSING_INTEGRITY = 3,
    EM_ERR_INTERNAL = 4,
    EM_ERR_OUT_OF_MEMORY = 5
} em_result;

typedef struct em_session em_session;

typedef struct em_buffer {
    uint8_t *data;
    size_t length;
} em_buffer;

/* Caches a copy of the passphrase in secure memory for repeated saves. */
em_result em_session_create(const uint8_t *passphrase, size_t passphrase_length,
                            em_session **out_session);

/* Copies the cached passphrase into a new independent session (used when an
   encrypted note is saved under a new path). The original stays usable. */
em_result em_session_clone(em_session *session, em_session **out_session);

/* Zeroes the cached passphrase and destroys the session. Safe with NULL. */
void em_session_free(em_session *session);

/* Encrypts with AES-256/CFB, iterated+salted S2K using SHA-256, ZLIB
   compression, binary OpenPGP framing and a fresh random salt. The writer
   always emits an integrity-protected packet (tag 18). */
em_result em_session_encrypt(em_session *session, const uint8_t *plaintext,
                             size_t plaintext_length, em_buffer *out_buffer);

/* Decrypts and verifies the whole message before returning any plaintext. */
em_result em_session_decrypt(em_session *session, const uint8_t *ciphertext,
                             size_t ciphertext_length, em_buffer *out_buffer);

/* Zeroes and frees a buffer returned by encrypt/decrypt. Safe on a zeroed
   or NULL buffer. */
void em_buffer_free(em_buffer *buffer);

/* Static, process-lifetime English description (never contains secrets). */
const char *em_result_message(em_result result);

#ifdef __cplusplus
}
#endif

#endif /* CENCRYPTMSG_H */
