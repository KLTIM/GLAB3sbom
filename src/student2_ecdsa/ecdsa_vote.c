#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <cjson/cJSON.h>

/* Проверка подписи команды оператора перед выдачей арбитру. */
int verify_operator_command(mbedtls_ecdsa_context *key,
                            const unsigned char *command, size_t command_len,
                            const unsigned char *signature, size_t signature_len) {
    unsigned char digest[32];
    if (!key || !command || !signature) return -1;
    if (mbedtls_sha256(command, command_len, digest, 0) != 0) return -1;
    return mbedtls_ecdsa_read_signature(key, digest, sizeof(digest),
                                        signature, signature_len);
}
