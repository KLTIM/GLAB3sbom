#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <cjson/cJSON.h>

/* Проверка подписи образа перед переключением A/B-раздела. */
int verify_firmware_image(mbedtls_pk_context *key,
                          const unsigned char *image, size_t image_len,
                          const unsigned char *signature, size_t signature_len) {
    unsigned char digest[32];
    if (!key || !image || !signature || image_len == 0) return -1;
    if (mbedtls_sha256(image, image_len, digest, 0) != 0) return -1;
    return mbedtls_pk_verify(key, MBEDTLS_MD_SHA256, digest, sizeof(digest),
                             signature, signature_len);
}
