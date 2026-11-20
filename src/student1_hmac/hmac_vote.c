#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cjson/cJSON.h>

/* Подпись голоса канала TMR: channel_id, cycle_id, nonce и команда. */
int sign_vote(const unsigned char *key, size_t key_len,
              const unsigned char *vote, size_t vote_len,
              unsigned char *tag, unsigned int *tag_len) {
    if (!key || !vote || !tag || !tag_len || key_len == 0) return 0;
    return HMAC(EVP_sha256(), key, (int)key_len, vote, vote_len,
                tag, tag_len) != NULL;
}
