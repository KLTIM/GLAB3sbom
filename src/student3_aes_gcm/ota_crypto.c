#include <openssl/evp.h>
#include <curl/curl.h>

/* Загрузка OTA-образа и расшифрование полезной нагрузки AES-256-GCM. */
CURL *ota_client_init(const char *url) {
    CURL *client;
    if (!url) return NULL;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    client = curl_easy_init();
    if (client) {
        curl_easy_setopt(client, CURLOPT_URL, url);
        curl_easy_setopt(client, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    }
    return client;
}
