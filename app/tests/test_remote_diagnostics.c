#include "remote_connection.h"
#include <assert.h>
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

static CURL *easy;
static CURLcode failure;
static CURLMsg done;
static bool pending;
static unsigned performs;
static char messages[4096];
CURL *__real_curl_easy_init(void);
CURL *__wrap_curl_easy_init(void) {
    return easy = __real_curl_easy_init();
}
CURLMcode __wrap_curl_multi_perform(CURLM *multi, int *running) {
    (void)multi;
    ++performs;
    *running = 0;
    done = (CURLMsg){.msg = CURLMSG_DONE, .easy_handle = easy};
    done.data.result = failure;
    pending = true;
    return CURLM_OK;
}
CURLMsg *__wrap_curl_multi_info_read(CURLM *multi, int *remaining) {
    (void)multi;
    *remaining = 0;
    if (!pending)
        return NULL;
    pending = false;
    return &done;
}
static void diagnostic(const char *message, void *context) {
    (void)context;
    assert(strlen(messages) + strlen(message) + 2 < sizeof(messages));
    strcat(messages, message);
    strcat(messages, "\n");
}
int main(void) {
    const CURLcode errors[] = {CURLE_COULDNT_RESOLVE_HOST, CURLE_COULDNT_CONNECT,
                               CURLE_SSL_CONNECT_ERROR, CURLE_PEER_FAILED_VERIFICATION,
                               CURLE_OPERATION_TIMEDOUT};
    uint8_t secret[32] = {0};
    IHS_ClientConfig config = {.deviceId = 17, .secretKey = secret, .deviceName = "test"};
    sl_remote_callbacks callbacks = {.diagnostic = diagnostic};
    for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        messages[0] = 0;
        failure = errors[i];
        performs = 0;
        sl_remote_connection *connection = sl_remote_connection_create(&config, &callbacks, NULL);
        assert(connection);
        sl_remote_connection_update(connection, 1000);
        char expected[96], description[256];
        snprintf(expected, sizeof(expected), "event=transfer_done stage=directory curl=%d http=0",
                 (int)failure);
        assert(strstr(messages, expected));
        assert(strstr(messages, "cloud_time total_ms=") && strstr(messages, "dns_ms="));
        assert(strstr(messages, "cloud_net event=retry established=0"));
        sl_remote_connection_describe(connection, 1000, description, sizeof(description));
        assert(strstr(description, "state=idle ready=0") && strstr(description, "retry_ms="));
        sl_remote_connection_update(connection, 1001);
        assert(performs == 1); /* Diagnostics must preserve initialization backoff. */
        sl_remote_connection_destroy(connection);
    }
    puts("DNS, TCP, TLS, certificate and timeout errors remain distinguishable; backoff preserved");
}
