#include "remote_connection.h"
#include <assert.h>
#include <curl/curl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static CURL *easy;
static CURLcode failure;
static CURLMsg done;
static bool pending, added;
static unsigned performs;
static char messages[4096];
static curl_debug_callback trace;
static void *trace_context;
static long verbose;
CURLcode __real_curl_easy_setopt(CURL *, CURLoption, ...);
CURLcode __wrap_curl_easy_setopt(CURL *handle, CURLoption option, ...) {
    va_list args;
    va_start(args, option);
    CURLcode result;
    if (option == CURLOPT_DEBUGFUNCTION) {
        trace = va_arg(args, curl_debug_callback);
        result = __real_curl_easy_setopt(handle, option, trace);
    } else if (option == CURLOPT_WRITEFUNCTION) {
        curl_write_callback write = va_arg(args, curl_write_callback);
        result = __real_curl_easy_setopt(handle, option, write);
    } else if (option >= CURLOPTTYPE_OBJECTPOINT && option < CURLOPTTYPE_FUNCTIONPOINT) {
        void *value = va_arg(args, void *);
        if (option == CURLOPT_DEBUGDATA)
            trace_context = value;
        result = __real_curl_easy_setopt(handle, option, value);
    } else {
        assert(option < CURLOPTTYPE_OBJECTPOINT);
        long value = va_arg(args, long);
        if (option == CURLOPT_VERBOSE)
            verbose = value;
        result = __real_curl_easy_setopt(handle, option, value);
    }
    va_end(args);
    return result;
}
CURL *__real_curl_easy_init(void);
CURL *__wrap_curl_easy_init(void) {
    return easy = __real_curl_easy_init();
}
CURLMcode __real_curl_multi_add_handle(CURLM *, CURL *);
CURLMcode __wrap_curl_multi_add_handle(CURLM *multi, CURL *handle) {
    CURLMcode result = __real_curl_multi_add_handle(multi, handle);
    if (result == CURLM_OK)
        added = true;
    return result;
}
CURLMcode __real_curl_multi_remove_handle(CURLM *, CURL *);
CURLMcode __wrap_curl_multi_remove_handle(CURLM *multi, CURL *handle) {
    added = false;
    return __real_curl_multi_remove_handle(multi, handle);
}
CURLMcode __wrap_curl_multi_perform(CURLM *multi, int *running) {
    (void)multi;
    ++performs;
    *running = 0;
    if (!added)
        return CURLM_OK;
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
        trace = NULL;
        trace_context = NULL;
        verbose = 0;
        failure = errors[i];
        performs = 0;
        added = pending = false;
        sl_remote_connection *connection = sl_remote_connection_create(&config, &callbacks, NULL);
        assert(connection);
        sl_remote_connection_update(connection, 1000);
        sl_remote_connection_update(connection, 1000);
        assert(trace && trace_context && verbose == 1);
        char expected[96], description[256];
        snprintf(expected, sizeof(expected), "event=transfer_done stage=directory curl=%d http=0",
                 (int)failure);
        assert(strstr(messages, expected));
        assert(strstr(messages, "cloud_time total_ms=") && strstr(messages, "dns_ms="));
        assert(strstr(messages, "cloud_net event=retry established=0"));
        sl_remote_connection_describe(connection, 1000, description, sizeof(description));
        assert(strstr(description, "state=idle ready=0") && strstr(description, "retry_ms="));
        unsigned before = performs;
        sl_remote_connection_update(connection, 1001);
        assert(performs == before); /* Diagnostics must preserve initialization backoff. */
        /* Callback data is length-delimited, never assumed NUL-terminated.
         * Numeric attempts survive failed TCP; every other trace stays private. */
        messages[0] = 0;
        char ipv4[] = "  Trying 11.171.50.44:443...\n";
        char ipv6[] = "  Trying 2d00:fdef::ff42:746:2037:8618:443...\n";
        char bracketed[] = "  Trying [2001:db8::1]:443...\n";
        assert(trace(easy, CURLINFO_TEXT, ipv4, sizeof(ipv4) - 1, trace_context) == 0);
        assert(trace(easy, CURLINFO_TEXT, ipv6, sizeof(ipv6) - 1, trace_context) == 0);
        assert(trace(easy, CURLINFO_TEXT, bracketed, sizeof(bracketed) - 1, trace_context) == 0);
        assert(strstr(messages, "ip=11.171.50.44 port=443"));
        assert(strstr(messages, "ip=2d00:fdef::ff42:746:2037:8618 port=443"));
        assert(strstr(messages, "ip=2001:db8::1 port=443"));
        size_t accepted = strlen(messages);
        for (int type = CURLINFO_HEADER_IN; type < CURLINFO_END; ++type)
            assert(trace(easy, (curl_infotype)type, ipv4, sizeof(ipv4) - 1, trace_context) == 0);
        const char *private[] = {"Authorization: secret", "  Trying secret:443...\n",
                                 "  Trying 127.0.0.1:65536...\n",
                                 "  Trying 127.0.0.1:443 secret...\n"};
        for (unsigned k = 0; k < sizeof(private) / sizeof(private[0]); ++k)
            trace(easy, CURLINFO_TEXT, (char *)private[k], strlen(private[k]), trace_context);
        for (size_t length = 0; length < sizeof(ipv4) - 3; ++length)
            trace(easy, CURLINFO_TEXT, ipv4, length, trace_context);
        assert(strlen(messages) == accepted);
        for (int k = 0; k < 40; ++k)
            trace(easy, CURLINFO_TEXT, ipv4, sizeof(ipv4) - 1, trace_context);
        unsigned attempts = 0;
        for (const char *p = messages; (p = strstr(p, "cloud_try ")); ++p)
            ++attempts;
        assert(attempts == 16); /* Bound output per request, even for unexpected curl traces. */
        sl_remote_connection_destroy(connection);
    }
    puts("Connection attempts survive TCP failures; trace privacy, bounds and backoff preserved");
}
