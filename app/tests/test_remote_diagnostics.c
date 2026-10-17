#include "dns_refresh.h"
#include "remote_connection.h"
#include <arpa/inet.h>
#include <assert.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static CURL *easy;
static CURLcode failure;
static CURLMsg done;
static bool pending;
static unsigned performs;
static char messages[4096];
static curl_debug_callback trace;
static void *trace_context;
static long verbose;
static bool refresh_enabled;
static sl_dns_config dns_config;
static char resolved[128], request_url[192];
static long verify_peer, verify_host;
bool __wrap_sl_dns_current_config(sl_dns_config *out) {
    if (!refresh_enabled)
        return false;
    *out = dns_config;
    return true;
}
static int last_dns_fd = -1;
int __real_socket(int, int, int);
int __wrap_socket(int domain, int type, int protocol) {
    int result = __real_socket(domain, type, protocol);
    if (domain == AF_INET && type == SOCK_DGRAM)
        last_dns_fd = result;
    return result;
}
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
        if (option == CURLOPT_URL)
            snprintf(request_url, sizeof(request_url), "%s", (char *)value);
        if (option == CURLOPT_RESOLVE) {
            struct curl_slist *list = value;
            assert(list && !list->next);
            snprintf(resolved, sizeof(resolved), "%s", list->data);
        }
        result = __real_curl_easy_setopt(handle, option, value);
    } else {
        assert(option < CURLOPTTYPE_OBJECTPOINT);
        long value = va_arg(args, long);
        if (option == CURLOPT_VERBOSE)
            verbose = value;
        if (option == CURLOPT_SSL_VERIFYPEER)
            verify_peer = value;
        if (option == CURLOPT_SSL_VERIFYHOST)
            verify_host = value;
        result = __real_curl_easy_setopt(handle, option, value);
    }
    va_end(args);
    return result;
}
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
static void directory_recovery(const IHS_ClientConfig *config,
                               const sl_remote_callbacks *callbacks) {
    dns_config = (sl_dns_config){.count = 1};
    int server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(server >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(server, (struct sockaddr *)&address, sizeof(address)) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(server, (struct sockaddr *)&address, &length) == 0);
    dns_config.servers[0] = address;
    refresh_enabled = true;
    messages[0] = resolved[0] = 0;
    failure = CURLE_OPERATION_TIMEDOUT;
    performs = 0;
    sl_remote_connection *connection = sl_remote_connection_create(config, callbacks, NULL);
    assert(connection);
    sl_remote_connection_update(connection, 1000);
    char description[256];
    sl_remote_connection_describe(connection, 1000, description, sizeof(description));
    assert(strstr(description, "state=dns_refresh") && performs == 1);
    int queried_fd = last_dns_fd;
    assert(queried_fd >= 0 && queried_fd != server);
    uint8_t packet[512];
    struct sockaddr_in client;
    length = sizeof(client);
    ssize_t n =
        recvfrom(server, packet, sizeof(packet), MSG_DONTWAIT, (struct sockaddr *)&client, &length);
    assert(n > 12 && n < 480);
    packet[2] = 0x81;
    packet[3] = 0x80;
    packet[6] = 0;
    packet[7] = 1;
    const uint8_t answer[] = {0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7};
    memcpy(packet + n, answer, sizeof(answer));
    size_t reply_size = (size_t)n + sizeof(answer);
    assert(sendto(server, packet, reply_size, 0, (struct sockaddr *)&client, sizeof(client)) ==
           (ssize_t)reply_size);
    /* A fresh destination failing again ends this attempt: no infinite refresh
     * loop and no bypass of the original TLS/URL policy. */
    failure = CURLE_COULDNT_CONNECT;
    sl_remote_connection_update(connection, 1001);
    assert(performs == 2);
    assert(!strcmp(resolved, "api.steampowered.com:443:198.51.100.7"));
    assert(!strcmp(request_url, "https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/"
                                "v1/?cellid=0&cmtype=websockets"));
    assert(verify_peer == 1 && verify_host == 2);
    assert(fcntl(queried_fd, F_GETFD) == -1);
    sl_remote_connection_describe(connection, 1001, description, sizeof(description));
    assert(strstr(description, "state=idle") && strstr(messages, "event=retry established=0"));
    sl_remote_connection_update(connection, 1002);
    assert(performs == 2);
    sl_remote_connection_update(connection, 1000000);
    assert(!strcmp(resolved, "-api.steampowered.com:443"));
    sl_remote_connection_destroy(connection);
    /* Suspending and destruction while DNS is pending must close its socket. */
    for (unsigned cancel = 0; cancel < 2; ++cancel) {
        messages[0] = 0;
        connection = sl_remote_connection_create(config, callbacks, NULL);
        assert(connection);
        sl_remote_connection_update(connection, 2000);
        queried_fd = last_dns_fd;
        assert(queried_fd >= 0 && fcntl(queried_fd, F_GETFD) >= 0);
        if (cancel)
            sl_remote_connection_set_active(connection, false);
        else {
            sl_remote_connection_destroy(connection);
            connection = NULL;
        }
        assert(fcntl(queried_fd, F_GETFD) == -1);
        sl_remote_connection_destroy(connection);
    }
    /* TLS/HTTP error classes must not activate this DNS-specific fallback. */
    const CURLcode tls_errors[] = {CURLE_PEER_FAILED_VERIFICATION, CURLE_SSL_CONNECT_ERROR};
    for (unsigned i = 0; i < 2; ++i) {
        messages[0] = 0;
        failure = tls_errors[i];
        connection = sl_remote_connection_create(config, callbacks, NULL);
        sl_remote_connection_update(connection, 3000);
        sl_remote_connection_describe(connection, 3000, description, sizeof(description));
        assert(strstr(description, "state=idle") && !strstr(messages, "cloud_dns event=begin"));
        sl_remote_connection_destroy(connection);
    }
    close(server);
    refresh_enabled = false;
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
        sl_remote_connection *connection = sl_remote_connection_create(&config, &callbacks, NULL);
        assert(connection);
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
        sl_remote_connection_update(connection, 1001);
        assert(performs == 1); /* Diagnostics must preserve initialization backoff. */
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
    directory_recovery(&config, &callbacks);
    puts("Directory recovery uses fresh DNS with original URL/TLS, bounded retries and "
         "cancellation");
}
