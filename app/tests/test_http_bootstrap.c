#include "dns_policy.h"
#include "http_bootstrap.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static unsigned ports[3], count;
bool __wrap_sl_dns_current_config(sl_dns_config *out) {
    memset(out, 0, sizeof(*out));
    out->count = count;
    for (unsigned i = 0; i < count; ++i) {
        out->servers[i].sin_family = AF_INET;
        out->servers[i].sin_port = htons(ports[i]);
        out->servers[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    return true;
}
static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static bool options(CURL *c, bool tls, void *ca) {
    assert(curl_easy_setopt(c, CURLOPT_PROXY, "") == CURLE_OK);
    assert(curl_easy_setopt(c, CURLOPT_CAINFO, ca) == CURLE_OK);
    assert(curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L) == CURLE_OK);
    assert(curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L) == CURLE_OK);
    assert(curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, 1000L) == CURLE_OK);
    assert(curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L) == CURLE_OK);
    if (tls)
        assert(curl_easy_setopt(c, CURLOPT_CONNECT_ONLY, 1L) == CURLE_OK);
    return true;
}
int main(int argc, char **argv) {
    assert(argc == 6);
    count = sscanf(argv[1], "%u,%u,%u", &ports[0], &ports[1], &ports[2]);
    const char *mode = argv[4], *expected = argv[5];
    bool tls = strstr(mode, "connect-only") != NULL, cancel = strstr(mode, "cancel") != NULL;
    assert(sl_http_global_acquire() && sl_dns_policy_init(NULL));
    CURLM *multi = curl_multi_init();
    assert(multi);
    uint64_t began = now_ms();
    sl_http_bootstrap *b =
        sl_http_bootstrap_create(multi, argv[2], tls, 8192, began, options, argv[3]);
    assert(b);
    CURL *winner = NULL;
    sl_http_route route = {0};
    uint8_t *body = NULL;
    size_t size = 0;
    CURLcode code = CURLE_OK;
    int complete = 0;
    while (!complete && now_ms() - began < (cancel ? 180 : 6000)) {
        complete = sl_http_bootstrap_poll(b, now_ms(), &winner, &route, &body, &size, &code);
        usleep(1000);
    }
    sl_http_bootstrap_destroy(b); // Losers close; winner remains in its multi.
    long response = 0;
    if (winner)
        curl_easy_getinfo(winner, CURLINFO_RESPONSE_CODE, &response);
    if (cancel)
        assert(!complete && !winner);
    else if (!strcmp(expected, "success"))
        assert(complete == 1 && code == CURLE_OK && response == 200 && size == 2 &&
               !memcmp(body, "OK", 2));
    else if (!strcmp(expected, "http"))
        assert(complete == 1 && code == CURLE_OK && response == 503 && size == 2 &&
               !memcmp(body, "NO", 2));
    else if (!strcmp(expected, "partial"))
        assert(complete == 1 && code != CURLE_OK && response == 200 && size == 2 &&
               !memcmp(body, "NO", 2));
    else if (!strcmp(expected, "failure"))
        assert(complete == -1 && !winner && code != CURLE_OK);
    else {
        assert(tls && winner && complete == 1 && code == CURLE_OK);
        long port;
        curl_easy_getinfo(winner, CURLINFO_PRIMARY_PORT, &port);
        char request[192], reply[512] = {0};
        int length =
            snprintf(request, sizeof(request),
                     "GET / HTTP/1.1\r\nHost: route.test:%ld\r\nConnection: close\r\n\r\n", port);
        size_t sent = 0, used = 0;
        for (unsigned tick = 0; tick < 2000 && sent < (size_t)length; ++tick) {
            size_t n = 0;
            CURLcode r = curl_easy_send(winner, request + sent, length - sent, &n);
            assert(r == CURLE_OK || r == CURLE_AGAIN);
            sent += n;
            usleep(1000);
        }
        assert(sent == (size_t)length);
        for (unsigned tick = 0; tick < 2000 && !strstr(reply, "\r\n\r\nOK"); ++tick) {
            size_t n = 0;
            CURLcode r = curl_easy_recv(winner, reply + used, sizeof(reply) - used - 1, &n);
            assert(r == CURLE_OK || r == CURLE_AGAIN);
            used += n;
            reply[used] = 0;
            usleep(1000);
        }
        assert(strstr(reply, "200 OK") && strstr(reply, "\r\n\r\nOK"));
    }
    free(body);
    if (winner) {
        curl_multi_remove_handle(multi, winner);
        curl_easy_cleanup(winner);
    }
    sl_http_route_clear(&route);
    curl_multi_cleanup(multi);
    assert(sl_dns_policy_shutdown());
    sl_http_global_release();
    printf("PASS bootstrap result=%d curl=%d elapsed_ms=%llu\n", complete, code,
           (unsigned long long)(now_ms() - began));
}
