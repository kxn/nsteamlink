#include "dns_policy.h"
#include "http_route.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static unsigned dns_port;
bool __wrap_sl_dns_current_config(sl_dns_config *out) {
    memset(out, 0, sizeof(*out));
    out->count = 1;
    out->servers[0].sin_family = AF_INET;
    out->servers[0].sin_port = htons(dns_port);
    out->servers[0].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return true;
}
static char body[128];
static size_t used;
static size_t receive(char *p, size_t size, size_t count, void *ctx) {
    (void)ctx;
    size_t bytes = size * count;
    assert(bytes <= sizeof(body) - used);
    memcpy(body + used, p, bytes);
    used += bytes;
    return bytes;
}
static void report(const char *line) {
    puts(line);
}
int main(int argc, char **argv) {
    assert(argc == 6);
    dns_port = (unsigned)atoi(argv[1]);
    const char *url = argv[2], *ca = argv[3], *mode = argv[4], *expected = argv[5];
    assert(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
    assert(sl_dns_policy_init(report));
    sl_dns_policy_begin(44);
    CURL *easy = curl_easy_init();
    assert(easy);
    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_PROXY, "");
    curl_easy_setopt(easy, CURLOPT_CAINFO, ca);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 1000L);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, receive);
    bool connect_only = !strcmp(mode, "connect-only");
    if (connect_only)
        curl_easy_setopt(easy, CURLOPT_CONNECT_ONLY, 1L);
    CURLcode code;
    if (!strcmp(mode, "blocking"))
        code = sl_http_route_perform(easy, url, 1000);
    else {
        CURLM *multi = curl_multi_init();
        sl_http_route route;
        assert(sl_http_route_begin(&route, easy, url, 1000));
        if (!strcmp(mode, "cancel"))
            sl_dns_policy_cancel(44);
        if (!strcmp(mode, "deadline"))
            route.deadline = 1;
        assert(curl_multi_add_handle(multi, easy) == CURLM_OK);
        bool done = false;
        code = CURLE_FAILED_INIT;
        while (!done) {
            int running, remaining;
            assert(curl_multi_perform(multi, &running) == CURLM_OK);
            CURLMsg *msg;
            while ((msg = curl_multi_info_read(multi, &remaining))) {
                if (msg->msg != CURLMSG_DONE)
                    continue;
                code = msg->data.result;
                if (connect_only && code == CURLE_OK) {
                    done = true;
                    break;
                }
                curl_multi_remove_handle(multi, easy);
                if (sl_http_route_retry(&route, easy, code)) {
                    assert(curl_multi_add_handle(multi, easy) == CURLM_OK);
                } else
                    done = true;
                break;
            }
            if (!done)
                usleep(1000);
        }
        if (connect_only) {
            /* Production CM keeps the successful CONNECT_ONLY easy in multi.
             * Verify the same TLS socket remains usable after address rotation. */
            assert(code == CURLE_OK);
            long port = 0;
            curl_easy_getinfo(easy, CURLINFO_PRIMARY_PORT, &port);
            char request[192];
            int length = snprintf(
                request, sizeof(request),
                "GET /directory HTTP/1.1\r\nHost: route.test:%ld\r\nConnection: close\r\n\r\n",
                port);
            size_t sent = 0;
            for (unsigned tick = 0; sent < (size_t)length && tick < 2000; ++tick) {
                size_t n = 0;
                CURLcode result = curl_easy_send(easy, request + sent, (size_t)length - sent, &n);
                assert(result == CURLE_OK || result == CURLE_AGAIN);
                sent += n;
                if (!n)
                    usleep(1000);
            }
            assert(sent == (size_t)length);
            for (unsigned tick = 0; tick < 2000; ++tick) {
                size_t n = 0;
                CURLcode result = curl_easy_recv(easy, body + used, sizeof(body) - used - 1, &n);
                assert(result == CURLE_OK || result == CURLE_AGAIN);
                used += n;
                body[used] = 0;
                if (strstr(body, "\r\n\r\nOK"))
                    break;
                usleep(1000);
            }
            assert(strstr(body, "200 OK") && strstr(body, "\r\n\r\nOK"));
            curl_multi_remove_handle(multi, easy);
        }
        curl_easy_setopt(easy, CURLOPT_RESOLVE, NULL);
        sl_http_route_clear(&route);
        curl_multi_cleanup(multi);
    }
    long response = 0;
    char *remote = NULL;
    curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response);
    curl_easy_getinfo(easy, CURLINFO_PRIMARY_IP, &remote);
    printf("RESULT curl=%d response=%ld ip=%s body=%.*s\n", code, response, remote ? remote : "",
           (int)used, body);
    if (!strcmp(expected, "success"))
        assert(code == CURLE_OK && response == 200 && used == 2 && !memcmp(body, "OK", 2));
    else if (!strcmp(expected, "connected"))
        assert(code == CURLE_OK && strstr(body, "200 OK"));
    else if (!strcmp(expected, "http"))
        assert(code == CURLE_OK && response == 503 && used == 2);
    else if (!strcmp(expected, "partial"))
        assert(code != CURLE_OK && response == 200 && used == 2);
    else
        assert(code != CURLE_OK && response == 0 && used == 0);
    curl_easy_cleanup(easy);
    sl_dns_policy_end(44);
    assert(sl_dns_policy_shutdown());
    curl_global_cleanup();
    return 0;
}
