#include "http_route.h"
#include "dns_policy.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__SWITCH__) || defined(NSL_HTTP_ROUTE_TEST)
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static void event(const sl_http_route *r, const char *name, const char *ip, int code) {
#if NSL_DIAGNOSTICS
    char line[384];
    snprintf(line, sizeof(line), "https_route event=%s host=%s ip=%s attempt=%u/%u curl=%d", name,
             r->host, ip, r->index + 1, r->count, code);
    sl_dns_policy_report(line);
#else
    (void)r;
    (void)name;
    (void)ip;
    (void)code;
#endif
}
static bool select_address(sl_http_route *r, CURL *easy) {
    char copy[SL_DNS_ADDRESSES_SIZE];
    strcpy(copy, r->addresses);
    char *state = NULL, *ip = strtok_r(copy, ",", &state);
    for (unsigned i = 0; ip && i < r->index; ++i)
        ip = strtok_r(NULL, ",", &state);
    uint64_t now = now_ms();
    if (!ip || now >= r->deadline || sl_dns_policy_cancelled())
        return false;
    char mapping[300];
    snprintf(mapping, sizeof(mapping), "%s:%u:%s", r->host, r->port, ip);
    struct curl_slist *next = curl_slist_append(NULL, mapping);
    if (!next)
        return false;
    CURLcode result = curl_easy_setopt(easy, CURLOPT_RESOLVE, next);
    if (result != CURLE_OK) {
        curl_slist_free_all(next);
        return false;
    }
    curl_slist_free_all(r->resolve);
    r->resolve = next;
    long remaining = (long)(r->deadline - now);
    long connect = remaining < 4000 ? remaining : 4000;
    /* Connect timeout includes TLS. Do not use an IP URL or disable certificate
     * checks: RESOLVE preserves the authority, SNI and CA/hostname validation.
     * Replacing the entry + FRESH_CONNECT avoids reusing the failed socket. */
    if (curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, connect) != CURLE_OK ||
        curl_easy_setopt(easy, CURLOPT_FRESH_CONNECT, 1L) != CURLE_OK ||
        (r->timeout_ms &&
         curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS,
                          r->timeout_ms < remaining ? r->timeout_ms : remaining) != CURLE_OK))
        return false;
    event(r, "try", ip, 0);
    return true;
}
#endif
bool sl_http_route_begin(sl_http_route *r, CURL *easy, const char *url, long timeout_ms) {
    memset(r, 0, sizeof(*r));
#if defined(__SWITCH__) || defined(NSL_HTTP_ROUTE_TEST)
    /* Hack rationale (D-A097): real-device logs show valid DNS answers but
     * intermittent TCP/TLS failure, including many siblings in one /24. A ping
     * is not proof HTTPS works; libcurl's automatic TCP fallback also does not
     * cover TLS failure. Query multiple providers once, interleave subnets and
     * try the REAL request on one candidate at a time, within 90s. No permanent
     * CDN blacklist, guessed Valve IPs, preflight requests or extra workers. */
    CURLU *parsed = curl_url();
    char *host = NULL, *scheme = NULL, *port = NULL;
    bool valid = parsed && curl_url_set(parsed, CURLUPART_URL, url, 0) == CURLUE_OK &&
                 curl_url_get(parsed, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK &&
                 !strcmp(scheme, "https") &&
                 curl_url_get(parsed, CURLUPART_HOST, &host, 0) == CURLUE_OK &&
                 strlen(host) < sizeof(r->host);
    if (valid) {
        strcpy(r->host, host);
        r->port = 443;
        if (curl_url_get(parsed, CURLUPART_PORT, &port, 0) == CURLUE_OK)
            r->port = (unsigned)atoi(port);
    }
    curl_free(host);
    curl_free(scheme);
    curl_free(port);
    curl_url_cleanup(parsed);
    if (!valid) {
        r->error = CURLE_URL_MALFORMAT;
        return false;
    }
    struct in_addr numeric;
    if (inet_pton(AF_INET, r->host, &numeric) == 1)
        return true;
    r->deadline = now_ms() + SL_HTTP_ROUTE_BUDGET_MS;
    r->timeout_ms = timeout_ms;
    sl_dns_refresh answer;
    if (!sl_dns_policy_lookup(r->host, &answer)) {
        r->error =
            sl_dns_policy_cancelled() ? CURLE_ABORTED_BY_CALLBACK : CURLE_COULDNT_RESOLVE_HOST;
        return false;
    }
    strcpy(r->addresses, answer.addresses);
    r->count = 1;
    for (const char *p = r->addresses; *p; ++p)
        if (*p == ',')
            ++r->count;
    if (select_address(r, easy))
        return true;
    r->error = sl_dns_policy_cancelled() ? CURLE_ABORTED_BY_CALLBACK : CURLE_FAILED_INIT;
    return false;
#else
    (void)easy;
    (void)url;
    (void)timeout_ms;
    return true; /* Desktop keeps its native resolver/connection policy. */
#endif
}
bool sl_http_route_retry(sl_http_route *r, CURL *easy, CURLcode code) {
#if defined(__SWITCH__) || defined(NSL_HTTP_ROUTE_TEST)
    if (!r->count || sl_dns_policy_cancelled())
        return false;
    long response = 0;
    curl_off_t bytes = 0;
    curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response);
    curl_easy_getinfo(easy, CURLINFO_SIZE_DOWNLOAD_T, &bytes);
    /* Only retry transport failures before any HTTP response/body. Never
     * concatenate partial downloads, replay application errors, or retry a
     * successful CONNECT_ONLY TLS handle used for the CM WebSocket. Certificate
     * failures may try another candidate, but verification always stays on. */
    bool network = code == CURLE_COULDNT_CONNECT || code == CURLE_OPERATION_TIMEDOUT ||
                   code == CURLE_SSL_CONNECT_ERROR || code == CURLE_PEER_FAILED_VERIFICATION ||
                   code == CURLE_GOT_NOTHING || code == CURLE_RECV_ERROR ||
                   code == CURLE_SEND_ERROR;
    if (!network || response || bytes)
        return false;
    event(r, "failed", "", (int)code);
    if (r->index + 1 >= r->count)
        return false;
    ++r->index;
    return select_address(r, easy);
#else
    (void)r;
    (void)easy;
    (void)code;
    return false;
#endif
}
void sl_http_route_clear(sl_http_route *r) {
    curl_slist_free_all(r->resolve);
    memset(r, 0, sizeof(*r));
}
CURLcode sl_http_route_perform(CURL *easy, const char *url, long timeout_ms) {
    sl_http_route route;
    CURLcode code;
    if (sl_http_route_begin(&route, easy, url, timeout_ms))
        do {
            code = curl_easy_perform(easy);
        } while (sl_http_route_retry(&route, easy, code));
    else
        code = route.error;
    /* The caller still owns easy. Detach the borrowed list before freeing it. */
    curl_easy_setopt(easy, CURLOPT_RESOLVE, NULL);
    sl_http_route_clear(&route);
    return code;
}
