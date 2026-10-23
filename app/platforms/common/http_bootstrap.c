#include "http_bootstrap.h"
#include "dns_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__SWITCH__) || defined(NSL_HTTP_ROUTE_TEST)
#define ATTEMPTS 3
#else
#define ATTEMPTS 1
#endif
struct attempt {
    CURL *easy;
    struct curl_slist *resolve;
    uint8_t *body;
    size_t size, limit;
    unsigned candidate;
    bool added;
};
struct sl_http_bootstrap {
    CURLM *multi;       /* Borrowed; all active handles belong to this bootstrap. */
    sl_http_route plan; /* One DNS subscription/cursor for ALL candidates. */
    struct attempt attempts[ATTEMPTS];
    sl_http_bootstrap_options options;
    void *context;
    char *url;
    size_t limit;
    bool tls_only, native_attempted;
    struct attempt *response_owner;
    uint64_t deadline, next_start;
    CURLcode failure;
};
static size_t receive(char *data, size_t size, size_t count, void *context) {
    struct attempt *a = context;
    if (size && count > SIZE_MAX / size)
        return 0;
    size_t bytes = size * count;
    if (bytes > a->limit - a->size)
        return 0;
    uint8_t *next = realloc(a->body, a->size + bytes + 1);
    if (!next)
        return 0;
    a->body = next;
    if (bytes)
        memcpy(next + a->size, data, bytes);
    a->size += bytes;
    next[a->size] = 0;
    return bytes;
}
static void clear(sl_http_bootstrap *b, struct attempt *a) {
    if (a->easy) {
        if (a->added)
            curl_multi_remove_handle(b->multi, a->easy);
        curl_easy_cleanup(a->easy);
    }
    curl_slist_free_all(a->resolve);
    free(a->body);
    memset(a, 0, sizeof(*a));
}
static bool configure(sl_http_bootstrap *b, struct attempt *a) {
    a->limit = b->limit;
    a->easy = curl_easy_init();
    if (!a->easy || !b->options(a->easy, b->tls_only, b->context))
        return false;
    return curl_easy_setopt(a->easy, CURLOPT_URL, b->url) == CURLE_OK &&
           curl_easy_setopt(a->easy, CURLOPT_WRITEFUNCTION, receive) == CURLE_OK &&
           curl_easy_setopt(a->easy, CURLOPT_WRITEDATA, a) == CURLE_OK;
}
sl_http_bootstrap *sl_http_bootstrap_create(CURLM *multi, const char *url, bool tls_only,
                                            size_t limit, uint64_t now,
                                            sl_http_bootstrap_options options, void *context) {
    sl_http_bootstrap *b = calloc(1, sizeof(*b));
    if (!b)
        return NULL;
    b->multi = multi;
    b->options = options;
    b->context = context;
    b->url = strdup(url);
    b->tls_only = tls_only;
    b->limit = limit;
    b->deadline = now + 20000;
    b->failure = CURLE_COULDNT_CONNECT;
    if (!b->url || !configure(b, &b->attempts[0]) ||
        !sl_http_route_begin_async(&b->plan, b->attempts[0].easy, url, 20000)) {
        sl_http_bootstrap_destroy(b);
        return NULL;
    }
    if (b->plan.deadline)
        b->deadline = b->plan.deadline;
    return b;
}
int sl_http_bootstrap_poll(sl_http_bootstrap *b, uint64_t now, CURL **winner, sl_http_route *route,
                           uint8_t **body, size_t *size, CURLcode *code) {
    *code = b->failure;
    if (now >= b->deadline || (b->plan.deadline && sl_dns_policy_cancelled())) {
        *code = now >= b->deadline ? CURLE_OPERATION_TIMEDOUT : CURLE_ABORTED_BY_CALLBACK;
        return -1;
    }
    int running = 0, remaining = 0;
    if (curl_multi_perform(b->multi, &running) != CURLM_OK) {
        *code = CURLE_FAILED_INIT;
        return -1;
    }
    CURLMsg *message;
    while ((message = curl_multi_info_read(b->multi, &remaining))) {
        if (message->msg != CURLMSG_DONE)
            continue;
        for (unsigned i = 0; i < ATTEMPTS; ++i) {
            struct attempt *a = &b->attempts[i];
            if (!a->added || message->easy_handle != a->easy)
                continue;
            CURLcode result = message->data.result;
            if (sl_http_route_transport_failure(a->easy, result)) {
                b->failure = result;
#if NSL_DIAGNOSTICS
                char line[384];
                snprintf(line, sizeof(line),
                         "https_bootstrap event=failed host=%s candidate=%u curl=%d", b->plan.host,
                         a->candidate + 1, (int)result);
                sl_dns_policy_report(line);
#endif
#if NSL_DIAGNOSTICS
                long os = 0, verified = 0;
                double tcp = 0, tls = 0;
                curl_easy_getinfo(a->easy, CURLINFO_OS_ERRNO, &os);
                curl_easy_getinfo(a->easy, CURLINFO_SSL_VERIFYRESULT, &verified);
                curl_easy_getinfo(a->easy, CURLINFO_CONNECT_TIME, &tcp);
                curl_easy_getinfo(a->easy, CURLINFO_APPCONNECT_TIME, &tls);
                snprintf(
                    line, sizeof(line),
                    "https_bootstrap_error candidate=%u os=%ld verify=%ld tcp_ms=%.0f tls_ms=%.0f",
                    a->candidate + 1, os, verified, tcp * 1000, tls * 1000);
                sl_dns_policy_report(line);
#endif
                clear(b, a);
                b->next_start = now; /* Refill a failed slot without another delay. */
            } else {
                /* First completed response wins, including HTTP/application or
                 * partial-body errors. Do not combine bodies or replay an RPC.
                 * Keep the winning TLS easy in multi until the caller is done. */
                *code = result;
                *winner = a->easy;
                *route = b->plan;
                route->resolve = a->resolve;
                route->index = a->candidate;
                *body = a->body;
                *size = a->size;
                a->easy = NULL;
                a->resolve = NULL;
                a->body = NULL;
                memset(&b->plan, 0, sizeof(b->plan));
                return 1;
            }
            break;
        }
    }
    /* Once HTTP has answered, commit to that response even if its body is
     * slow or incomplete. Never launch a replacement after observing headers,
     * and never splice a second candidate's body into the selected response. */
    if (!b->tls_only && !b->response_owner) {
        for (unsigned i = 0; i < ATTEMPTS; ++i) {
            struct attempt *a = &b->attempts[i];
            long status = 0;
            if (a->added)
                curl_easy_getinfo(a->easy, CURLINFO_RESPONSE_CODE, &status);
            if (status) {
                b->response_owner = a;
                break;
            }
        }
        if (b->response_owner) {
            for (unsigned i = 0; i < ATTEMPTS; ++i)
                if (&b->attempts[i] != b->response_owner)
                    clear(b, &b->attempts[i]);
            sl_http_route_stop_resolving(&b->plan);
        }
    }
    if (b->response_owner)
        return 0;
    unsigned active = 0;
    for (unsigned i = 0; i < ATTEMPTS; ++i)
        active += b->attempts[i].added;
    if (active && now < b->next_start)
        return 0;
    for (unsigned i = 0; i < ATTEMPTS; ++i) {
        struct attempt *a = &b->attempts[i];
        if (a->added)
            continue;
        if (!b->plan.deadline && b->native_attempted) {
            *code = b->failure;
            return -1;
        }
        if (!a->easy && !configure(b, a)) {
            *code = CURLE_FAILED_INIT;
            return -1;
        }
        int ready = sl_http_route_poll(&b->plan, a->easy);
        if (!ready)
            return 0;
        if (ready < 0) {
            if (active)
                return 0; /* Another assigned candidate may still win. */
            *code = b->failure == CURLE_COULDNT_CONNECT ? b->plan.error : b->failure;
            return -1;
        }
        b->native_attempted = true;
        a->candidate = b->plan.index;
        a->resolve = b->plan.resolve;
        b->plan.resolve = NULL;
        /* Assign once, globally. Late DNS answers can append candidates but
         * cannot renumber or reassign the already-attempted prefix. */
        ++b->plan.index;
        b->plan.select_pending = true;
        if (curl_multi_add_handle(b->multi, a->easy) != CURLM_OK) {
            *code = CURLE_FAILED_INIT;
            return -1;
        }
        a->added = true;
        b->next_start = now + 250;
        return 0;
    }
    return 0;
}
uint64_t sl_http_bootstrap_deadline(const sl_http_bootstrap *b) {
    return b->deadline;
}
void sl_http_bootstrap_destroy(sl_http_bootstrap *b) {
    if (!b)
        return;
    for (unsigned i = 0; i < ATTEMPTS; ++i)
        clear(b, &b->attempts[i]);
    sl_http_route_clear(&b->plan); /* Last subscriber stops/joins DNS after easy cleanup. */
    free(b->url);
    free(b);
}
