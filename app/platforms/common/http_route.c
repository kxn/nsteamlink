#include "http_route.h"
#include "dns_policy.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The deployed curl 7.69 backend predates thread-safe global initialization.
 * Modules own references, not independent concurrent init/cleanup operations.
 * Keep platform TLS/allocator state alive through the last handle/worker. */
static pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned global_owners;
bool sl_http_global_acquire(void) {
    pthread_mutex_lock(&global_lock);
    bool ok = global_owners || curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
    if (ok)
        ++global_owners;
    pthread_mutex_unlock(&global_lock);
    return ok;
}
void sl_http_global_release(void) {
    pthread_mutex_lock(&global_lock);
    if (global_owners && --global_owners == 0)
        curl_global_cleanup();
    pthread_mutex_unlock(&global_lock);
}

#if defined(__SWITCH__) || defined(NSL_HTTP_ROUTE_TEST)
struct sl_http_dns {
    struct sl_http_dns *next;
    unsigned readers; /* Protected by dns_jobs_lock; each route owns one. */
    pthread_t thread;
    pthread_mutex_t lock;
    atomic_bool done, cancel;
    char host[254];
    char addresses[SL_DNS_ADDRESSES_SIZE];
};
/* Only in-flight work is shared. No IP/CM cache, TTL or cross-launch state.
 * Startup directory/config/artwork requests for the same host subscribe to one
 * paced lookup rather than each creating five competing wire queries. CURL
 * handles, candidate cursors, request deadlines and cancellation stay private. */
static pthread_mutex_t dns_jobs_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sl_http_dns *dns_jobs;
static bool dns_cancelled(void *context) {
    return atomic_load(&((struct sl_http_dns *)context)->cancel);
}
static void dns_available(const sl_dns_refresh *answer, void *context) {
    struct sl_http_dns *job = context;
    pthread_mutex_lock(&job->lock);
    strcpy(job->addresses, answer->addresses);
    pthread_mutex_unlock(&job->lock);
}
static void *dns_worker(void *context) {
    struct sl_http_dns *job = context;
    sl_dns_refresh answer;
    sl_dns_policy_lookup_progressive(job->host, &answer, dns_cancelled, job, dns_available);
    atomic_store_explicit(&job->done, true, memory_order_release);
    return NULL;
}
static struct sl_http_dns *acquire_dns(const char *host) {
    pthread_mutex_lock(&dns_jobs_lock);
    for (struct sl_http_dns *job = dns_jobs; job; job = job->next) {
        if (!strcmp(job->host, host) && !atomic_load_explicit(&job->done, memory_order_acquire)) {
            ++job->readers;
            pthread_mutex_unlock(&dns_jobs_lock);
            return job;
        }
    }
    struct sl_http_dns *job = calloc(1, sizeof(*job));
    if (job) {
        strcpy(job->host, host);
        atomic_init(&job->done, false);
        atomic_init(&job->cancel, false);
        if (pthread_mutex_init(&job->lock, NULL)) {
            free(job);
            job = NULL;
        } else if (pthread_create(&job->thread, NULL, dns_worker, job)) {
            pthread_mutex_destroy(&job->lock);
            free(job);
            job = NULL;
        }
    }
    if (job) {
        job->readers = 1;
        job->next = dns_jobs;
        dns_jobs = job;
    }
    pthread_mutex_unlock(&dns_jobs_lock);
    return job;
}
/* Releasing one subscriber must not cancel another request's lookup. The last
 * subscriber removes the job before stop/join, without holding registry locks.
 * No worker accesses CURL, route storage, or the registry after its owner dies. */
static void clear_dns(sl_http_route *r) {
    struct sl_http_dns *job = r->dns;
    if (!job)
        return;
    r->dns = NULL;
    pthread_mutex_lock(&dns_jobs_lock);
    bool last = --job->readers == 0;
    if (last) {
        struct sl_http_dns **link = &dns_jobs;
        while (*link != job)
            link = &(*link)->next;
        *link = job->next;
        atomic_store(&job->cancel, true);
    }
    pthread_mutex_unlock(&dns_jobs_lock);
    if (!last)
        return;
    pthread_join(job->thread, NULL);
    pthread_mutex_destroy(&job->lock);
    free(job);
}
/* Append/dedupe published addresses, retaining the attempted prefix. Never
 * change RESOLVE while CURL owns an active transfer. Newly learned subnets are
 * preferred at the NEXT attempt, not allowed to renumber the current one. */
static void append_addresses(sl_http_route *r, const char *addresses) {
    char copy[SL_DNS_ADDRESSES_SIZE];
    strcpy(copy, addresses);
    char *state = NULL;
    for (char *ip = strtok_r(copy, ",", &state); ip; ip = strtok_r(NULL, ",", &state)) {
        struct in_addr address;
        if (inet_pton(AF_INET, ip, &address) != 1 || r->count == SL_DNS_CANDIDATES)
            continue;
        char existing[SL_DNS_ADDRESSES_SIZE];
        strcpy(existing, r->addresses);
        char *cursor = NULL;
        bool duplicate = false;
        for (char *p = strtok_r(existing, ",", &cursor); p; p = strtok_r(NULL, ",", &cursor))
            duplicate |= !strcmp(p, ip);
        if (duplicate)
            continue;
        size_t used = strlen(r->addresses);
        snprintf(r->addresses + used, sizeof(r->addresses) - used, "%s%s", used ? "," : "", ip);
        ++r->count;
    }
}
static void collect_dns(sl_http_route *r) {
    if (!r->dns)
        return;
    char addresses[SL_DNS_ADDRESSES_SIZE];
    pthread_mutex_lock(&r->dns->lock);
    strcpy(addresses, r->dns->addresses);
    pthread_mutex_unlock(&r->dns->lock);
    append_addresses(r, addresses);
    if (atomic_load_explicit(&r->dns->done, memory_order_acquire)) {
        /* Re-read after acquiring completion: the last publication might have
         * happened between the first snapshot and observing done. */
        pthread_mutex_lock(&r->dns->lock);
        strcpy(addresses, r->dns->addresses);
        pthread_mutex_unlock(&r->dns->lock);
        append_addresses(r, addresses);
        clear_dns(r);
    }
}
static void prioritize_next(sl_http_route *r) {
    char copy[SL_DNS_ADDRESSES_SIZE], *ips[SL_DNS_CANDIDATES], *state = NULL;
    uint32_t groups[SL_DNS_CANDIDATES];
    strcpy(copy, r->addresses);
    unsigned count = 0;
    for (char *ip = strtok_r(copy, ",", &state); ip && count < SL_DNS_CANDIDATES;
         ip = strtok_r(NULL, ",", &state)) {
        struct in_addr address;
        inet_pton(AF_INET, ip, &address);
        ips[count] = ip;
        groups[count++] = ntohl(address.s_addr) & 0xffffff00u;
    }
    unsigned best = r->index, score = SL_DNS_CANDIDATES + 1;
    for (unsigned i = r->index; i < count; ++i) {
        unsigned tried = 0;
        for (unsigned j = 0; j < r->index; ++j)
            tried += groups[j] == groups[i];
        if (tried < score) {
            best = i;
            score = tried;
        }
    }
    char *ip = ips[r->index];
    ips[r->index] = ips[best];
    ips[best] = ip;
    size_t used = 0;
    for (unsigned i = 0; i < count; ++i)
        used += snprintf(r->addresses + used, sizeof(r->addresses) - used, "%s%s", i ? "," : "",
                         ips[i]);
}
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
    r->select_pending = false;
    return true;
}

#endif
static bool begin(sl_http_route *r, CURL *easy, const char *url, long timeout_ms, bool async) {
    memset(r, 0, sizeof(*r));
#if defined(__SWITCH__) || defined(NSL_HTTP_ROUTE_TEST)
    /* Hack rationale (D-A097): real-device logs show valid DNS answers but
     * intermittent TCP/TLS failure, including many siblings in one /24. A ping
     * is not proof HTTPS works; libcurl's automatic TCP fallback also does not
     * cover TLS failure. Query multiple providers once, interleave subnets and
     * try the REAL request on one candidate at a time, within 90s. No permanent
     * CDN blacklist, guessed Valve IPs or preflight requests. D-A099 moves DNS
     * off polled owners. D-A102 publishes a first answer immediately instead
     * of waiting for all DNS providers; later answers extend the fallback list.
     * Owners subscribe to in-flight same-host DNS work (D-A104); final
     * release cancels/joins it. Their TLS cannot stop other subscribers or
     * collection of remaining providers. */
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
    r->select_pending = true;
    r->dns = acquire_dns(r->host);
    if (!r->dns) {
        r->error = CURLE_FAILED_INIT;
        return false;
    }
    if (async)
        return true;
    int ready;
    while (!(ready = sl_http_route_poll(r, easy))) {
        struct timespec pause = {.tv_nsec = 1000000};
        nanosleep(&pause, NULL);
    }
    return ready > 0;
#else
    (void)easy;
    (void)url;
    (void)timeout_ms;
    (void)async;
    return true; /* Desktop keeps its native resolver/connection policy. */
#endif
}
bool sl_http_route_begin(sl_http_route *r, CURL *easy, const char *url, long timeout_ms) {
    return begin(r, easy, url, timeout_ms, false);
}
bool sl_http_route_begin_async(sl_http_route *r, CURL *easy, const char *url, long timeout_ms) {
    return begin(r, easy, url, timeout_ms, true);
}
int sl_http_route_poll(sl_http_route *r, CURL *easy) {
    if (r->error != CURLE_OK)
        return -1;
#if defined(__SWITCH__) || defined(NSL_HTTP_ROUTE_TEST)
    collect_dns(r);
    if (!r->select_pending)
        return 1;
    if (sl_dns_policy_cancelled())
        r->error = CURLE_ABORTED_BY_CALLBACK;
    else if (now_ms() >= r->deadline)
        r->error = CURLE_OPERATION_TIMEDOUT;
    else if (r->index < r->count) {
        prioritize_next(r);
        if (select_address(r, easy))
            return 1;
        r->error = CURLE_FAILED_INIT;
    } else if (r->dns)
        return 0; /* More providers may still supply a new IP. */
    else
        r->error = r->failure ? r->failure : CURLE_COULDNT_RESOLVE_HOST;
    return -1;
#else
    (void)easy;
    return 1;
#endif
}
bool sl_http_route_transport_failure(CURL *easy, CURLcode code) {
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
    return network && !response && !bytes;
}
bool sl_http_route_retry(sl_http_route *r, CURL *easy, CURLcode code) {
#if defined(__SWITCH__) || defined(NSL_HTTP_ROUTE_TEST)
    if (!r->count || sl_dns_policy_cancelled() || !sl_http_route_transport_failure(easy, code))
        return false;
    event(r, "failed", "", (int)code);
    ++r->index;
    r->failure = code;
    r->select_pending = true;
    return sl_http_route_poll(r, easy) >= 0;
#else
    (void)r;
    (void)easy;
    (void)code;
    return false;
#endif
}
void sl_http_route_stop_resolving(sl_http_route *r) {
#if defined(__SWITCH__) || defined(NSL_HTTP_ROUTE_TEST)
    clear_dns(r);
#else
    (void)r;
#endif
}
void sl_http_route_clear(sl_http_route *r) {
#if defined(__SWITCH__) || defined(NSL_HTTP_ROUTE_TEST)
    clear_dns(r);
#endif
    curl_slist_free_all(r->resolve);
    memset(r, 0, sizeof(*r));
}
CURLcode sl_http_route_perform(CURL *easy, const char *url, long timeout_ms) {
    sl_http_route route;
    CURLcode code;
    if (sl_http_route_begin(&route, easy, url, timeout_ms))
        do {
            int ready;
            while (!(ready = sl_http_route_poll(&route, easy))) {
                struct timespec pause = {.tv_nsec = 1000000};
                nanosleep(&pause, NULL);
            }
            if (ready < 0) {
                code = route.error;
                break;
            }
            code = curl_easy_perform(easy);
        } while (sl_http_route_retry(&route, easy, code));
    else
        code = route.error;
    /* The caller still owns easy. Detach the borrowed list before freeing it. */
    curl_easy_setopt(easy, CURLOPT_RESOLVE, NULL);
    sl_http_route_clear(&route);
    return code;
}
