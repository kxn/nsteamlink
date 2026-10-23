#include "dns_policy.h"
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

typedef struct scope {
    struct scope *next;
    uint32_t token;
    atomic_bool cancelled;
} scope;
static pthread_mutex_t lock;
static scope *scopes;
static unsigned scope_count;
static _Thread_local scope *current;
static atomic_bool stopped = true;
/* Process-wide, not per lookup: updater, artwork, SDK and runtime may resolve
 * concurrently. Five providers must not become 5 * workers live sockets. */
static atomic_uint wire_queries;
static bool reserve_query(void) {
    unsigned active = atomic_load(&wire_queries);
    while (active < SL_DNS_SERVERS)
        if (atomic_compare_exchange_weak(&wire_queries, &active, active + 1))
            return true;
    return false;
}
static bool initialized;
#if NSL_DIAGNOSTICS
static void (*diagnostic)(const char *);
#endif
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
void sl_dns_policy_report(const char *line) {
#if NSL_DIAGNOSTICS
    if (diagnostic)
        diagnostic(line);
#else
    (void)line;
#endif
}
bool sl_dns_policy_init(void (*report)(const char *)) {
    if (initialized || pthread_mutex_init(&lock, NULL))
        return false;
    initialized = true;
    scopes = NULL;
    scope_count = 0;
    current = NULL;
    atomic_store(&wire_queries, 0);
    atomic_store(&stopped, false);
#if NSL_DIAGNOSTICS
    diagnostic = report;
#else
    (void)report;
#endif
    return true;
}
static scope *add_scope(uint32_t token) {
    if (!initialized || atomic_load(&stopped))
        return NULL;
    scope *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->token = token;
    atomic_init(&s->cancelled, false);
    pthread_mutex_lock(&lock);
    if (scope_count == 16 || atomic_load(&stopped)) {
        pthread_mutex_unlock(&lock);
        free(s);
        return NULL;
    }
    s->next = scopes;
    scopes = s;
    ++scope_count;
    pthread_mutex_unlock(&lock);
    return s;
}
static void remove_scope(scope *s) {
    if (!s)
        return;
    pthread_mutex_lock(&lock);
    scope **p = &scopes;
    while (*p && *p != s)
        p = &(*p)->next;
    if (*p) {
        *p = s->next;
        --scope_count;
    }
    pthread_mutex_unlock(&lock);
    free(s);
}
void sl_dns_policy_begin(uint32_t token) {
    remove_scope(current);
    current = add_scope(token);
}
void sl_dns_policy_end(uint32_t token) {
    if (current && current->token == token) {
        remove_scope(current);
        current = NULL;
    }
}
void sl_dns_policy_cancel(uint32_t token) {
    if (!initialized || !token)
        return;
    pthread_mutex_lock(&lock);
    for (scope *s = scopes; s; s = s->next)
        if (s->token == token)
            atomic_store(&s->cancelled, true);
    pthread_mutex_unlock(&lock);
}
void sl_dns_policy_stop_all(void) {
    atomic_store(&stopped, true);
    if (!initialized)
        return;
    pthread_mutex_lock(&lock);
    for (scope *s = scopes; s; s = s->next)
        atomic_store(&s->cancelled, true);
    pthread_mutex_unlock(&lock);
}
bool sl_dns_policy_shutdown(void) {
    sl_dns_policy_stop_all();
    if (!initialized)
        return true;
    pthread_mutex_lock(&lock);
    bool empty = scopes == NULL && scope_count == 0 && atomic_load(&wire_queries) == 0;
    scope *remaining = scopes;
    scopes = NULL;
    scope_count = 0;
    pthread_mutex_unlock(&lock);
    /* Contract: all resolving workers have joined. Clean any unmatched scope
     * too, while reporting the imbalance; no mutex/heap state crosses hbmenu. */
    while (remaining) {
        scope *next = remaining->next;
        free(remaining);
        remaining = next;
    }
    current = NULL;
    pthread_mutex_destroy(&lock);
    initialized = false;
#if NSL_DIAGNOSTICS
    diagnostic = NULL;
#endif
    return empty;
}
bool sl_dns_policy_cancelled(void) {
    return atomic_load(&stopped) || (current && atomic_load(&current->cancelled));
}
void sl_dns_policy_merge(sl_dns_refresh *out, const sl_dns_refresh *answers, unsigned count) {
    uint32_t ips[SL_DNS_CANDIDATES], groups[SL_DNS_CANDIDATES];
    unsigned used = 0, group_count = 0;
    out->addresses[0] = out->canonical[0] = 0;
    for (unsigned i = 0; i < count; ++i) {
        char copy[SL_DNS_ADDRESSES_SIZE];
        snprintf(copy, sizeof(copy), "%s", answers[i].addresses);
        char *state = NULL;
        for (char *ip = strtok_r(copy, ",", &state); ip; ip = strtok_r(NULL, ",", &state)) {
            struct in_addr address;
            if (inet_pton(AF_INET, ip, &address) != 1)
                continue;
            uint32_t value = ntohl(address.s_addr);
            unsigned j = 0;
            for (; j < used && ips[j] != value; ++j) {
            }
            if (j != used || used == SL_DNS_CANDIDATES)
                continue;
            ips[used++] = value;
            uint32_t group = value & 0xffffff00u;
            for (j = 0; j < group_count && groups[j] != group; ++j) {
            }
            if (j == group_count)
                groups[group_count++] = group;
            if (!out->canonical[0])
                snprintf(out->canonical, sizeof(out->canonical), "%s", answers[i].canonical);
        }
    }
    /* User observed correlated failures within a subnet. /24 is only an
     * ordering heuristic, not a route/ASN fact or a subnet ban: try the first
     * address of each group, then its second, etc. Never discard siblings. */
    size_t length = 0;
    for (unsigned round = 0; round < used; ++round)
        for (unsigned g = 0; g < group_count; ++g) {
            unsigned rank = 0;
            for (unsigned i = 0; i < used; ++i) {
                if ((ips[i] & 0xffffff00u) != groups[g] || rank++ != round)
                    continue;
                struct in_addr address = {.s_addr = htonl(ips[i])};
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &address, ip, sizeof(ip));
                length += snprintf(out->addresses + length, sizeof(out->addresses) - length, "%s%s",
                                   length ? "," : "", ip);
            }
        }
}
bool sl_dns_policy_lookup(const char *host, sl_dns_refresh *result) {
    memset(result, 0, sizeof(*result));
    result->fd = -1;
    if (!host || !host[0] || strlen(host) > 253)
        return false;
    char normalized[254];
    strcpy(normalized, host);
    size_t n = strlen(normalized);
    if (normalized[n - 1] == '.')
        normalized[n - 1] = 0;
    /* Sanitize before any diagnostic. Only ordinary DNS hostname bytes. */
    for (const char *p = normalized; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
              *p == '-' || *p == '.'))
            return false;
    scope *s = current ? current : add_scope(0);
    if (!s)
        return false;
    bool temporary = s != current;
    sl_dns_config config = {0};
    uint64_t start = now_ms();
    bool configured =
        !atomic_load(&s->cancelled) && !atomic_load(&stopped) && sl_dns_current_config(&config);
    /* Fan out on this existing worker, no threads or cross-network cache.
     * Wait for all providers (or the shared 3s deadline), so a fast first
     * answer does not suppress address diversity. Allocate wire buffers on
     * heap: five DNS/TCP states would be excessive on a Switch worker stack. */
    unsigned count = configured ? config.count : 0;
    if (count > SL_DNS_SERVERS)
        count = 0;
    sl_dns_refresh *queries = count ? calloc(count, sizeof(*queries)) : NULL;
    int states[SL_DNS_SERVERS] = {0}, start_errors[SL_DNS_SERVERS] = {0};
    unsigned starts[SL_DNS_SERVERS] = {0};
    uint64_t next_start[SL_DNS_SERVERS] = {0};
    bool held[SL_DNS_SERVERS] = {0};
    if (!queries)
        count = 0;
    for (unsigned i = 0; i < count; ++i) {
        queries[i].fd = -1;
        states[i] = 2; /* queued; 0=active, 1=success, -1=terminal failure */
    }
    while (count && !atomic_load(&s->cancelled) && !atomic_load(&stopped)) {
        uint64_t now = now_ms();
        if (now - start >= 3000)
            break;
        bool pending = false;
        for (unsigned i = 0; i < count; ++i) {
            if (states[i] == 2 && now >= next_start[i] && reserve_query()) {
                held[i] = true;
                sl_dns_config single = config;
                single.count = 1;
                single.servers[0] = config.servers[i];
                errno = 0;
                bool begun = sl_dns_refresh_begin(&queries[i], &single, normalized, now);
                start_errors[i] = begun ? 0 : errno;
                ++starts[i];
                states[i] = begun ? 0 : -1;
                /* A local resource shortage is not a negative DNS answer.
                 * Wait inside the SAME 3s budget, allowing another owner to
                 * close its query sockets; never spin/retry on the UI thread. */
                if (!begun && (errno == ENOBUFS || errno == ENOMEM || errno == EMFILE ||
                               errno == ENFILE || errno == EAGAIN)) {
                    states[i] = 2;
                    next_start[i] = now + 50;
                }
#if NSL_DIAGNOSTICS
                if (starts[i] == 1) {
                    char line[384], local[INET_ADDRSTRLEN] = "", server[INET_ADDRSTRLEN] = "";
                    inet_ntop(AF_INET, &config.local, local, sizeof(local));
                    inet_ntop(AF_INET, &single.servers[0].sin_addr, server, sizeof(server));
                    snprintf(line, sizeof(line),
                             "dns_query event=begin host=%s local=%s server=%s platform=%u "
                             "started=%d os=%d",
                             normalized, local, server, config.platform_error, begun,
                             start_errors[i]);
                    sl_dns_policy_report(line);
                }
#endif
            }
            if (!states[i])
                states[i] = sl_dns_refresh_poll(&queries[i], now);
            if (held[i] && states[i]) {
                sl_dns_refresh_cancel(&queries[i]);
                atomic_fetch_sub(&wire_queries, 1);
                held[i] = false;
            }
            pending |= states[i] == 0 || states[i] == 2;
        }
        if (!pending)
            break;
        struct timespec pause = {.tv_nsec = 1000000};
        nanosleep(&pause, NULL);
    }
    bool cancelled = atomic_load(&s->cancelled) || atomic_load(&stopped);
    for (unsigned i = 0; i < count; ++i) {
        sl_dns_refresh_cancel(&queries[i]);
        if (held[i])
            atomic_fetch_sub(&wire_queries, 1);
        if (states[i] != 1 || cancelled)
            queries[i].addresses[0] = 0;
#if NSL_DIAGNOSTICS
        char line[640], server[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &config.servers[i].sin_addr, server, sizeof(server));
        snprintf(
            line, sizeof(line),
            "dns_query event=answer host=%s server=%s status=%d addresses=%s starts=%u start_os=%d",
            normalized, server, states[i], queries[i].addresses, starts[i], start_errors[i]);
        sl_dns_policy_report(line);
#endif
    }
    sl_dns_policy_merge(result, queries, count);
    free(queries);
    bool success = result->addresses[0] && !cancelled;
#if NSL_DIAGNOSTICS
    char line[640];
    snprintf(line, sizeof(line),
             "dns_query event=%s host=%s addresses=%s elapsed_ms=%llu platform=%u",
             success     ? "ready"
             : cancelled ? "cancelled"
                         : "failed",
             normalized, success ? result->addresses : "", (unsigned long long)(now_ms() - start),
             config.platform_error);
    sl_dns_policy_report(line);
#endif
    if (temporary)
        remove_scope(s);
    return success;
}
