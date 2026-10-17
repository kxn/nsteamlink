#include "dns_policy.h"
#include <arpa/inet.h>
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
    bool empty = scopes == NULL && scope_count == 0;
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
    bool begun = configured && sl_dns_refresh_begin(result, &config, normalized, start);
#if NSL_DIAGNOSTICS
    char line[224], local[INET_ADDRSTRLEN] = "", server[INET_ADDRSTRLEN] = "";
    if (configured) {
        inet_ntop(AF_INET, &config.local, local, sizeof(local));
        inet_ntop(AF_INET, &config.servers[0].sin_addr, server, sizeof(server));
    }
    snprintf(line, sizeof(line), "dns_query event=begin host=%s local=%s server=%s platform=%u",
             normalized, local, server, config.platform_error);
    sl_dns_policy_report(line);
#endif
    int status = -1;
    while (begun && !atomic_load(&s->cancelled) && !atomic_load(&stopped)) {
        uint64_t now = now_ms();
        if (now - start >= 3000)
            break;
        status = sl_dns_refresh_poll(result, now);
        if (status)
            break;
        struct timespec pause = {.tv_nsec = 1000000};
        nanosleep(&pause, NULL);
    }
    bool cancelled = atomic_load(&s->cancelled) || atomic_load(&stopped);
    bool success = status > 0 && !cancelled;
    sl_dns_refresh_cancel(result);
#if NSL_DIAGNOSTICS
    snprintf(line, sizeof(line), "dns_query event=%s host=%s addresses=%s elapsed_ms=%llu",
             success     ? "ready"
             : cancelled ? "cancelled"
                         : "failed",
             normalized, success ? result->addresses : "", (unsigned long long)(now_ms() - start));
    sl_dns_policy_report(line);
#endif
    if (temporary)
        remove_scope(s);
    return success;
}
