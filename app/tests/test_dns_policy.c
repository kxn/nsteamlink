#include "dns_policy.h"
#include <arpa/inet.h>
#include <assert.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

int __wrap_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
CURL *__wrap_curl_easy_init(void);
static unsigned numeric_calls, cache_disabled;
int __real_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints,
                       struct addrinfo **out) {
    unsigned char bytes[16];
    assert(!host || !host[0] || inet_pton(AF_INET, host, bytes) == 1 ||
           inet_pton(AF_INET6, host, bytes) == 1 || !strcmp(host, "localhost") ||
           (hints && (hints->ai_flags & AI_NUMERICHOST)));
    ++numeric_calls;
    return getaddrinfo(host, service, hints, out);
}
CURL *__real_curl_easy_init(void) {
    return curl_easy_init();
}
CURLcode __real_curl_easy_setopt(CURL *, CURLoption, ...);
CURLcode __wrap_curl_easy_setopt(CURL *easy, CURLoption option, ...) {
    assert(option == CURLOPT_DNS_CACHE_TIMEOUT);
    va_list args;
    va_start(args, option);
    long value = va_arg(args, long);
    va_end(args);
    assert(value == 0);
    ++cache_disabled;
    return __real_curl_easy_setopt(easy, option, value);
}
static sl_dns_config config;
static pthread_mutex_t config_lock = PTHREAD_MUTEX_INITIALIZER;
bool __wrap_sl_dns_current_config(sl_dns_config *out) {
    pthread_mutex_lock(&config_lock);
    *out = config;
    pthread_mutex_unlock(&config_lock);
    return out->count != 0;
}
typedef struct {
    int fd;
    pthread_t worker;
    atomic_bool stop, drop;
    atomic_uint queries;
    unsigned network;
    struct sockaddr_in address;
    char hosts[32][254];
} fixture;
static void *dns_server(void *context) {
    fixture *f = context;
    while (!atomic_load(&f->stop)) {
        uint8_t packet[512];
        struct sockaddr_in peer;
        socklen_t length = sizeof(peer);
        ssize_t n = recvfrom(f->fd, packet, sizeof(packet), 0, (struct sockaddr *)&peer, &length);
        if (n < 17)
            continue;
        size_t p = 12, used = 0;
        char name[254];
        while (p < (size_t)n && packet[p]) {
            unsigned size = packet[p++];
            assert(size <= 63 && size < (size_t)n - p);
            if (used)
                name[used++] = '.';
            assert(used + size < sizeof(name));
            memcpy(name + used, packet + p, size);
            used += size;
            p += size;
        }
        name[used] = 0;
        unsigned index = atomic_load(&f->queries);
        if (index < 32)
            strcpy(f->hosts[index], name);
        atomic_fetch_add(&f->queries, 1);
        if (atomic_load(&f->drop))
            continue;
        assert((size_t)n + 32 < sizeof(packet));
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6] = 0;
        packet[7] = 2;
        for (unsigned i = 0; i < 2; ++i) {
            uint8_t answer[] = {0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 0};
            answer[15] = (uint8_t)(f->network + i);
            memcpy(packet + n, answer, sizeof(answer));
            n += sizeof(answer);
        }
        assert(sendto(f->fd, packet, (size_t)n, 0, (struct sockaddr *)&peer, sizeof(peer)) == n);
    }
    return NULL;
}
static void start_fixture(fixture *f, unsigned network) {
    memset(f, 0, sizeof(*f));
    f->network = network;
    atomic_init(&f->stop, false);
    atomic_init(&f->drop, false);
    atomic_init(&f->queries, 0);
    f->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(f->fd >= 0);
    f->address =
        (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(f->fd, (struct sockaddr *)&f->address, sizeof(f->address)) == 0);
    socklen_t length = sizeof(f->address);
    assert(getsockname(f->fd, (struct sockaddr *)&f->address, &length) == 0);
    struct timeval timeout = {.tv_usec = 10000};
    assert(setsockopt(f->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    assert(pthread_create(&f->worker, NULL, dns_server, f) == 0);
}
static void use_fixture(fixture *f) {
    pthread_mutex_lock(&config_lock);
    config = (sl_dns_config){.count = 1, .local = htonl(0xc0000200 | f->network)};
    config.servers[0] = f->address;
    pthread_mutex_unlock(&config_lock);
}
static unsigned open_fds(void) {
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd) count += fcntl(fd, F_GETFD) != -1;
    return count;
}
static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void verify_host(const char *host, unsigned network, bool canonical) {
    struct addrinfo hints = {.ai_family = AF_INET,
                             .ai_socktype = SOCK_STREAM,
                             .ai_flags = canonical ? AI_CANONNAME : 0},
                    *result = NULL;
    assert(__wrap_getaddrinfo(host, "443", &hints, &result) == 0);
    unsigned count = 0;
    for (struct addrinfo *p = result; p; p = p->ai_next) {
        assert(p->ai_family == AF_INET && p->ai_socktype == SOCK_STREAM);
        const struct sockaddr_in *address = (const struct sockaddr_in *)p->ai_addr;
        assert(ntohs(address->sin_port) == 443);
        assert(ntohl(address->sin_addr.s_addr) == (0xc6336400 | (network + count)));
        if (!count && canonical)
            assert(!strcmp(p->ai_canonname, host));
        ++count;
    }
    assert(count == 2);
    freeaddrinfo(result);
}
static void *cancelled_lookup(void *arg) {
    uint32_t token = *(uint32_t *)arg;
    if (token)
        sl_dns_policy_begin(token);
    struct addrinfo *result = NULL;
    assert(__wrap_getaddrinfo("cancel.example", "443", NULL, &result) == EAI_AGAIN && !result);
    if (token)
        sl_dns_policy_end(token);
    return NULL;
}
int main(void) {
    fixture first, second;
    start_fixture(&first, 7);
    start_fixture(&second, 27);
    assert(sl_dns_policy_init(NULL));
    use_fixture(&first);
    const char *hosts[] = {"api.steampowered.com",   "cmp1-test.steamserver.net",
                           "api.steampowered.com",   "stun.example",
                           "shared.steamstatic.com", "api.github.com"};
    /* Repeated API lookup represents independent directory/SDR easy handles;
     * SDK hostnames and artwork/updater names share exactly the same policy. */
    for (unsigned i = 0; i < sizeof(hosts) / sizeof(hosts[0]); ++i)
        verify_host(hosts[i], 7, i == 0);
    assert(atomic_load(&first.queries) == 6);
    for (unsigned i = 0; i < 6; ++i)
        assert(!strcmp(first.hosts[i], hosts[i]));
    use_fixture(&second);
    verify_host("api.steampowered.com", 27, false);
    verify_host("cmp1-test.steamserver.net", 27, false);
    assert(atomic_load(&second.queries) == 2); /* Same process, changed DNS/interface. */
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_DGRAM}, *result = NULL;
    assert(__wrap_getaddrinfo("127.0.0.1", "27031", &hints, &result) == 0);
    assert(result->ai_socktype == SOCK_DGRAM);
    freeaddrinfo(result);
    assert(atomic_load(&second.queries) == 2);
    for (unsigned i = 0; i < 3; ++i) {
        CURL *easy = __wrap_curl_easy_init();
        assert(easy);
        curl_easy_cleanup(easy);
    }
    assert(cache_disabled == 3 && numeric_calls >= 17);
    /* Missing current DNS fails explicitly: the real SDK sees no hostname. */
    pthread_mutex_lock(&config_lock);
    config.count = 0;
    pthread_mutex_unlock(&config_lock);
    assert(__wrap_getaddrinfo("must-not-query.invalid", "443", NULL, &result) == EAI_AGAIN);
    /* Fanout really sends to both providers, retains their unique answers,
     * dedupes repeated servers, and bounds a nonresponsive provider separately. */
    pthread_mutex_lock(&config_lock);
    config.count = 3;
    config.servers[0] = first.address;
    config.servers[1] = second.address;
    config.servers[2] = first.address;
    pthread_mutex_unlock(&config_lock);
    sl_dns_refresh merged;
    unsigned fd_baseline = open_fds();
    assert(sl_dns_policy_lookup("fanout.example", &merged));
    assert(open_fds() == fd_baseline);
    assert(!strcmp(merged.addresses, "198.51.100.7,198.51.100.8,198.51.100.27,198.51.100.28"));
    sl_dns_refresh samples[3] = {0};
    strcpy(samples[0].addresses, "88.221.83.200,88.221.83.187");
    strcpy(samples[1].addresses, "88.221.83.187,2.17.107.128");
    strcpy(samples[2].addresses, "104.110.240.106,2.17.107.129");
    sl_dns_policy_merge(&merged, samples, 3);
    assert(!strcmp(merged.addresses, "88.221.83.200,2.17.107.128,104.110.240.106,88.221.83.187,2.17.107.129"));
    /* A dead provider neither suppresses the live result nor leaks its UDP
     * retries; the shared deadline bounds the batch, not each server in turn. */
    atomic_store(&first.drop, true);
    pthread_mutex_lock(&config_lock);
    config.count = 2;
    config.servers[0] = first.address;
    config.servers[1] = second.address;
    pthread_mutex_unlock(&config_lock);
    uint64_t fanout_start = now_ms();
    assert(sl_dns_policy_lookup("one-dead.example", &merged));
    assert(now_ms() - fanout_start < 3500 && open_fds() == fd_baseline);
    assert(!strcmp(merged.addresses, "198.51.100.27,198.51.100.28"));
    use_fixture(&second);
    atomic_store(&second.drop, true);
    for (unsigned mode = 0; mode < 2; ++mode) {
        uint32_t token = mode ? 0 : 77;
        unsigned before = atomic_load(&second.queries);
        pthread_t thread;
        assert(pthread_create(&thread, NULL, cancelled_lookup, &token) == 0);
        uint64_t until = now_ms() + 1000;
        while (atomic_load(&second.queries) == before && now_ms() < until)
            usleep(1000);
        assert(atomic_load(&second.queries) > before);
        uint64_t start = now_ms();
        if (mode)
            sl_dns_policy_stop_all();
        else
            sl_dns_policy_cancel(token);
        assert(pthread_join(thread, NULL) == 0 && now_ms() - start < 500);
    }
    assert(sl_dns_policy_shutdown());
    assert(open_fds() == fd_baseline);
    /* Scope/mutex state is reinitializable; timeout remains bounded. */
    assert(sl_dns_policy_init(NULL));
    uint64_t start = now_ms();
    assert(__wrap_getaddrinfo("timeout.example", "443", NULL, &result) == EAI_AGAIN);
    assert(now_ms() - start >= 2900 && now_ms() - start < 3500);
    assert(sl_dns_policy_shutdown());
    atomic_store(&first.stop, true);
    atomic_store(&second.stop, true);
    pthread_join(first.worker, NULL);
    pthread_join(second.worker, NULL);
    close(first.fd);
    close(second.fd);
    pthread_mutex_destroy(&config_lock);
    puts("Unified names, multiple contexts, network change, numeric ABI, curl cache, cancellation "
         "and cleanup pass");
}
