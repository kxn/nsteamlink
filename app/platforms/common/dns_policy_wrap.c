#include "dns_policy.h"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int __real_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
CURL *__real_curl_easy_init(void);
#ifdef __SWITCH__
/* SDK resolver/freeaddrinfo allocate/free one block per addrinfo node through
 * these hooks (libnx 4.12.0 runtime/resolver.c and runtime/alloc.c). */
extern void *__libnx_alloc(size_t);
#define NODE_ALLOC __libnx_alloc
#else
#define NODE_ALLOC malloc
#endif
struct info_node {
    struct addrinfo info;
    struct sockaddr_storage address;
    char canonical[];
};
int __wrap_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints,
                       struct addrinfo **out) {
    unsigned char numeric[16];
    if (!host || !host[0] || !out || (hints && (hints->ai_flags & AI_NUMERICHOST)) ||
        inet_pton(AF_INET, host, numeric) == 1 || inet_pton(AF_INET6, host, numeric) == 1 ||
        !strcmp(host, "localhost"))
        return __real_getaddrinfo(host, service, hints, out);
    *out = NULL;
    if (hints && hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET)
        return EAI_FAMILY; /* The fixed Switch resolver/curl build is IPv4. */
    sl_dns_refresh resolved;
    if (!sl_dns_policy_lookup(host, &resolved))
        return EAI_AGAIN;
    struct addrinfo numeric_hints = hints ? *hints : (struct addrinfo){0};
    numeric_hints.ai_flags = (numeric_hints.ai_flags | AI_NUMERICHOST) & ~AI_CANONNAME;
    struct addrinfo **tail = out;
    char *state = NULL;
    for (char *ip = strtok_r(resolved.addresses, ",", &state); ip;
         ip = strtok_r(NULL, ",", &state)) {
        struct addrinfo *native = NULL;
        int error = __real_getaddrinfo(ip, service, &numeric_hints, &native);
        if (error) {
            freeaddrinfo(*out);
            *out = NULL;
            return error;
        }
        for (const struct addrinfo *p = native; p; p = p->ai_next) {
            bool canonical = !*out && hints && (hints->ai_flags & AI_CANONNAME);
            size_t length = canonical ? strlen(resolved.canonical) + 1 : 0;
            if (!p->ai_addr || p->ai_addrlen > sizeof(struct sockaddr_storage)) {
                freeaddrinfo(native);
                freeaddrinfo(*out);
                *out = NULL;
                return EAI_FAIL;
            }
            struct info_node *node = NODE_ALLOC(sizeof(*node) + length);
            if (!node) {
                freeaddrinfo(native);
                freeaddrinfo(*out);
                *out = NULL;
                return EAI_MEMORY;
            }
            memset(node, 0, sizeof(*node));
            node->info = *p;
            node->info.ai_flags = hints ? hints->ai_flags : 0;
            node->info.ai_next = NULL;
            node->info.ai_addr = (struct sockaddr *)&node->address;
            memcpy(&node->address, p->ai_addr, p->ai_addrlen);
#ifdef __SWITCH__
            if (canonical) {
                memcpy(node->canonical, resolved.canonical, length);
                node->info.ai_canonname = node->canonical;
            } else
                node->info.ai_canonname = NULL;
#else
            /* Host tests use glibc freeaddrinfo, whose canonical name is a
             * separate allocation. Production follows libnx's single block. */
            node->info.ai_canonname = canonical ? strdup(resolved.canonical) : NULL;
            if (canonical && !node->info.ai_canonname) {
                free(node);
                freeaddrinfo(native);
                freeaddrinfo(*out);
                *out = NULL;
                return EAI_MEMORY;
            }
#endif
            *tail = &node->info;
            tail = &node->info.ai_next;
        }
        freeaddrinfo(native);
    }
    return *out ? 0 : EAI_NONAME;
}
CURL *__wrap_curl_easy_init(void) {
    CURL *easy = __real_curl_easy_init();
    if (easy && curl_easy_setopt(easy, CURLOPT_DNS_CACHE_TIMEOUT, 0L) != CURLE_OK) {
        curl_easy_cleanup(easy);
        return NULL;
    }
    return easy;
}
