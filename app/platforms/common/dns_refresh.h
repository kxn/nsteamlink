#pragma once
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Small, bounded A-query recovery for the cloud directory. No worker or cache.
 * Config comes from the current interface, never a hard-coded public resolver. */
typedef struct {
    uint32_t local, platform_error;
    struct sockaddr_in servers[2];
    unsigned count;
} sl_dns_config;
typedef struct {
    int fd;
    sl_dns_config config;
    unsigned attempt;
    uint64_t deadline, expires_at;
    uint16_t id;
    char host[254];
    uint8_t query[272];
    size_t query_size;
    char addresses[64]; /* Up to four IPv4 addresses. */
} sl_dns_refresh;
bool sl_dns_current_config(sl_dns_config *);
/* Initialize fd=-1 before first begin; cancel is idempotent. */
bool sl_dns_refresh_begin(sl_dns_refresh *, const sl_dns_config *, const char *, uint64_t);
/* 0=pending, 1=addresses ready, -1=failed. Never blocks. */
int sl_dns_refresh_poll(sl_dns_refresh *, uint64_t);
void sl_dns_refresh_cancel(sl_dns_refresh *);
