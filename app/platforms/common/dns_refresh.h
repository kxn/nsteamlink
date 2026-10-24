#pragma once
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bounded A-query resolver shared by Switch hostname lookups. No worker/cache.
 * dns_config.c selects the resolver and reads the current interface. */
#define SL_DNS_SERVERS 7 /* Current network primary/secondary, then five public providers. */
#define SL_DNS_WIRE_LIMIT 5 /* Candidate count must not raise simultaneous socket use. */
#define SL_DNS_CANDIDATES (SL_DNS_SERVERS * 4)
#define SL_DNS_ADDRESSES_SIZE (SL_DNS_CANDIDATES * 16)
typedef struct {
    uint32_t local, platform_error;
    struct sockaddr_in servers[SL_DNS_SERVERS];
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
    char addresses[SL_DNS_ADDRESSES_SIZE]; /* Four per wire answer; merged by policy. */
    char canonical[254];
    bool tcp;
    uint8_t response[4098], stream_query[274];
    size_t received, expected, sent;
} sl_dns_refresh;
bool sl_dns_current_config(sl_dns_config *);
/* Network-byte-order DNS addresses; rebuild the ordered, unique server list. */
void sl_dns_config_servers(sl_dns_config *, uint32_t primary, uint32_t secondary);
/* Initialize fd=-1 before first begin; cancel is idempotent. */
bool sl_dns_refresh_begin(sl_dns_refresh *, const sl_dns_config *, const char *, uint64_t);
/* 0=pending, 1=addresses ready, -1=failed. Never blocks. */
int sl_dns_refresh_poll(sl_dns_refresh *, uint64_t);
void sl_dns_refresh_cancel(sl_dns_refresh *);
