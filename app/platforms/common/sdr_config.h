#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

enum { SL_SDR_POP_MAX = 128, SL_SDR_ENDPOINT_MAX = 1024, SL_SDR_ALIAS_MAX = 512 };
typedef struct sl_sdr_endpoint {
    uint32_t ipv4;
    uint16_t port_min, port_max;
    unsigned pop;
} sl_sdr_endpoint;
typedef struct sl_sdr_pop {
    uint32_t id;
    int tier;
    size_t first_endpoint, endpoint_count;
} sl_sdr_pop;
typedef struct sl_sdr_alias { uint32_t id; unsigned pop; } sl_sdr_alias;
typedef struct sl_sdr_config {
    uint64_t revision;
    uint8_t relay_public_key[32];
    bool have_relay_key;
    sl_sdr_pop pops[SL_SDR_POP_MAX];
    sl_sdr_endpoint endpoints[SL_SDR_ENDPOINT_MAX];
    sl_sdr_alias aliases[SL_SDR_ALIAS_MAX];
    size_t pop_count, endpoint_count, alias_count;
} sl_sdr_config;
/* Caller validates/imports certificate trust independently. No partial output
 * on failure. Bounds are local memory policy. Only advertised IPv4 relay
 * addresses are accepted; no DNS lookup or guessed relay port. */
bool sl_sdr_config_parse(const char *, size_t, sl_sdr_config *);
const sl_sdr_pop *sl_sdr_config_pop(const sl_sdr_config *, uint32_t id);
/* Map known aliases once; preserve unknown IDs, as MapToCanonicalPOPID does. */
uint32_t sl_sdr_config_canonical(const sl_sdr_config *, uint32_t id);
