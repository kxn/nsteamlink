#pragma once
#include "host_registry.h"
#include <stddef.h>
typedef struct sl_auth_store {
    uint64_t device_id;
    uint8_t secret[32];
    char device_name[64];
    sl_host_registry registry;
    uint32_t quality;
    bool sound;
    uint32_t bitrate_kbps;
} sl_auth_store;
/* Explicit bandwidth choices; independent of the quality preference. */
static inline bool sl_bitrate_valid(uint32_t kbps) {
    return kbps == 4000 || kbps == 6000 || kbps == 10000 || kbps == 20000;
}
/* 0 loaded, 1 created, negative: corrupt/unreadable; never replaces corrupt identity. */
int sl_auth_load(sl_auth_store *store, const char *directory);
bool sl_auth_save(const sl_auth_store *store, const char *directory);

/* Address hint only: never creates a host or grants authorization. */
bool sl_auth_discovery_hint(const sl_auth_store *, const char *directory, char *address,
                            size_t size);
