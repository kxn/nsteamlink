#pragma once
#include "host_registry.h"
typedef struct sl_auth_store {
    uint64_t device_id;
    uint8_t secret[32];
    char device_name[64];
    sl_host_registry registry;
    uint32_t quality;
    bool sound;
} sl_auth_store;
/* 0 loaded, 1 created, negative: corrupt/unreadable; never replaces corrupt identity. */
int sl_auth_load(sl_auth_store *store, const char *directory);
bool sl_auth_save(const sl_auth_store *store, const char *directory);
