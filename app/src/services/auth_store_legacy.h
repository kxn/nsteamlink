#pragma once
/* Frozen on-disk layouts of older profile versions. Never change them: they
 * must keep reading the files written by earlier releases. Shared with the
 * tests so migrations are exercised against the real layouts. */
#include "host_registry.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* sl_host as stored by profiles v2 and v3, before the per-host secret. */
typedef struct sl_game_v3 {
    uint64_t id;
    char name[128];
} sl_game_v3;
typedef struct sl_host_v3 {
    uint64_t id, client_id, instance_id, account, last_seen;
    char name[64], address[64], system[24];
    bool paired, observed, legacy, games_running;
    int focus;
    sl_game_v3 games[4];
} sl_host_v3;
typedef struct sl_host_registry_v3 {
    sl_host_v3 hosts[16];
    int count, selected;
    uint64_t next_id;
} sl_host_registry_v3;

typedef struct auth_store_v2 {
    uint64_t device_id;
    uint8_t secret[32];
    char device_name[64];
    sl_host_registry_v3 registry;
    uint32_t quality;
    bool sound;
} auth_store_v2;
typedef struct disk_store_v2 {
    char magic[8];
    uint32_t version, size, checksum;
    auth_store_v2 data;
} disk_store_v2;

typedef struct auth_store_v3 {
    uint64_t device_id;
    uint8_t secret[32];
    char device_name[64];
    sl_host_registry_v3 registry;
    uint32_t quality;
    bool sound;
    uint32_t bitrate_kbps;
} auth_store_v3;
typedef struct disk_store_v3 {
    char magic[8];
    uint32_t version, size, checksum;
    auth_store_v3 data;
} disk_store_v3;

/* Hosts paired by v2/v3 keep using the installation secret (has_secret false). */
static inline void sl_host_registry_from_v3(sl_host_registry *dst, const sl_host_registry_v3 *src) {
    sl_host_registry_init(dst);
    dst->count = src->count;
    dst->selected = src->selected;
    dst->next_id = src->next_id;
    for (int i = 0; i < 16 && i < SL_HOST_LIMIT; ++i) {
        const sl_host_v3 *o = &src->hosts[i];
        sl_host *h = &dst->hosts[i];
        h->id = o->id;
        h->client_id = o->client_id;
        h->instance_id = o->instance_id;
        h->account = o->account;
        h->last_seen = o->last_seen;
        memcpy(h->name, o->name, sizeof(h->name));
        memcpy(h->address, o->address, sizeof(h->address));
        memcpy(h->system, o->system, sizeof(h->system));
        h->paired = o->paired;
        h->observed = o->observed;
        h->legacy = o->legacy;
        h->games_running = o->games_running;
        h->focus = o->focus;
        for (int j = 0; j < 4 && j < SL_RECENT_LIMIT; ++j) {
            h->games[j].id = o->games[j].id;
            memcpy(h->games[j].name, o->games[j].name, sizeof(h->games[j].name));
        }
    }
}
