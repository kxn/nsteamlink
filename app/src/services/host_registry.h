#pragma once
#include <stdbool.h>
#include <stdint.h>

#define SL_HOST_LIMIT   16
#define SL_RECENT_LIMIT 4
typedef struct sl_game {
    uint64_t id;
    char name[128];
} sl_game;
typedef struct sl_host {
    uint64_t id, client_id, instance_id, account, last_seen;
    char name[64], address[64], system[24];
    bool paired, observed, legacy, games_running;
    int focus;
    sl_game games[SL_RECENT_LIMIT];
} sl_host;
typedef struct sl_host_registry {
    sl_host hosts[SL_HOST_LIMIT];
    int count, selected;
    uint64_t next_id;
} sl_host_registry;
void sl_host_registry_init(sl_host_registry *r);
sl_host *sl_host_find(sl_host_registry *r, uint64_t id);
sl_host *sl_host_observe(sl_host_registry *r, const sl_host *observation, uint64_t now);
bool sl_host_online(const sl_host *h, uint64_t now);
void sl_host_forget(sl_host_registry *r, uint64_t id);
void sl_host_activity(sl_host *h, uint64_t account, const sl_game *game);
