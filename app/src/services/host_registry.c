#include "host_registry.h"
#include <string.h>

void sl_host_registry_init(sl_host_registry *r) {
    memset(r, 0, sizeof(*r));
    r->selected = -1;
    r->next_id = 1;
}
sl_host *sl_host_find(sl_host_registry *r, uint64_t id) {
    for (int i = 0; i < r->count; ++i)
        if (r->hosts[i].id == id)
            return &r->hosts[i];
    return NULL;
}
bool sl_host_online(const sl_host *h, uint64_t now) {
    return h && h->observed && now >= h->last_seen && now - h->last_seen < 15000;
}
sl_host *sl_host_observe(sl_host_registry *r, const sl_host *o, uint64_t now) {
    sl_host *h = NULL;
    for (int i = 0; i < r->count; ++i) {
        sl_host *candidate = &r->hosts[i];
        /* clientId identifies the host installation; concurrent collisions never
         * transfer authorization. instanceId is a launch, address is not identity. */
        if (o->client_id && candidate->client_id == o->client_id &&
            (!sl_host_online(candidate, now) || candidate->instance_id == o->instance_id)) {
            h = candidate;
            break;
        }
    }
    if (!h) {
        if (r->count == SL_HOST_LIMIT)
            return NULL;
        h = &r->hosts[r->count++];
        memset(h, 0, sizeof(*h));
        h->id = r->next_id++;
        if (r->selected < 0)
            r->selected = 0;
    }
    h->client_id = o->client_id;
    h->instance_id = o->instance_id;
    memcpy(h->name, o->name, sizeof(h->name));
    memcpy(h->address, o->address, sizeof(h->address));
    memcpy(h->system, o->system, sizeof(h->system));
    h->name[sizeof(h->name) - 1] = 0;
    h->address[sizeof(h->address) - 1] = 0;
    h->system[sizeof(h->system) - 1] = 0;
    h->observed = true;
    h->games_running = o->games_running;
    h->last_seen = now;
    return h;
}
void sl_host_forget(sl_host_registry *r, uint64_t id) {
    for (int i = 0; i < r->count; ++i)
        if (r->hosts[i].id == id) {
            memmove(&r->hosts[i], &r->hosts[i + 1], (r->count - i - 1) * sizeof(sl_host));
            --r->count;
            if (r->selected >= r->count)
                r->selected = r->count - 1;
            return;
        }
}
void sl_host_activity(sl_host *h, uint64_t account, const sl_game *game) {
    if (!h || !h->paired || h->account != account || !game->id || !game->name[0])
        return;
    int index = SL_RECENT_LIMIT - 1;
    for (int i = 0; i < SL_RECENT_LIMIT; ++i)
        if (h->games[i].id == game->id) {
            index = i;
            break;
        }
    memmove(&h->games[1], &h->games[0], index * sizeof(sl_game));
    h->games[0] = *game;
    h->games[0].name[sizeof(h->games[0].name) - 1] = 0;
}
