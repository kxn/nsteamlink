/* Production callbacks -> runtime event queue -> actual UI registry/layout.
 * Status/Offline inputs are controlled callback providers; this is not Steam,
 * DNS, WebSocket, UDP wire parsing, Switch or complete address-cache proof. */
#include "../platforms/common/runtime.c"
#include "ui/ui_events.h"
#include <assert.h>

static void drain(sl_runtime *r, sl_ui_model *ui) {
    sl_runtime_event event;
    while (sl_runtime_poll(r, &event))
        sl_ui_runtime_event(ui, &event);
    sl_ui_layout(ui);
}
int main(void) {
    IHS_Init();
    sl_runtime r = {0};
    assert(!pthread_mutex_init(&r.lock, NULL));
    sl_host_registry_init(&r.store.registry);
    sl_host saved = {.client_id = 123, .instance_id = 456, .paired = true,
                     .account = 789, .has_secret = true};
    strcpy(saved.name, "Previously paired host");
    strcpy(saved.address, "10.10.10.166");
    saved.games[0].id = 367520;
    strcpy(saved.games[0].name, "Cached game");
    memset(saved.secret, 0x5a, sizeof(saved.secret));
    sl_host *stored = sl_host_observe(&r.store.registry, &saved, sl_system_now());
    assert(stored);
    /* Discovery observation never imports authorization/history; install the
     * persisted profile fields separately, as the real profile loader does. */
    stored->paired = stored->has_secret = true;
    stored->account = saved.account;
    memcpy(stored->secret, saved.secret, sizeof(stored->secret));
    memcpy(stored->games, saved.games, sizeof(stored->games));
    sl_ui_model ui;
    sl_ui_init(&ui, &r.store);
    ui.now = sl_system_now();
    IHS_HostInfo udp = {.clientId = 123, .instanceId = 456,
                       .universe = IHS_SteamUniversePublic};
    strcpy(udp.hostname, saved.name);
    assert(IHS_IPAddressFromString(&udp.address.ip, saved.address));
    udp.address.port = 27036;

    discovered(NULL, &udp, &r);
    sl_remote_host cloud = {.info = udp, .steam_id = saved.account};
    cloud_observed(&cloud, &r);
    drain(&r, &ui);
    sl_host *h = sl_host_find(&ui.store.registry, stored->id);
    assert(h && sl_host_online(h, ui.now));
    assert(sl_ui_host_source(&ui, h) == SL_DISCOVERY_LAN);
    assert(r.cloud_count == 1 && r.local_count == 1);

    cloud_offline(123, &r);
    assert(!r.cloud_count);
    IHS_HostInfo retained;
    assert(local_host(&r, 123, &retained)); /* Offline does not erase the address cache. */
    drain(&r, &ui);
    assert(!sl_host_online(h, ui.now));
    assert(sl_ui_host_source(&ui, h) == SL_DISCOVERY_NONE);
    assert(h->paired && h->account == saved.account && h->has_secret);
    assert(!memcmp(h->secret, saved.secret, sizeof(saved.secret)));
    assert(h->games[0].id == saved.games[0].id && sl_ui_game_count(&ui) == 1);
    bool disabled = false;
    for (int i = 0; i < ui.layout.count; ++i)
        if (ui.layout.controls[i].action == SL_RECENT) {
            assert(ui.layout.controls[i].disabled);
            disabled = true;
        }
    assert(disabled);
    cloud_offline(123, &r); /* Duplicate Offline cannot revive cached LAN status. */
    drain(&r, &ui);
    assert(!sl_host_online(h, ui.now));

    discovered(NULL, &udp, &r); /* A new packet, rather than the cache, revives presence. */
    drain(&r, &ui);
    assert(sl_host_online(h, ui.now));
    assert(sl_ui_host_source(&ui, h) == SL_DISCOVERY_LAN && h->paired);
    assert(!r.cloud_count && r.local_count == 1);
    for (int i = 0; i < ui.layout.count; ++i)
        if (ui.layout.controls[i].action == SL_RECENT)
            assert(!ui.layout.controls[i].disabled);
    /* The UI may not drain between receive/update callbacks. Coalescing
     * cannot move a new status to the other side of an older Offline. */
    discovered(NULL, &udp, &r);
    cloud_offline(123, &r);
    discovered(NULL, &udp, &r);
    drain(&r, &ui);
    assert(sl_host_online(h, ui.now));
    assert(sl_ui_host_source(&ui, h) == SL_DISCOVERY_LAN);
    discovered(NULL, &udp, &r);
    cloud_offline(123, &r);
    cloud_offline(123, &r);
    drain(&r, &ui);
    assert(!sl_host_online(h, ui.now));
    /* All fixtures are synchronous: no socket/worker/stream was created. */
    pthread_mutex_destroy(&r.lock);
    IHS_Quit();
    puts("PASS cloud Offline with cached LAN status: hidden presence, retained keys/history, fresh UDP revival");
    return 0;
}
