/* Default: read-only anonymous CreateSession. Explicit --pair/--status use an
 * isolated private profile. This tool never requests a media session. */
#include "remote_connection.h"
#include "services/auth_store.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
typedef struct live {
    sl_auth_store store;
    const char *profile;
    bool ready, failed, paired, status;
    unsigned codes;
} live;
static void connected(bool ready, void *ctx) {
    ((live *)ctx)->ready = ready;
    printf("CLOUD_CONNECTED=%d\n", ready);
    fflush(stdout);
}
static void diagnostic(const char *message, void *ctx) {
    (void)ctx;
    fprintf(stderr, "%lld %s\n", (long long)time(NULL), message);
}
static void pin(const char *code, void *ctx) {
    live *l = ctx;
    ++l->codes;
    /* Explicit interactive test only. Never dump identity, key or certificate. */
    printf("PAIR_CODE=%s\n", code);
    fflush(stdout);
}
static bool save(const sl_remote_peer *peer, void *ctx) {
    live *l = ctx;
    sl_host *h = NULL;
    for (int i = 0; i < l->store.registry.count; ++i)
        if (l->store.registry.hosts[i].client_id == peer->client_id)
            h = &l->store.registry.hosts[i];
    if (!h) {
        if (l->store.registry.count == SL_HOST_LIMIT)
            return false;
        h = &l->store.registry.hosts[l->store.registry.count++];
        *h = (sl_host){.id = l->store.registry.next_id++, .client_id = peer->client_id};
        snprintf(h->name, sizeof(h->name), "Steam");
        l->store.registry.selected = (int)(h - l->store.registry.hosts);
    }
    h->paired = h->has_secret = true;
    h->account = peer->steam_id;
    memcpy(h->secret, peer->secret, 32);
    return sl_auth_save(&l->store, l->profile);
}
static void paired(const sl_remote_peer *peer, void *ctx) {
    (void)peer;
    ((live *)ctx)->paired = true;
    puts("PAIRED=1");
    fflush(stdout);
}
static void failed(IHS_AuthorizationResult result, void *ctx) {
    ((live *)ctx)->failed = true;
    printf("PAIR_FAILED=%d\n", result);
    fflush(stdout);
}
static void host(const sl_remote_host *h, void *ctx) {
    (void)h;
    ((live *)ctx)->status = true;
    puts("CLOUD_STATUS=1");
    fflush(stdout);
}
static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
int main(int argc, char **argv) {
    uint8_t secret[32] = {0};
    IHS_ClientConfig config = {
        .deviceId = 1, .secretKey = secret, .deviceName = "NSteamLink probe"};
    bool pairing = argc == 3 && !strcmp(argv[1], "--pair");
    bool status = argc == 3 && !strcmp(argv[1], "--status");
    bool idle = argc == 2 && !strcmp(argv[1], "--idle");
    if (argc != 1 && !pairing && !status && !idle) {
        fprintf(stderr, "usage: %s [--idle | --pair|--status PRIVATE_PROFILE_DIRECTORY]\n",
                argv[0]);
        return 2;
    }
    live l = {.profile = argc == 3 ? argv[2] : NULL};
    umask(0077);
    if (l.profile) {
        if (sl_auth_load(&l.store, l.profile) < 0)
            return 1;
        config = (IHS_ClientConfig){.deviceId = l.store.device_id,
                                    .secretKey = l.store.secret,
                                    .deviceName = l.store.device_name};
    }
    sl_remote_callbacks cb = {.diagnostic = diagnostic,
                              .connected = connected,
                              .pair_code = pin,
                              .save_key = save,
                              .paired = paired,
                              .pair_failed = failed,
                              .host = host};
    sl_remote_connection *c = sl_remote_connection_create(&config, &cb, &l);
    if (!c)
        return 1;
    sl_remote *protocol = sl_remote_connection_protocol(c);
    if (l.profile) {
        sl_remote_peer peers[SL_REMOTE_PEERS];
        size_t count = 0;
        for (int i = 0; i < l.store.registry.count; ++i) {
            sl_host *h = &l.store.registry.hosts[i];
            if (!h->paired || !h->client_id || !h->account)
                continue;
            peers[count] = (sl_remote_peer){.client_id = h->client_id, .steam_id = h->account};
            memcpy(peers[count++].secret, h->has_secret ? h->secret : l.store.secret, 32);
        }
        sl_remote_watch(protocol, peers, count);
        memset(peers, 0, sizeof(peers));
    }
    uint64_t deadline = now_ms() + (pairing ? 1800000 : idle ? 90000 : 60000);
    bool started = false, success = false;
    uint64_t connected_at = 0;
    while (!l.failed && now_ms() < deadline) {
        sl_remote_connection_update(c, now_ms());
        if (l.ready && !connected_at)
            connected_at = now_ms();
        if (idle && connected_at && !l.ready) {
            l.failed = true;
            break;
        }
        if (l.ready && pairing && !started) {
            started = true;
            if (!sl_remote_pair(protocol))
                break;
        }
        success = pairing  ? l.paired && l.status
                  : status ? l.status
                  : idle   ? connected_at && now_ms() - connected_at >= 65000
                           : l.ready;
        if (success)
            break;
        usleep(10000);
    }
    sl_remote_cancel(protocol);
    /* Flush cancellation/confirmation already queued; bounded owner-thread drain. */
    for (unsigned i = 0; i < 20; ++i) {
        sl_remote_connection_update(c, now_ms());
        usleep(10000);
    }
    sl_remote_connection_destroy(c);
    memset(&l.store, 0, sizeof(l.store));
    puts(success ? "PASS anonymous cloud test" : "FAIL anonymous cloud test");
    return success ? 0 : 1;
}
