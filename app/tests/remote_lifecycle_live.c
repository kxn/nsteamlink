/* Explicit live acceptance only: real CM/TLS/service, no LAN discovery, media,
 * host shutdown or firewall changes. Faults affect this executable's receiver.
 * Wire/transaction evidence: NETWORKING sections 8.1, 9.2, 11.1; AUTH.
 * Never print PINs, accounts, device IDs, session IDs or packet contents. */
#include "platform/system.h"
#include "remote_connection.h"
#include "remote_wire.h"
#include "services/auth_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct probe {
    sl_remote_connection *connection;
    sl_remote *protocol;
    bool ready, error, hold_start, drop_start;
    unsigned connections, disconnects, codes, failures, hosts, offline;
    unsigned tx[8], rx[8], raw_hosts, raw_offline, dropped;
    uint8_t held[128];
    size_t held_size;
    uint64_t target;
} probe;
static probe *updating;
static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static sl_proto_field field(const void *data, size_t size, unsigned number) {
    sl_proto_reader r = {data, size, 0, false};
    sl_proto_field f, result = {0};
    while (sl_proto_next(&r, &f))
        if (f.number == number)
            result = f;
    return sl_proto_done(&r) ? result : (sl_proto_field){0};
}
bool __real_sl_remote_receive(sl_remote *, const uint8_t *, size_t);
bool __wrap_sl_remote_receive(sl_remote *r, const uint8_t *data, size_t size) {
    probe *p = updating;
    if (!p || p->protocol != r)
        return __real_sl_remote_receive(r, data, size);
    for (unsigned kind = 2; kind <= 7; ++kind) {
        sl_proto_field body = field(data, size, kind);
        if (!body.number || body.wire != 2)
            continue;
        ++p->rx[kind];
        uint64_t result = field(data, size, 1).value;
        printf("LIVE_RX kind=%u result=%llu\n", kind, (unsigned long long)result);
        if (result != 1)
            p->error = true;
        if (kind == 3 && (p->hold_start || p->drop_start)) {
            ++p->dropped;
            if (p->hold_start && size <= sizeof(p->held)) {
                memcpy(p->held, data, size);
                p->held_size = size;
            }
            return true;
        }
        if (kind == 7 && field(data, size, 1).value == 1)
            ++p->raw_offline;
        if (kind == 6) {
            sl_proto_reader reader = {body.bytes, body.size, 0, false};
            sl_proto_field packet;
            while (sl_proto_next(&reader, &packet)) {
                static const uint8_t magic[] = {255, 255, 255, 255, 33, 76, 95, 160};
                if (packet.number != 1 || packet.wire != 2 || packet.size < 16 ||
                    memcmp(packet.bytes, magic, sizeof(magic)))
                    continue;
                const uint8_t *b = packet.bytes;
                uint32_t hs =
                    b[8] | (uint32_t)b[9] << 8 | (uint32_t)b[10] << 16 | (uint32_t)b[11] << 24;
                if (hs <= packet.size - 16 && field(b + 12, hs, 1).value == p->target &&
                    field(b + 12, hs, 2).value == 1)
                    ++p->raw_hosts;
            }
        }
    }
    return __real_sl_remote_receive(r, data, size);
}
size_t __real_sl_ws_encode(uint8_t *, size_t, unsigned, const void *, size_t, const uint8_t *);
size_t __wrap_sl_ws_encode(uint8_t *out, size_t capacity, unsigned op, const void *data,
                           size_t size, const uint8_t *mask) {
    if (updating && op == 2)
        for (unsigned i = 1; i <= 7; ++i)
            if (field(data, size, i).number) {
                ++updating->tx[i];
                printf("LIVE_TX kind=%u\n", i);
            }
    return __real_sl_ws_encode(out, capacity, op, data, size, mask);
}
static void connected(bool ready, void *ctx) {
    probe *p = ctx;
    p->ready = ready;
    if (ready)
        ++p->connections;
    else
        ++p->disconnects;
    printf("LIVE_CONNECTED ready=%d connections=%u disconnects=%u\n", ready, p->connections,
           p->disconnects);
}
static void code(const char *pin, void *ctx) {
    (void)pin;
    ++((probe *)ctx)->codes;
}
static void failed(IHS_AuthorizationResult result, void *ctx) {
    ++((probe *)ctx)->failures;
    printf("LIVE_PAIR_FAILURE result=%d\n", result);
}
static void host(const sl_remote_host *h, void *ctx) {
    probe *p = ctx;
    if (h->info.clientId == p->target)
        ++p->hosts;
}
static void offline(uint64_t id, void *ctx) {
    probe *p = ctx;
    if (id == p->target)
        ++p->offline;
    printf("LIVE_OFFLINE matches_target=%d\n", id == p->target);
}
static void diagnostic(const char *message, void *ctx) {
    (void)ctx;
    fprintf(stderr, "%s\n", message);
}
static bool init(probe *p, const IHS_ClientConfig *config, const sl_remote_peer *peer) {
    sl_remote_callbacks cb = {.connected = connected,
                              .pair_code = code,
                              .pair_failed = failed,
                              .host = host,
                              .offline = offline,
                              .diagnostic = diagnostic};
    p->connection = sl_remote_connection_create(config, &cb, p);
    if (!p->connection)
        return false;
    p->protocol = sl_remote_connection_protocol(p->connection);
    if (peer) {
        p->target = peer->client_id;
        return sl_remote_watch(p->protocol, peer, 1);
    }
    return true;
}
static void pump(probe *p) {
    updating = p;
    sl_remote_connection_update(p->connection, now_ms());
    updating = NULL;
}
static bool wait_count(probe *p, const unsigned *value, unsigned minimum, unsigned ms) {
    uint64_t end = now_ms() + ms;
    while (*value < minimum && now_ms() < end) {
        pump(p);
        usleep(10000);
    }
    return *value >= minimum;
}
static bool pair(probe *p) {
    updating = p;
    bool ok = sl_remote_pair(p->protocol);
    updating = NULL;
    return ok;
}
static void cancel(probe *p) {
    updating = p;
    sl_remote_cancel(p->protocol);
    updating = NULL;
}
static bool watch(probe *p, const sl_remote_peer *peer) {
    updating = p;
    bool ok = sl_remote_watch(p->protocol, peer, peer ? 1 : 0);
    updating = NULL;
    return ok;
}
static bool pairing_cycles(probe *p) {
    if (!wait_count(p, &p->connections, 1, 60000))
        return false;
    p->hold_start = true;
    if (!pair(p) || !wait_count(p, &p->dropped, 1, 10000) || !p->held_size)
        return false;
    cancel(p);
    if (pair(p))
        return false; /* No new transaction while the late PIN is outstanding. */
    updating = p;
    bool ok = __real_sl_remote_receive(p->protocol, p->held, p->held_size);
    updating = NULL;
    memset(p->held, 0, sizeof(p->held));
    p->held_size = 0;
    p->hold_start = false;
    if (!ok || p->codes || p->tx[4] != 2 || !wait_count(p, &p->rx[5], 2, 10000) || !pair(p) ||
        !wait_count(p, &p->rx[4], 1, 10000) || p->codes != 1)
        return false;
    cancel(p);
    if (!wait_count(p, &p->rx[5], 3, 10000))
        return false;
    puts("LIVE_PAIR_CANCEL_LATE_AND_PUBLISHED=PASS");
    p->drop_start = true;
    uint64_t start = now_ms();
    if (!pair(p) || !wait_count(p, &p->dropped, 2, 10000) ||
        !wait_count(p, &p->failures, 1, 25000) || !wait_count(p, &p->connections, 2, 60000))
        return false;
    p->drop_start = false;
    if (p->codes != 1 || p->disconnects != 1 || !pair(p) || !wait_count(p, &p->rx[4], 2, 10000) ||
        p->codes != 2)
        return false;
    cancel(p);
    if (!wait_count(p, &p->rx[5], 4, 10000) || p->failures != 1 || p->error)
        return false;
    printf("LIVE_PAIR_TIMEOUT_RECONNECT_RETRY=PASS elapsed_ms=%llu\n",
           (unsigned long long)(now_ms() - start));
    return true;
}
static bool subscriptions(probe *p, probe *control, const sl_remote_peer *peer) {
    if (!wait_count(p, &p->hosts, 1, 60000) || !wait_count(control, &control->hosts, 1, 60000))
        return false;
    if (!watch(p, NULL))
        return false;
    /* Allow queued pre-unsubscribe notifications to drain before measuring. */
    uint64_t end = now_ms() + 2000;
    while (now_ms() < end) {
        pump(p);
        pump(control);
        usleep(10000);
    }
    unsigned before = p->raw_hosts, control_before = control->raw_hosts;
    end = now_ms() + 30000;
    while (now_ms() < end) {
        pump(p);
        pump(control);
        usleep(10000);
    }
    unsigned retired = p->raw_hosts - before, active = control->raw_hosts - control_before;
    printf("LIVE_UNSUBSCRIBE_WINDOW ms=30000 retired_raw_status=%u control_raw_status=%u\n",
           retired, active);
    unsigned restored = p->hosts;
    if (!watch(p, peer) || !wait_count(p, &p->hosts, restored + 1, 15000))
        return false;
    bool ok = !p->error && !control->error && !retired && active && p->tx[5] == 2 &&
              p->tx[6] == 1 && p->connections == 1 && control->connections == 1 &&
              !p->disconnects && !control->disconnects;
    puts(ok ? "LIVE_UNSUBSCRIBE_RESUBSCRIBE=PASS"
         : !active && !retired && !p->error && !control->error
             ? "LIVE_UNSUBSCRIBE_RESUBSCRIBE=INCONCLUSIVE"
             : "LIVE_UNSUBSCRIBE_RESUBSCRIBE=FAIL");
    return ok;
}
static bool offline_cycle(probe *p) {
    if (!wait_count(p, &p->hosts, 1, 60000))
        return false;
    puts("LIVE_OFFLINE_READY=1");
    fflush(stdout);
    if (!wait_count(p, &p->offline, 1, 180000) || !p->raw_offline)
        return false;
    unsigned before = p->hosts;
    if (!wait_count(p, &p->hosts, before + 1, 180000))
        return false;
    bool ok = !p->error && p->connections == 1 && !p->disconnects;
    puts(ok ? "LIVE_SERVER_OFFLINE_ONLINE=PASS" : "LIVE_SERVER_OFFLINE_ONLINE=FAIL");
    return ok;
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    bool pairing = argc == 2 && !strcmp(argv[1], "--pair-cycles");
    bool subs = argc == 3 && !strcmp(argv[1], "--subscriptions");
    bool off = argc == 3 && !strcmp(argv[1], "--offline");
    if (!pairing && !subs && !off) {
        fprintf(stderr, "usage: %s --pair-cycles | --subscriptions|--offline PRIVATE_PROFILE\n",
                argv[0]);
        return 2;
    }
    IHS_Init();
    sl_auth_store store = {0};
    sl_remote_peer peer = {0};
    uint8_t secret[32] = {0};
    IHS_ClientConfig config = {.secretKey = secret, .deviceName = "NSteamLink lifecycle probe"};
    if (pairing && (!sl_system_random(&config.deviceId, sizeof(config.deviceId)) ||
                    !sl_system_random(secret, sizeof(secret)) || !config.deviceId)) {
        IHS_Quit();
        return 1;
    }
    if (!pairing) {
        if (sl_auth_load(&store, argv[2]) != 0) {
            IHS_Quit();
            return 1;
        }
        config = (IHS_ClientConfig){.deviceId = store.device_id,
                                    .secretKey = store.secret,
                                    .deviceName = store.device_name};
        for (int i = 0; i < store.registry.count; ++i) {
            sl_host *h = &store.registry.hosts[i];
            if (h->paired && h->client_id && h->account) {
                peer = (sl_remote_peer){.client_id = h->client_id, .steam_id = h->account};
                memcpy(peer.secret, h->has_secret ? h->secret : store.secret, 32);
                break;
            }
        }
        if (!peer.client_id) {
            IHS_Quit();
            return 1;
        }
    }
    probe p = {0}, control = {0};
    bool ok = init(&p, &config, pairing ? NULL : &peer);
    if (ok && subs)
        ok = init(&control, &config, &peer);
    if (ok)
        ok = pairing ? pairing_cycles(&p)
             : subs  ? subscriptions(&p, &control, &peer)
                     : offline_cycle(&p);
    if (p.protocol) {
        cancel(&p);
        if (!pairing)
            watch(&p, NULL);
    }
    if (control.protocol)
        watch(&control, NULL);
    /* Both unsubscriptions must reach the provider before its FIFO is torn down. */
    for (unsigned i = 0; i < 30; ++i) {
        if (p.protocol)
            pump(&p);
        if (control.protocol)
            pump(&control);
        usleep(10000);
    }
    sl_remote_connection_destroy(control.connection);
    sl_remote_connection_destroy(p.connection);
    IHS_Quit();
    memset(&store, 0, sizeof(store));
    memset(&peer, 0, sizeof(peer));
    puts(ok ? "PASS remote lifecycle" : "FAIL remote lifecycle");
    return ok ? 0 : 1;
}
