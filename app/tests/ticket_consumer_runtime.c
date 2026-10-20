/* Actual product worker and IHS/RPC parsers through the ticket-consumer boundary.
 * CM/UDP receive bytes and final sends are providers. SDK construction/update
 * and IHS Session construction are observed terminals; no real Steam/media. */
#include "../platforms/common/runtime.c"
#include "fixture_cleanup.h"
#include "remote_wire.h"
#include <assert.h>
#include <poll.h>

static sl_runtime *actor;
static sl_remote *protocol;
static char connection;
#if NSL_HAVE_SNS
static char backend;
#endif
static pthread_t owner;
static atomic_bool ready, request_seen, injected, settled;
static atomic_uint session_creates, backend_creates, backend_destroys;
static uint8_t cm_packets[8][4096], udp_packets[8][4096];
static size_t cm_sizes[8], udp_sizes[8];
static unsigned cm_count, udp_count, udp_index, after_injection;
static bool backend_live;
static unsigned final_phase;

static bool send_rpc(const uint8_t *raw, size_t size, void *ctx) {
    (void)raw; (void)size; (void)ctx;
    assert(pthread_equal(owner, pthread_self()));
    return true;
}
sl_remote_connection *__wrap_sl_remote_connection_create(const IHS_ClientConfig *config,
                                                         const sl_remote_callbacks *callbacks,
                                                         void *ctx) {
    owner = pthread_self(); actor = ctx;
    sl_remote_callbacks cb = *callbacks;
    cb.send = send_rpc;
    protocol = sl_remote_create(config, &cb, ctx);
    assert(protocol && sl_remote_open(protocol));
    return (sl_remote_connection *)&connection;
}
sl_remote *__wrap_sl_remote_connection_protocol(sl_remote_connection *c) {
    assert(c == (sl_remote_connection *)&connection);
    return protocol;
}
void __wrap_sl_remote_connection_update(sl_remote_connection *c, uint64_t now) {
    assert(c == (sl_remote_connection *)&connection && pthread_equal(owner, pthread_self()));
    if (!atomic_load(&ready)) {
        uint8_t body[32], wire[64];
        sl_proto_writer b = {body, 0, sizeof(body), false}, w = {wire, 0, sizeof(wire), false};
        sl_proto_fixed64(&b, 1, 1001); sl_proto_uint(&b, 2, 1);
        sl_proto_uint(&w, 1, 1); sl_proto_bytes(&w, 2, body, b.size);
        assert(sl_remote_receive(protocol, wire, w.size));
        uint64_t account = UINT64_C(76561198000000001);
        const char *addresses[] = {"127.0.0.1"};
        sl_remote_host h = {.info = {.clientId = 123, .universe = IHS_SteamUniversePublic},
                            .steam_id = account, .steam_ids = &account, .steam_id_count = 1,
                            .addresses = addresses, .address_count = 1};
        strcpy(h.info.hostname, "Fixture Host");
        cloud_observed(&h, actor);
        atomic_store(&ready, true);
    } else if (atomic_load(&request_seen) && !atomic_load(&injected)) {
        for (unsigned n = 0; n < cm_count; ++n)
            assert(sl_remote_receive(protocol, cm_packets[n], cm_sizes[n]));
        atomic_store(&injected, true);
    } else if (atomic_load(&injected) && ++after_injection == 2) {
        final_phase = IHS_ClientHandshakePhase(actor->client);
        atomic_store(&settled, true); /* Two real actor passes after delivery. */
    }
    sl_remote_update(protocol, now);
}
void __wrap_sl_remote_connection_describe(const sl_remote_connection *c, uint64_t now,
                                          char *out, size_t capacity) {
    (void)c; (void)now;
    snprintf(out, capacity, "fixture CM");
}
void __wrap_sl_remote_connection_destroy(sl_remote_connection *c) {
    assert(c == (sl_remote_connection *)&connection && pthread_equal(owner, pthread_self()));
    sl_remote_close(protocol); sl_remote_destroy(protocol); protocol = NULL;
}
uint32_t __wrap_IHS_CryptoRandomUInt32(void) { return 17; }
bool __wrap_sl_network_stats_load(const char *dir, sl_network_stats_average *average) {
    (void)dir; (void)average;
    return true; /* Existing stats file input; explicit tests still run. */
}
bool __wrap_IHS_ClientSendControl(IHS_Client *client, const IHS_HostInfo *host,
                                  const IHS_SocketAddress *source, ERemoteClientBroadcastMsg tag,
                                  ProtobufCMessage *message) {
    (void)client; (void)host; (void)source;
    assert(pthread_equal(owner, pthread_self()));
    if (tag == k_ERemoteDeviceStreamingRequest) {
        assert(((CMsgRemoteDeviceStreamingRequest *)message)->request_id == 17);
        atomic_store(&request_seen, true);
    }
    return true;
}
ssize_t __wrap_recvfrom(int fd, void *data, size_t capacity, int flags,
                        struct sockaddr *address, socklen_t *length) {
    (void)fd; (void)flags;
    if (!atomic_load(&injected) || udp_index == udp_count) { errno = EAGAIN; return -1; }
    assert(pthread_equal(owner, pthread_self()) && *length >= sizeof(struct sockaddr_in));
    size_t size = udp_sizes[udp_index];
    assert(size <= capacity);
    memcpy(data, udp_packets[udp_index++], size);
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(27036),
                               .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    memcpy(address, &peer, sizeof(peer)); *length = sizeof(peer);
    return (ssize_t)size;
}
ssize_t __wrap_sendto(int fd, const void *data, size_t size, int flags,
                      const struct sockaddr *address, socklen_t length) {
    (void)fd; (void)data; (void)flags; (void)address; (void)length;
    return (ssize_t)size;
}
IHS_Session *__wrap_IHS_SessionCreate(const IHS_ClientConfig *config, const IHS_SessionInfo *info) {
    (void)config;
    assert(pthread_equal(owner, pthread_self()) && info->sessionKeyLen == 32);
    for (unsigned n = 0; n < 32; ++n) assert(info->sessionKey[n] == n);
    atomic_fetch_add(&session_creates, 1);
    return NULL; /* Observe consumption, without creating a media/socket worker. */
}
#if NSL_HAVE_SNS
sl_sns *__wrap_sl_sns_create(const IHS_ClientConfig *config, const sl_remote_material *m,
                             bool share, char *error, size_t capacity) {
    (void)config; (void)error; (void)capacity;
    assert(pthread_equal(owner, pthread_self()) && share && !backend_live);
    assert(m->transport == 4 && m->client_id == 123 && m->key_size == 32);
    assert(!strcmp(m->cert, "fixture-certificate") &&
           !strcmp(m->stun_servers, "stun:fixture.invalid:3478"));
    for (unsigned n = 0; n < 32; ++n) assert(m->key[n] == n);
    atomic_fetch_add(&backend_creates, 1); backend_live = true;
    return (sl_sns *)&backend;
}
void __wrap_sl_sns_update(sl_sns *s, uint64_t now) {
    (void)now;
    assert(s == (sl_sns *)&backend && backend_live && pthread_equal(owner, pthread_self()));
}
sl_sns_state __wrap_sl_sns_get_state(const sl_sns *s) {
    assert(s == (sl_sns *)&backend && backend_live);
    return SL_SNS_CONNECTED;
}
void __wrap_sl_sns_get_stats(const sl_sns *s, sl_sns_stats *out) {
    assert(s == (sl_sns *)&backend && backend_live); memset(out, 0, sizeof(*out));
}
int __wrap_sl_sns_end_reason(const sl_sns *s) { (void)s; return 0; }
void __wrap_sl_sns_destroy(sl_sns *s) {
    if (!s) return;
    assert(s == (sl_sns *)&backend && backend_live && pthread_equal(owner, pthread_self()));
    backend_live = false; atomic_fetch_add(&backend_destroys, 1);
}
#endif
static unsigned packets(char *text, uint8_t output[8][4096], size_t sizes[8]) {
    unsigned count = 0;
    if (!strcmp(text, "-")) return 0;
    char *save;
    for (char *p = strtok_r(text, ";", &save); p; p = strtok_r(NULL, ";", &save)) {
        size_t size = strlen(p)/2;
        assert(count < 8 && !(strlen(p)&1) && size < 4096);
        for (size_t n = 0; n < size; ++n) {
            unsigned byte;
            assert(sscanf(p+2*n, "%2x", &byte) == 1); output[count][n] = byte;
        }
        sizes[count++] = size;
    }
    return count;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    char cm[8192], udp[8192];
    assert(scanf("%8191s %8191s", cm, udp) == 2);
    cm_count = packets(cm, cm_packets, cm_sizes); udp_count = packets(udp, udp_packets, udp_sizes);
    char directory[] = "/tmp/nsl-ticket-consumer-XXXXXX";
    assert(mkdtemp(directory) && !setenv("NSL_DATA_DIR", directory, 1));
    sl_auth_store store = {.device_id = UINT64_C(0x1122334455667788), .sound = true};
    for (unsigned n = 0; n < 32; ++n) store.secret[n] = 32+n;
    strcpy(store.device_name, "ticket fixture"); sl_host_registry_init(&store.registry);
    sl_host h = {.client_id = 123}; strcpy(h.name, "Fixture Host"); strcpy(h.address, "127.0.0.1");
    sl_host *saved = sl_host_observe(&store.registry, &h, 0);
    assert(saved); saved->paired = true; saved->account = UINT64_C(76561198000000001);
    sl_runtime *r = sl_runtime_create(&store); assert(r);
    uint64_t deadline = sl_system_now()+6000;
    while (!atomic_load(&ready)) { assert(sl_system_now() < deadline); poll(NULL, 0, 1); }
    sl_command cmd = {.type = SL_CMD_STREAM, .host = *saved, .generation = 1,
                      .test_only = atoi(argv[1]) != 0};
    assert(sl_runtime_submit(r, &cmd, &store));
    while (!atomic_load(&settled)) { assert(sl_system_now() < deadline); poll(NULL, 0, 1); }
    assert(udp_index == udp_count);
    unsigned sessions = atomic_load(&session_creates), backends = atomic_load(&backend_creates);
    sl_runtime_destroy(r);
    assert(!backend_live && atomic_load(&backend_creates) == atomic_load(&backend_destroys));
    sl_fixture_remove_tree(directory);
    printf("{\"state\":%u,\"sessions\":%u,\"backends\":%u,\"clean\":true}\n", final_phase, sessions, backends);
    return 0;
}
