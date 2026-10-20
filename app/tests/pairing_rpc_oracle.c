/* Product RPC/runtime callbacks and real IHS transaction owners. Final manager
 * SendControl, CM/WebRequest, clocks, entropy and GetServerInfo/hint are explicit
 * providers matching the original instruction audit. No Steam/TLS/SDK runs. */
#include "../platforms/common/runtime.c"
#include "crypto.h"
#include "fixture_cleanup.h"
#include "remote_wire.h"
#include <assert.h>
#include <poll.h>

typedef struct record {
    uint8_t wire[4096];
    size_t size;
    unsigned tag, state, rid, session_state;
    char kind[16];
    unsigned error;
    uint64_t target, recipient;
    uint8_t secret[32];
} record;
static record rpc[64], controls[64], events[64];
static unsigned rpc_count, control_count, event_count, keypairs, random_ids;
static uint8_t tickets[32][1024];
static size_t ticket_sizes[32];
static unsigned ticket_count, service_random;
static bool preparing, usable_hint, cloud_error;
static sl_runtime runtime;
static sl_remote *protocol;
static char connection;
static IHS_HostInfo target;
static void state(record *r) {
    r->state = IHS_ClientHandshakePhase(runtime.client);
    IHS_BaseLock(&runtime.client->base);
    r->rid = runtime.client->lastLaunchId;
    r->target = runtime.client->lastLaunchHost.clientId;
    IHS_BaseUnlock(&runtime.client->base);
    r->session_state = sl_remote_ready(protocol) ? 5 : 0;
    IHS_ClientGetSecretKey(runtime.client, r->secret);
}
static void event(const char *kind, unsigned error) {
    assert(event_count < 64);
    record *r = &events[event_count++];
    *r = (record){.error = error};
    snprintf(r->kind, sizeof(r->kind), "%s", kind);
    state(r);
}
time_t __wrap_time(time_t *out) {
    if (out)
        *out = 1000;
    return 1000; /* Session-only clock steps must not tick the stream owner. */
}
uint32_t __wrap_IHS_CryptoRandomUInt32(void) {
    static const uint32_t ids[] = {17, 19, 23, 29};
    assert(random_ids < 4);
    return ids[random_ids++];
}
int __wrap_IHS_CryptoRandomBytes(uint8_t *out, size_t size) {
    if (preparing && size == 32 && service_random++ > 0) {
        for (size_t n = 0; n < size; ++n)
            out[n] = n + (service_random == 2 ? 0 : 64);
    } else if (size == 4) {
        uint32_t pin = 42;
        memcpy(out, &pin, size);
    } else {
        if (size == 32)
            ++keypairs;
        for (size_t n = 0; n < size; ++n)
            out[n] = n;
    }
    return 0;
}
int __real_IHS_CryptoRSAEncrypt(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *,
                                size_t *);
int __wrap_IHS_CryptoRSAEncrypt(const uint8_t *raw, size_t size, const uint8_t *key,
                                size_t key_size, uint8_t *out, size_t *out_size) {
    assert(ticket_count < 32 && size < sizeof(tickets[0]));
    memcpy(tickets[ticket_count], raw, size);
    ticket_sizes[ticket_count++] = size;
    return __real_IHS_CryptoRSAEncrypt(raw, size, key, key_size, out, out_size);
}
bool __wrap_IHS_ClientSendControl(IHS_Client *c, const IHS_HostInfo *host,
                                  const IHS_SocketAddress *source, ERemoteClientBroadcastMsg tag,
                                  ProtobufCMessage *message) {
    (void)c;
    (void)host;
    (void)source;
    assert(control_count < 64);
    record *r = &controls[control_count++];
    *r = (record){.tag = tag};
    r->recipient = host->clientId;
    state(r);
    r->size = message ? protobuf_c_message_get_packed_size(message) : 0;
    assert(r->size < sizeof(r->wire));
    if (message)
        protobuf_c_message_pack(message, r->wire);
    return true; /* Original audit also stops at final SendMessage caller. */
}
ssize_t __wrap_sendto(int fd, const void *data, size_t size, int flags,
                      const struct sockaddr *address, socklen_t length) {
    (void)fd;
    (void)data;
    (void)flags;
    (void)address;
    (void)length;
    return size; /* Discovery cannot contact an actual host. */
}
static bool visible(IHS_Client *c, uint64_t id, IHS_HostInfo *out, void *ctx) {
    (void)c;
    (void)ctx;
    if (!usable_hint)
        return false;
    *out = target;
    out->clientId = id;
    return true;
}
static void resolve(IHS_Client *c, uint64_t id, IHS_SocketAddress *out, void *ctx) {
    (void)c;
    (void)id;
    (void)ctx;
    *out = (IHS_SocketAddress){0};
}
static const IHS_ClientRoutingCallbacks route = {.host = visible, .resolve = resolve};
static bool send_rpc(const uint8_t *raw, size_t size, void *ctx) {
    (void)ctx;
    assert(rpc_count < 64 && size < sizeof(rpc[0].wire));
    record *r = &rpc[rpc_count++];
    *r = (record){.size = size};
    memcpy(r->wire, raw, size);
    state(r);
    return true;
}
static void session_connected(bool ready, void *ctx) {
    cloud_connected(ready, ctx);
    if (runtime.client)
        event(ready ? "connected" : "disconnected", 0);
}
static void code(const char *pin, void *ctx) {
    event("code", 0);
    cloud_code(pin, ctx);
}
static void failed(IHS_Client *c, const IHS_HostInfo *host, IHS_AuthorizationResult result,
                   void *ctx) {
    if (cloud_error && result == IHS_AuthorizationOffline) {
        const sl_directory_host *sentinel = sl_directory_find(runtime.directory, 777);
        assert(sentinel && !sentinel->cloud); /* Membership clears before error notification. */
    }
    unsigned error = cloud_error && result == IHS_AuthorizationOffline ? 18
                     : result == IHS_AuthorizationDenied               ? 2
                     : result == IHS_AuthorizationNotLoggedIn          ? 3
                     : result == IHS_AuthorizationOffline              ? 4
                     : result == IHS_AuthorizationBusy                 ? 5
                     : result == IHS_AuthorizationTimedOut             ? 6
                                                                       : 1;
    event("failed", error);
    auth_failed(c, host, result, ctx);
}
static void rpc_failed(IHS_AuthorizationResult result, void *ctx) {
    cloud_error = true;
    cloud_pair_failed(result, ctx);
    cloud_error = false;
}
static void pairing_complete(IHS_Client *c, const IHS_HostInfo *host, uint64_t account, void *ctx) {
    event("paired", 0);
    authorized(c, host, account, ctx);
}
static bool prepare(IHS_SteamUniverse universe, const char *pin, uint8_t **raw, size_t *size,
                    void *ctx) {
    preparing = true;
    service_random = 0;
    bool ok = cloud_prepare_pairing(universe, pin, raw, size, ctx);
    preparing = false;
    return ok;
}
sl_remote_connection *__wrap_sl_remote_connection_create(const IHS_ClientConfig *config,
                                                         const sl_remote_callbacks *callbacks,
                                                         void *ctx) {
    sl_remote_callbacks cb = *callbacks;
    cb.send = send_rpc;
    cb.connected = session_connected;
    cb.pair_code = code;
    cb.prepare_pairing = prepare;
    cb.pair_failed = rpc_failed;
    protocol = sl_remote_create(config, &cb, ctx);
    assert(protocol);
    return (sl_remote_connection *)&connection;
}
sl_remote *__wrap_sl_remote_connection_protocol(sl_remote_connection *c) {
    assert(c == (sl_remote_connection *)&connection);
    return protocol;
}
void __wrap_sl_remote_connection_destroy(sl_remote_connection *c) {
    assert(c == (sl_remote_connection *)&connection);
    sl_remote_close(protocol);
    sl_remote_destroy(protocol);
    protocol = NULL;
}
static size_t unhex(const char *text, uint8_t *raw) {
    size_t size = strlen(text) / 2;
    assert(size < 4096 && !(strlen(text) & 1));
    for (size_t n = 0; n < size; ++n) {
        unsigned value;
        assert(sscanf(text + 2 * n, "%2x", &value) == 1);
        raw[n] = value;
    }
    return size;
}
static void open_session(uint64_t id) {
    assert(sl_remote_open(protocol));
    uint8_t body[32], wire[64];
    sl_proto_writer b = {body, 0, sizeof(body), false}, w = {wire, 0, sizeof(wire), false};
    sl_proto_fixed64(&b, 1, id);
    sl_proto_uint(&b, 2, 1);
    sl_proto_uint(&w, 1, 1);
    sl_proto_bytes(&w, 2, body, b.size);
    assert(sl_remote_receive(protocol, wire, w.size));
}
static void stream_reply(ERemoteDeviceStreamingResult result) {
    CMsgRemoteDeviceStreamingResponse reply = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
    reply.request_id = runtime.client->lastLaunchId;
    reply.result = result;
    uint8_t key[16], secret[32], encrypted[64];
    for (unsigned n = 0; n < 16; ++n)
        key[n] = n;
    size_t size = sizeof(encrypted);
    if (result == k_ERemoteDeviceStreamingSuccess) {
        IHS_ClientGetSecretKey(runtime.client, secret);
        assert(!IHS_CryptoSymmetricEncrypt(key, sizeof(key), secret, 32, encrypted, &size));
        reply.has_port = reply.has_encrypted_session_key = true;
        reply.port = 61024;
        reply.encrypted_session_key = (ProtobufCBinaryData){size, encrypted};
    }
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_msg_type = true;
    header.client_id = 123;
    header.msg_type = 6;
    IHS_ClientStreamingCallback(runtime.client, &target.address, &header, &reply.base);
}
static void known(const char *phase) {
    bool previous = usable_hint;
    usable_hint = true;
    runtime.active.type = SL_CMD_STREAM;
    IHS_StreamingRequest request = {0};
    strcpy(request.pin, "9876");
    unsigned before = control_count;
    assert(IHS_ClientStreamingRequest(runtime.client, &target, &request));
    for (unsigned n = 0; n < 2000 && control_count == before; ++n) {
        IHS_ClientPumpAuthorization(runtime.client, 32);
        poll(NULL, 0, 1);
    }
    assert(control_count > before);
    if (!strcmp(phase, "known"))
        stream_reply(k_ERemoteDeviceStreamingUnauthorized);
    else if (!strcmp(phase, "ticket"))
        stream_reply(k_ERemoteDeviceStreamingSuccess);
    usable_hint = previous;
}
static void start(void) {
    runtime.active.type = SL_CMD_REMOTE_PAIR;
    cloud_error = true;
    assert(sl_remote_pair(protocol));
    cloud_error = false;
}
static void pin(void) {
    static const uint8_t raw[] = {8, 1, 26, 3, 8, 210, 9};
    assert(sl_remote_receive(protocol, raw, sizeof(raw)));
}
static void hex(const uint8_t *raw, size_t size) {
    for (size_t n = 0; n < size; ++n)
        printf("%02x", raw[n]);
}
static void print_state(const record *r) {
    printf("{\"state\":%u,\"rid\":%u,\"session_state\":%u,\"secret\":\"", r->state, r->rid,
           r->session_state);
    hex(r->secret, 32);
    putchar('"');
    printf(",\"target\":%llu", (unsigned long long)r->target);
}
static void snapshot(void) {
    record current = {0};
    state(&current);
    print_state(&current);
    const sl_directory_host *reply = sl_directory_find(runtime.directory, 456);
    printf(",\"keypairs\":%u,\"reply_metadata\":%s,\"paired_count\":%zu,\"rpc\":[", keypairs,
           reply && reply->accounts.count ? "true" : "false", runtime.paired_accounts.count);
    for (unsigned n = 0; n < rpc_count; ++n) {
        if (n)
            putchar(',');
        printf("{\"wire\":\"");
        hex(rpc[n].wire, rpc[n].size);
        printf("\",\"state\":");
        print_state(&rpc[n]);
        printf("}}");
    }
    printf("],\"controls\":[");
    for (unsigned n = 0; n < control_count; ++n) {
        if (n)
            putchar(',');
        print_state(&controls[n]);
        printf(",\"tag\":%u,\"recipient\":%llu,\"body\":\"", controls[n].tag,
               (unsigned long long)controls[n].recipient);
        hex(controls[n].wire, controls[n].size);
        printf("\"}");
    }
    printf("],\"events\":[");
    for (unsigned n = 0; n < event_count; ++n) {
        if (n)
            putchar(',');
        print_state(&events[n]);
        printf(",\"kind\":\"%s\",\"error\":%u}", events[n].kind, events[n].error);
    }
    printf("],\"tickets\":[");
    for (unsigned n = 0; n < ticket_count; ++n) {
        if (n)
            putchar(',');
        putchar('"');
        hex(tickets[n], ticket_sizes[n]);
        putchar('"');
    }
    puts("]}");
}
int main(int argc, char **argv) {
    assert(argc == 3);
    char directory[] = "/tmp/nsl-pairing-rpc-XXXXXX";
    assert(mkdtemp(directory) && !setenv("NSL_DATA_DIR", directory, 1));
    assert(!pthread_mutex_init(&runtime.lock, NULL) && !pthread_cond_init(&runtime.wake, NULL));
    sl_host_registry_init(&runtime.store.registry);
    runtime.store.device_id = UINT64_C(0x1122334455667788);
    for (unsigned n = 0; n < 32; ++n)
        runtime.store.secret[n] = 32 + n;
    strcpy(runtime.store.device_name, "Switch fixture");
    runtime.config = (IHS_ClientConfig){.deviceId = runtime.store.device_id,
                                        .secretKey = runtime.store.secret,
                                        .deviceName = "Switch fixture",
                                        .deviceModel = "Switch model fixture",
                                        .deviceSerial = "serial fixture"};
    IHS_Init();
    assert(sl_stream_settings_init(&runtime.settings, &runtime.store) && start_client(&runtime));
    IHS_ClientAuthorizationCallbacks auth = auth_cb;
    auth.failed = failed;
    auth.success = pairing_complete;
    IHS_ClientSetAuthorizationCallbacks(runtime.client, &auth, &runtime);
    IHS_ClientSetRoutingCallbacks(runtime.client, &route, NULL);
    target =
        (IHS_HostInfo){.clientId = 123, .universe = IHS_SteamUniversePublic, .address.port = 27036};
    assert(IHS_IPAddressFromString(&target.address.ip, "127.0.0.1"));
    start_cloud(&runtime);
    open_session(1001);
    rpc_count = event_count = 0;
    usable_hint = atoi(argv[2]) != 0;
    sl_directory_host *sentinel = sl_directory_ensure(&runtime.directory, 777);
    assert(sentinel);
    sentinel->cloud = true;
    if (!strcmp(argv[1], "waiting") || !strcmp(argv[1], "auth")) {
        start();
        if (!strcmp(argv[1], "auth"))
            pin();
    } else if (strcmp(argv[1], "idle"))
        known(argv[1]);
    snapshot();
    char command[8192];
    while (fgets(command, sizeof(command), stdin)) {
        if (command[0] == 's')
            start();
        else if (command[0] == 'c')
            sl_remote_cancel(protocol);
        else if (command[0] == 'r') {
            uint8_t raw[4096];
            char text[8192];
            assert(sscanf(command, "r %8191s", text) == 1);
            cloud_error = true;
            size_t size = unhex(text, raw);
            assert(sl_remote_receive(protocol, raw, size));
            cloud_error = false;
        } else if (command[0] == 'b') {
            /* remote_connection's WS decoder dispatches every complete service
             * frame before the worker gets another IHS pump. Exercise that
             * exact absence of an inter-frame pump, using production callbacks. */
            unsigned frames = 0;
            cloud_error = true;
            char *save;
            for (char *text = strtok_r(command + 1, " \r\n", &save); text;
                 text = strtok_r(NULL, " \r\n", &save)) {
                uint8_t raw[4096];
                size_t size = unhex(text, raw);
                assert(sl_remote_receive(protocol, raw, size));
                ++frames;
            }
            assert(frames > 1);
            cloud_error = false;
        } else if (command[0] == 'u') {
            unsigned ws;
            long long now;
            assert(sscanf(command, "u %u %lld", &ws, &now) == 2);
            cloud_error = true;
            if (ws != 3)
                sl_remote_close(protocol);
            else
                sl_remote_update(protocol, now);
            cloud_error = false;
        } else if (command[0] == 'o') {
            unsigned before = rpc_count;
            open_session(1002);
            rpc_count = before; /* Reconnect transport/CreateSession are providers here. */
        } else if (command[0] == 'k')
            known("known");
        else if (command[0] == 't')
            known("stream");
        else
            assert(!"unknown command");
        IHS_ClientPumpAuthorization(runtime.client, 32);
        snapshot();
    }
    stop_client(&runtime);
    __wrap_sl_remote_connection_destroy(runtime.remote);
    runtime.remote = NULL;
    clear_control_locked(&runtime);
    sl_stream_settings_destroy(&runtime.settings);
    sl_directory_destroy(&runtime.directory);
    sl_accounts_destroy(&runtime.paired_accounts);
    pthread_cond_destroy(&runtime.wake);
    pthread_mutex_destroy(&runtime.lock);
    IHS_Quit();
    sl_fixture_remove_tree(directory);
    return 0;
}
