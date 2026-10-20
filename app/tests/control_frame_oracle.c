/* Actual production framing and signal queue/HMAC -> cloud envelope. Token
 * encryption is a supplied deterministic provider, not a crypto proof. Including
 * the production TU exposes its internal manager sender without adding a public
 * testing API or compiling a second copy of the algorithm. */
#include "../platforms/common/remote_protocol.c"
#include "client_pri.h"
#include "protobuf/remoteplay.pb-c.h"
#include "stream_bridge.h"
#include <assert.h>

static unsigned packets, token_calls;
static uint8_t delivered[128];
static size_t delivered_size;
static int incoming_result = 1; /* Other valid message types are ignored. */
static const char *ihs_mode;
static unsigned resolves, direct_sends;
static void resolve_address(IHS_Client *client, uint64_t peer, IHS_SocketAddress *out, void *ctx) {
    (void)client;
    (void)ctx;
    assert(peer == 123);
    ++resolves;
    *out = (IHS_SocketAddress){0};
    if (strcmp(ihs_mode, "ihs")) {
        assert(IHS_IPAddressFromString(&out->ip, "10.0.0.8"));
        out->port = 31000;
    }
}
bool __wrap_IHS_BaseSend(IHS_Base *base, IHS_SocketAddress address, const IHS_Buffer *wire) {
    (void)base;
    IHS_IPAddress expected;
    bool explicit_source = !strcmp(ihs_mode, "ihs-direct");
    assert(IHS_IPAddressFromString(&expected, explicit_source ? "192.0.2.4" : "10.0.0.8"));
    assert(!IHS_IPAddressCompare(&address.ip, &expected) &&
           address.port == (explicit_source ? 27036 : 31000));
    for (size_t i = 0; i < wire->size; ++i)
        printf("%02x", wire->data[i]);
    putchar('\n');
    ++packets;
    ++direct_sends;
    return false; /* An attempted UDP failure must not append a cloud fallback. */
}
static bool send_remote(IHS_Client *client, uint64_t peer, const uint8_t *wire, size_t size,
                        void *ctx) {
    (void)client;
    assert(peer == 123);
    return sl_remote_packet(ctx, 88, wire, size);
}
int __wrap_IHS_CryptoSymmetricEncrypt(const uint8_t *in, size_t size,
        const uint8_t *key, size_t key_size, uint8_t *out, size_t *out_size) {
    uint8_t id[8];
    IHS_WriteUInt64LE(id, 42);
    assert(size == sizeof(id) && !memcmp(in, id, sizeof(id)) && key_size == 32 && *out_size >= 32);
    for (unsigned i = 0; i < 32; ++i) {
        assert(key[i] == i);
        out[i] = (uint8_t)i;
    }
    *out_size = 32;
    ++token_calls;
    return 0;
}
static bool sent(const uint8_t *data, size_t size, void *unused) {
    (void)unused;
    sl_proto_reader envelope = {data, size, 0, false};
    sl_proto_field field;
    assert(sl_proto_next(&envelope, &field) && field.number == 7 && field.wire == 2);
    sl_proto_reader body = {field.bytes, field.size, 0, false};
    assert(!sl_proto_next(&envelope, &field) && sl_proto_done(&envelope));
    bool wire = false;
    while (sl_proto_next(&body, &field)) {
        if (field.number == 1) assert(field.value == 1001);
        else if (field.number == 2) assert(field.value == 88);
        else if (field.number == 4) {
            assert(field.wire == 2 && !wire);
            wire = true;
            for (size_t i = 0; i < field.size; ++i) printf("%02x", field.bytes[i]);
            putchar('\n');
        } else assert(!"unexpected cloud envelope field");
    }
    assert(sl_proto_done(&body) && wire);
    ++packets;
    return true;
}
static bool receive(const uint8_t *data, size_t size, void *unused) {
    (void)unused;
    /* Reconstruct the backend's one parsed CTransportSignalMsg observation
     * from actual delivered SDR elements, preserving duplicates and order. */
    sl_proto_writer out = {delivered, delivered_size, sizeof(delivered), false};
    sl_proto_bytes(&out, 2, data, size);
    assert(!out.invalid);
    delivered_size = out.size;
    return true;
}
static void incoming(uint64_t peer, const uint8_t *body, size_t size, void *context) {
    incoming_result = sl_signal_channel_receive(context, peer, body, size);
}
int main(int argc, char **argv) {
    assert(argc == 2 || argc == 3);
    uint8_t secret[32];
    for (unsigned i = 0; i < 32; ++i) secret[i] = (uint8_t)i;
    IHS_ClientConfig config = {.deviceId = 42, .deviceName = "fixture", .secretKey = secret};
    sl_remote_callbacks cb = {.send = sent};
    sl_remote *r = sl_remote_create(&config, &cb, NULL);
    assert(r);
    r->session = 1001; /* Session boundary, no service interaction. */
    if (!strncmp(argv[1], "ihs", 3)) {
        assert(argc == 3);
        ihs_mode = argv[1];
        assert(!strcmp(ihs_mode, "ihs") || !strcmp(ihs_mode, "ihs-direct") ||
               !strcmp(ihs_mode, "ihs-cache") || !strcmp(ihs_mode, "ihs-incomplete-source"));
        IHS_Init();
        IHS_Client client = {0};
        IHS_BaseInit(&client.base, &config, NULL, true);
        IHS_ClientRoutingCallbacks routing = {.resolve = resolve_address,
                                              .sendRemote = send_remote};
        IHS_ClientSetRoutingCallbacks(&client, &routing, r);
        IHS_HostInfo host = {.clientId = 123};
        assert(IHS_IPAddressFromString(&host.address.ip, "203.0.113.99"));
        host.address.port = 27036;
        IHS_SocketAddress explicit_source = {.port = 27036};
        assert(IHS_IPAddressFromString(&explicit_source.ip, "192.0.2.4"));
        if (!strcmp(ihs_mode, "ihs-incomplete-source"))
            explicit_source.port = 0;
        bool supplied =
            !strcmp(ihs_mode, "ihs-direct") || !strcmp(ihs_mode, "ihs-incomplete-source");
        CMsgRemoteClientBroadcastDiscovery msg = CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
        msg.has_seq_num = true;
        msg.seq_num = 17;
        assert(IHS_ClientSendControl(&client, &host, supplied ? &explicit_source : NULL,
                                     (ERemoteClientBroadcastMsg)atoi(argv[2]), &msg.base));
        bool cloud = !strcmp(ihs_mode, "ihs");
        assert(packets == 1 && token_calls == (unsigned)cloud && direct_sends == (unsigned)!cloud);
        assert(resolves == (unsigned)(strcmp(ihs_mode, "ihs-direct") != 0));
        IHS_BaseDestroy(&client.base);
        IHS_Quit();
        sl_remote_destroy(r);
        return 0;
    }
    if (!strcmp(argv[1], "receive")) {
        assert(argc == 3 && strlen(argv[2]) % 2 == 0 && strlen(argv[2]) < 512);
        uint8_t wire[256];
        size_t size = strlen(argv[2])/2;
        for (size_t i = 0; i < size; ++i) {
            unsigned value;
            assert(sscanf(argv[2]+2*i, "%2x", &value) == 1);
            wire[i] = (uint8_t)value;
        }
        sl_signal_callbacks callbacks = {.receive = receive};
        sl_signal_channel *channel = sl_signal_channel_create(123, 88, secret, 16, &callbacks, NULL);
        assert(channel);
        r->ctx = channel;
        r->cb.transport_signal = incoming;
        uint8_t body[512], envelope[528];
        sl_proto_writer out = {body, 0, sizeof(body), false};
        sl_proto_bytes(&out, 1, wire, size);
        sl_proto_writer response = {envelope, 0, sizeof(envelope), false};
        sl_proto_uint(&response, 1, 1);
        sl_proto_bytes(&response, 6, body, out.size);
        assert(!out.invalid && !response.invalid && sl_remote_receive(r, envelope, response.size));
        for (size_t i = 0; i < delivered_size; ++i) printf("%02x", delivered[i]);
        if (delivered_size) putchar('\n');
        fprintf(stderr, "%d\n", incoming_result);
        assert(!packets && !token_calls);
        sl_signal_channel_destroy(channel);
        sl_remote_destroy(r);
        return 0;
    }
    bool manager = !strcmp(argv[1], "manager");
    if (manager) {
        assert(argc == 3);
        CMsgRemoteClientBroadcastDiscovery msg = CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
        msg.has_seq_num = true; msg.seq_num = 17;
        assert(send_message(r, 88, (ERemoteClientBroadcastMsg)atoi(argv[2]), &msg.base));
    } else {
        assert(!strcmp(argv[1], "signal") && argc == 2);
        sl_signal_callbacks callbacks = {.receive = receive};
        sl_signal_channel *channel = sl_signal_channel_create(123, 88, secret, 16, &callbacks, NULL);
        assert(channel && sl_signal_channel_queue(channel, (uint8_t[]){0x38, 1}, 2) &&
               sl_signal_channel_queue(channel, (uint8_t[]){0x58, 1}, 2));
        sl_signal_channel_flush(channel, r);
        assert(!sl_signal_channel_pending(channel));
        sl_signal_channel_destroy(channel);
    }
    assert(packets == 1 && token_calls == (unsigned)manager);
    sl_remote_destroy(r);
    return 0;
}
