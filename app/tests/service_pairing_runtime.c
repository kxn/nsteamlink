/* Actual product worker, shared IHS receive owner, crypto and persistent files.
 * CM service/UDP syscalls are providers. The UI queues a stale empty snapshot
 * inside the first real profile-save call, before authorization completes. */
#include "../platforms/common/runtime.c"
#include "crypto.h"
#include "fixture_cleanup.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "remote_wire.h"
#include "ui/ui_events.h"
#include <assert.h>
#include <poll.h>
#include <sys/stat.h>

static const uint64_t account = UINT64_C(76561198000000001), client = 456;
static sl_remote *protocol;
static sl_runtime *actor, *runtime;
static char connection;
static pthread_t owner;
static unsigned responses;
static uint8_t auth_wire[1024], accepted_secret[32];
static size_t auth_size;
static atomic_bool ready, deliver_auth;
static atomic_uint saves, saves_done, confirmed, confirm_calls;
static sl_auth_store empty;

static sl_proto_field field(const void *raw, size_t size, unsigned number) {
    sl_proto_reader reader = {raw, size, 0, false};
    sl_proto_field f, out = {0};
    while (sl_proto_next(&reader, &f))
        if (f.number == number)
            out = f;
    assert(sl_proto_done(&reader));
    return out;
}
static bool receive(unsigned kind, const void *raw, size_t size) {
    uint8_t wire[2048];
    sl_proto_writer out = {wire, 0, sizeof(wire), false};
    sl_proto_uint(&out, 1, 1);
    sl_proto_bytes(&out, kind, raw, size);
    assert(!out.invalid);
    return sl_remote_receive(protocol, wire, out.size);
}
static void prepare_reply(sl_proto_field body) {
    sl_proto_field masked = field(body.bytes, body.size, 4);
    assert(masked.size == 32 && IHS_ClientAuthorizationServiceActive(actor->client));
    assert(field(body.bytes, body.size, 5).number && !field(body.bytes, body.size, 5).value);
    uint8_t hash[32], peer_private[32], peer_public[32], client_public[32], key[32], token[64],
        id[8];
    assert(!IHS_CryptoSHA256((const uint8_t *)"1234", 4, hash));
    for (unsigned n = 0; n < 32; ++n) {
        peer_private[n] = 32 + n;
        client_public[n] = masked.bytes[n] ^ hash[n];
    }
    assert(!IHS_CryptoX25519PublicKey(peer_private, peer_public));
    assert(!IHS_CryptoKeyExchange(peer_private, client_public, accepted_secret));
    for (unsigned n = 0; n < 32; ++n)
        key[n] = peer_public[n] ^ hash[n];
    IHS_WriteUInt64LE(id, empty.device_id);
    size_t size = sizeof(token);
    assert(!IHS_CryptoSymmetricEncrypt(id, sizeof(id), accepted_secret, 32, token, &size));
    CMsgRemoteDeviceAuthorizationResponse reply = CMSG_REMOTE_DEVICE_AUTHORIZATION_RESPONSE__INIT;
    reply.result = k_ERemoteDeviceAuthorizationSuccess;
    reply.has_steamid = reply.has_auth_key = reply.has_device_token = true;
    reply.steamid = account;
    reply.auth_key = (ProtobufCBinaryData){sizeof(key), key};
    reply.device_token = (ProtobufCBinaryData){size, token};
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_msg_type = true;
    header.client_id = client;
    header.msg_type = k_ERemoteDeviceAuthorizationResponse;
    const uint8_t magic[] = {255, 255, 255, 255, 33, 76, 95, 160};
    memcpy(auth_wire, magic, 8);
    size_t hs = protobuf_c_message_pack(&header.base, auth_wire + 12);
    IHS_WriteUInt32LE(auth_wire + 8, hs);
    size_t ms = protobuf_c_message_pack(&reply.base, auth_wire + 16 + hs);
    IHS_WriteUInt32LE(auth_wire + 12 + hs, ms);
    auth_size = hs + ms + 16;
}
static bool send_rpc(const uint8_t *raw, size_t size, void *ctx) {
    (void)ctx;
    assert(pthread_equal(owner, pthread_self()));
    if (field(raw, size, 1).number)
        responses |= 1;
    if (field(raw, size, 2).number)
        responses |= 2;
    sl_proto_field publish = field(raw, size, 3);
    if (publish.number) {
        prepare_reply(field(publish.bytes, publish.size, 3));
        responses |= 4;
    }
    sl_proto_field packet = field(raw, size, 7);
    if (packet.number) {
        sl_proto_field frame = field(packet.bytes, packet.size, 4);
        uint32_t hs;
        assert(frame.size >= 16);
        IHS_ReadUInt32LE(frame.bytes + 8, &hs);
        assert(hs <= frame.size - 16);
        unsigned kind = field(frame.bytes + 12, hs, 2).value;
        if (kind == 14) {
            assert(!field(frame.bytes + 16 + hs, frame.size - 16 - hs, 1).value);
            assert(field(packet.bytes, packet.size, 2).value == account);
            /* The copied CM frame can flush after the next queued UI save.
             * The earlier IHS caller boundary below verifies save-before-ACK. */
            assert(atomic_load(&saves_done) >= 1 && atomic_load(&confirm_calls) == 1);
            atomic_fetch_add(&confirmed, 1);
        }
    }
    return true;
}
sl_remote_connection *__wrap_sl_remote_connection_create(const IHS_ClientConfig *config,
                                                         const sl_remote_callbacks *callbacks,
                                                         void *ctx) {
    assert(!protocol);
    owner = pthread_self();
    actor = ctx;
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
    (void)now;
    sl_remote_update(protocol, time(NULL));
    unsigned pending = responses;
    responses = 0;
    uint8_t body[64];
    sl_proto_writer out = {body, 0, sizeof(body), false};
    if (pending & 1) {
        sl_proto_fixed64(&out, 1, 1001);
        sl_proto_uint(&out, 2, 1);
        assert(receive(2, body, out.size));
        atomic_store(&ready, true);
    }
    if (pending & 2) {
        out.size = 0;
        sl_proto_uint(&out, 1, 1234);
        assert(receive(3, body, out.size));
    }
    if (pending & 4)
        assert(receive(4, NULL, 0));
    if (auth_size && atomic_exchange(&deliver_auth, false)) {
        out.size = 0;
        uint8_t payload[1100];
        sl_proto_writer packet = {payload, 0, sizeof(payload), false};
        sl_proto_bytes(&packet, 1, auth_wire, auth_size);
        assert(receive(6, payload, packet.size));
        auth_size = 0;
    }
}
#if NSL_DIAGNOSTICS
void __wrap_sl_remote_connection_describe(const sl_remote_connection *c, uint64_t now, char *out,
                                          size_t size) {
    (void)c;
    (void)now;
    snprintf(out, size, "fixture CM service");
}
#endif
void __wrap_sl_remote_connection_destroy(sl_remote_connection *c) {
    assert(c == (sl_remote_connection *)&connection && pthread_equal(owner, pthread_self()));
    sl_remote_close(protocol);
    sl_remote_destroy(protocol);
    protocol = NULL;
}
ssize_t __wrap_sendto(int fd, const void *raw, size_t size, int flags,
                      const struct sockaddr *address, socklen_t length) {
    (void)fd;
    (void)raw;
    (void)flags;
    (void)address;
    (void)length;
    return size; /* No discovery or control datagram leaves this fixture. */
}
bool __real_sl_auth_save(const sl_auth_store *, const char *);
bool __real_IHS_ClientSendControl(IHS_Client *, const IHS_HostInfo *, const IHS_SocketAddress *,
                                  ERemoteClientBroadcastMsg, ProtobufCMessage *);
bool __wrap_IHS_ClientSendControl(IHS_Client *c, const IHS_HostInfo *host,
                                  const IHS_SocketAddress *source, ERemoteClientBroadcastMsg type,
                                  ProtobufCMessage *message) {
    if (type == k_ERemoteDeviceAuthorizationConfirmed) {
        assert(((CMsgRemoteDeviceAuthorizationConfirmed *)message)->result == 0);
        assert(atomic_load(&saves_done) == 1 && pthread_equal(owner, pthread_self()));
        atomic_fetch_add(&confirm_calls, 1);
    }
    return __real_IHS_ClientSendControl(c, host, source, type, message);
}
bool __wrap_sl_auth_save(const sl_auth_store *store, const char *dir) {
    assert(pthread_equal(owner, pthread_self()));
    unsigned count = atomic_fetch_add(&saves, 1) + 1;
    if (count == 1) {
        assert(store->registry.count == 1 && store->registry.hosts[0].client_id == client);
        /* Submitted before credential_revision increments and before the
         * paired event exists. The UI cannot include its new host yet. */
        sl_command save = {.type = SL_CMD_SAVE, .generation = 1};
        assert(sl_runtime_submit(runtime, &save, &empty));
    } else if (count == 2) {
        assert(store->registry.count == 1 && store->registry.hosts[0].client_id == client);
        assert(store->registry.hosts[0].paired && store->registry.hosts[0].has_secret &&
               !memcmp(store->registry.hosts[0].secret, accepted_secret, 32));
    } else
        assert(count == 3 && !store->registry.count); /* Explicit later removal. */
    bool ok = __real_sl_auth_save(store, dir);
    atomic_store(&saves_done, count);
    return ok;
}
static void one(bool fail_key_file) {
    char dir[] = "/tmp/nsl-service-runtime-XXXXXX";
    assert(mkdtemp(dir) && !setenv("NSL_DATA_DIR", dir, 1));
    empty = (sl_auth_store){.device_id = 42, .sound = true};
    memset(empty.secret, 0x4D, 32);
    strcpy(empty.device_name, "service runtime fixture");
    sl_host_registry_init(&empty.registry);
    char blocked[1024];
    uint8_t namespace[16];
    IHS_WriteUInt64LE(namespace, client);
    IHS_WriteUInt64LE(namespace + 8, account);
    char hex[33];
    for (unsigned n = 0; n < 16; ++n)
        snprintf(hex + n * 2, 3, "%02x", namespace[n]);
    snprintf(blocked, sizeof(blocked), "%s/key-%s.txt.tmp", dir, hex);
    if (fail_key_file)
        assert(!mkdir(blocked, 0700));
    responses = 0;
    auth_size = 0;
    atomic_store(&ready, false);
    atomic_store(&deliver_auth, false);
    atomic_store(&saves, 0);
    atomic_store(&saves_done, 0);
    atomic_store(&confirmed, 0);
    atomic_store(&confirm_calls, 0);
    runtime = sl_runtime_create(&empty);
    assert(runtime);
    uint64_t deadline = sl_system_now() + 8000;
    while (!atomic_load(&ready)) {
        assert(sl_system_now() < deadline);
        poll(NULL, 0, 1);
    }
    sl_command pair = {.type = SL_CMD_REMOTE_PAIR, .generation = 1};
    assert(sl_runtime_submit(runtime, &pair, &empty));
    sl_ui_model ui;
    sl_ui_init(&ui, &empty);
    sl_ui_action(&ui, SL_OPEN_REMOTE_PAIR, 0);
    assert(ui.generation == 1 && ui.page == SL_PAIRING);
    bool got_code = false, paired = false;
    while (!paired || atomic_load(&saves_done) < 2 || !atomic_load(&confirmed)) {
        assert(sl_system_now() < deadline);
        sl_runtime_event event;
        while (sl_runtime_poll(runtime, &event)) {
            assert(event.type != SL_EVENT_FAILURE);
            sl_ui_runtime_event(&ui, &event);
            if (event.type == SL_EVENT_CODE) {
                assert(!strcmp(event.text, "1234"));
                got_code = true;
                atomic_store(&deliver_auth, true);
            }
            paired |= event.type == SL_EVENT_AUTHORIZED;
        }
        poll(NULL, 0, 1);
    }
    assert(got_code && ui.page == SL_HOME && !ui.adding_host && ui.store.registry.count == 1);
    sl_host host = ui.store.registry.hosts[0];
    assert(host.client_id == client && host.account == account && host.paired && host.has_secret &&
           !memcmp(host.secret, accepted_secret, 32));
    sl_auth_store disk;
    assert(!sl_auth_load(&disk, dir) && disk.registry.count == 1);
    assert(disk.registry.next_id > host.id && disk.registry.hosts[0].client_id == client &&
           !memcmp(disk.registry.hosts[0].secret, accepted_secret, 32));
    uint8_t key[32];
    int loaded = sl_host_key_load(dir, client, account, key);
    assert(fail_key_file ? loaded == 1 : !loaded && !memcmp(key, accepted_secret, 32));
    sl_command save = {.type = SL_CMD_SAVE, .generation = 1};
    assert(sl_runtime_submit(runtime, &save, &empty));
    while (atomic_load(&saves_done) < 3) {
        assert(sl_system_now() < deadline);
        poll(NULL, 0, 1);
    }
    assert(!sl_auth_load(&disk, dir) && !disk.registry.count);
    sl_runtime_destroy(runtime);
    runtime = actor = NULL;
    sl_fixture_remove_tree(dir);
    printf("PASS service product worker: key-file-failure=%d, shared CM auth, UI pairing, "
           "pre-completion stale snapshot, persisted new host, explicit later removal, joined "
           "teardown\n",
           fail_key_file);
}
int main(void) {
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    one(false);
    one(true);
    stream_media_shutdown();
    return 0;
}
