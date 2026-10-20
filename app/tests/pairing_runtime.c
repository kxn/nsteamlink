/* Product pairing actor, actual RX/timer UDP, real profile writes/readback.
 * Peer/entropy and a storage failure are controlled inputs, not Steam/SDL pixels. */
#include "crypto.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "ihslib/client.h"
#include "media.h"
#include "network_stats_file.h"
#include "network_test_discovery_peer.h"
#include "platform/runtime.h"
#include "platform/system.h"
#include "remote_connection.h"
#include "services/host_key_store.h"
#include "ui/ui_events.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static uint16_t peer_port;
static atomic_uint random_calls, save_calls, confirmations;
static atomic_uint save_completed;
static atomic_bool allow_queued_save;
static atomic_bool peer_secret_ready;
static bool fail_save, stale_snapshot, proof_mode, proof_file_fail;
static atomic_bool proof_stage;
static atomic_uint proof_key_calls, proof_sent;
static uint8_t rotated[32];
static bool discover_universe, automatic, testing, compatibility;
static unsigned stream_calls, scenario;
static pthread_t save_thread;
static sl_runtime *runtime;
static sl_auth_store initial;
static sl_host host;
static uint8_t peer_secret[32];
void __real_IHS_ClientSetDiscoveryCallbacks(IHS_Client *, const IHS_ClientDiscoveryCallbacks *, void *);
void __wrap_IHS_ClientSetDiscoveryCallbacks(IHS_Client *c,
    const IHS_ClientDiscoveryCallbacks *callbacks, void *context) {
    __real_IHS_ClientSetDiscoveryCallbacks(c, callbacks, context);
    /* LAN authorization fixtures supply prior discovery explicitly.
     * The Beta-universe case still waits for its actual UDP status below. */
    if (!discover_universe)
        test_discovery_observed(c, callbacks, context, peer_port);
}
/* This fixture verifies LAN authorization entropy and actual UDP ownership.
 * Keep the real cloud object/cleanup, but do not contact production directory
 * services: a background WebSocket mask must not consume scripted PIN entropy. */
void __wrap_sl_remote_connection_update(sl_remote_connection *connection, uint64_t now) {
    (void)connection;
    (void)now;
}
bool __wrap_sl_system_random(void *data, size_t size) {
    assert(size == 4);
    unsigned n = atomic_fetch_add(&random_calls, 1);
    assert(n < 3);
    const uint32_t values[] = {0, 10000, 10042};
    memcpy(data, &values[n], 4);
    return true;
}
int __real_IHS_CryptoRandomBytes(uint8_t *, size_t);
int __wrap_IHS_CryptoRandomBytes(uint8_t *out, size_t n) {
    if (automatic && n == 4)
        return __wrap_sl_system_random(out, n) ? 0 : -1;
    return __real_IHS_CryptoRandomBytes(out, n);
}
bool __wrap_sl_network_stats_load(const char *dir, sl_network_stats_average *stats) {
    (void)dir;
    (void)stats;
    return automatic && !testing; /* Controlled stats-readability selection. */
}
bool __real_IHS_ClientStreamingRequest(IHS_Client *, const IHS_HostInfo *,
                                       const IHS_StreamingRequest *);
bool __wrap_IHS_ClientStreamingRequest(IHS_Client *c, const IHS_HostInfo *h,
                                       const IHS_StreamingRequest *request) {
    assert(automatic && ++stream_calls == 1);
    assert(h->universe == (discover_universe ? IHS_SteamUniverseBeta : IHS_SteamUniversePublic));
    assert(request->networkTest == testing);
    assert(request->keySteamId == host.account);
    if (scenario >= 18) {
        uint8_t selected[32], expected[32];
        IHS_ClientGetSecretKey(c, selected);
        for (unsigned n = 0; n < 32; ++n)
            expected[n] = (scenario == 18 ? 64 : 96) + n;
        assert(!memcmp(selected, expected, 32));
    }
    IHS_HostInfo target = *h;
    target.address.port = peer_port;
    return __real_IHS_ClientStreamingRequest(c, &target, request);
}
bool __real_IHS_ClientAuthorizationRequest(IHS_Client *, const IHS_HostInfo *, const char *);
bool __wrap_IHS_ClientAuthorizationRequest(IHS_Client *c, const IHS_HostInfo *h, const char *pin) {
    assert(h->universe == (discover_universe ? IHS_SteamUniverseBeta : IHS_SteamUniversePublic));
    IHS_HostInfo peer = *h;
    peer.address.port = peer_port;
    return __real_IHS_ClientAuthorizationRequest(c, &peer, pin);
}
bool __real_sl_auth_save(const sl_auth_store *, const char *);
bool __wrap_sl_auth_save(const sl_auth_store *s, const char *dir) {
    if (automatic && stale_snapshot && atomic_load(&save_calls) == 1) {
        /* A queued UI snapshot can be saved after Resume. Hold this second
         * actor operation until the peer/UI observes resumption, then wait for
         * the completed real write instead of treating the event as its ACK. */
        unsigned n;
        for (n = 0; n < 5000 && !atomic_load(&allow_queued_save); ++n)
            poll(NULL, 0, 1);
        assert(n < 5000);
    }
    unsigned n = atomic_fetch_add(&save_calls, 1) + 1;
    save_thread = pthread_self();
    bool ok = !fail_save && !(atomic_load(&proof_stage) && proof_file_fail) &&
              __real_sl_auth_save(s, dir);
    if (stale_snapshot && n == 1) {
        sl_command cmd = {.type = SL_CMD_SAVE, .generation = 1};
        assert(sl_runtime_submit(runtime, &cmd, &initial));
    }
    atomic_store_explicit(&save_completed, n, memory_order_release);
    return ok;
}
bool __real_sl_host_key_save(const char *, uint64_t, uint64_t, const uint8_t[32]);
bool __wrap_sl_host_key_save(const char *dir, uint64_t client, uint64_t account,
                             const uint8_t key[32]) {
    if (atomic_load(&proof_stage)) {
        assert(client == host.client_id && account == host.account && !memcmp(key, rotated, 32));
        atomic_fetch_add(&proof_key_calls, 1);
        if (proof_file_fail)
            return false;
    }
    return __real_sl_host_key_save(dir, client, account, key);
}
bool __real_IHS_ClientSend(IHS_Client *, IHS_SocketAddress, ERemoteClientBroadcastMsg,
                           ProtobufCMessage *);
bool __real_IHS_ClientBroadcast(IHS_Client *, ERemoteClientBroadcastMsg, ProtobufCMessage *);
bool __wrap_IHS_ClientBroadcast(IHS_Client *c, ERemoteClientBroadcastMsg type,
                                ProtobufCMessage *m) {
    if (discover_universe && type == k_ERemoteClientBroadcastMsgDiscovery) {
        IHS_SocketAddress a = {.port = peer_port};
        assert(IHS_IPAddressFromString(&a.ip, "127.0.0.1"));
        return __real_IHS_ClientSend(c, a, type, m);
    }
    return __real_IHS_ClientBroadcast(c, type, m);
}
static void observe_control_send(IHS_Client *c, ERemoteClientBroadcastMsg type,
                                 ProtobufCMessage *m) {
    if (type == k_ERemoteDeviceAuthorizationConfirmed &&
        ((CMsgRemoteDeviceAuthorizationConfirmed *)m)->result == 0) {
        assert(atomic_load_explicit(&peer_secret_ready, memory_order_acquire));
        assert(atomic_load(&save_calls) == 1 && pthread_equal(save_thread, pthread_self()));
        char path[512];
        snprintf(path, sizeof(path), "%s/profile.bin", sl_system_data_dir());
        if (fail_save)
            assert(access(path, F_OK) != 0);
        else {
            sl_auth_store loaded;
            assert(sl_auth_load(&loaded, sl_system_data_dir()) == 0);
            const sl_host *saved = sl_host_find(&loaded.registry, host.id);
            assert(saved && saved->paired && saved->account == 76561198000000001ULL &&
                   saved->has_secret && !memcmp(saved->secret, peer_secret, 32));
        }
        atomic_fetch_add(&confirmations, 1);
    }
    if (type == k_ERemoteDeviceProofResponse) {
        assert(atomic_load(&proof_stage) && atomic_load(&proof_key_calls) == 1);
        uint8_t selected[32], actual[32];
        IHS_ClientGetSecretKey(c, selected);
        assert(!memcmp(selected, rotated, 32));
        int loaded = sl_host_key_load(sl_system_data_dir(), host.client_id, host.account, actual);
        if (!proof_file_fail)
            assert(!loaded && !memcmp(actual, rotated, 32));
        else if (host.account == 76561198000000001ULL)
            assert(!loaded && !memcmp(actual, peer_secret, 32));
        else
            assert(loaded == 1);
        sl_auth_store disk;
        assert(sl_auth_load(&disk, sl_system_data_dir()) == 0);
        const sl_host *saved = sl_host_find(&disk.registry, host.id);
        bool mirror = host.account == 76561198000000001ULL;
        assert(saved && saved->account == 76561198000000001ULL && saved->has_secret);
        assert(!memcmp(saved->secret, mirror && !proof_file_fail ? rotated : peer_secret, 32));
        atomic_fetch_add(&proof_sent, 1);
    }
}
bool __wrap_IHS_ClientSend(IHS_Client *c, IHS_SocketAddress a, ERemoteClientBroadcastMsg type,
                           ProtobufCMessage *m) {
    if (discover_universe && type == k_ERemoteClientBroadcastMsgDiscovery) {
        a.port = peer_port;
        assert(IHS_IPAddressFromString(&a.ip, "127.0.0.1"));
    }
    observe_control_send(c, type, m);
    return __real_IHS_ClientSend(c, a, type, m);
}
bool __real_IHS_ClientSendControl(IHS_Client *, const IHS_HostInfo *, const IHS_SocketAddress *,
                                  ERemoteClientBroadcastMsg, ProtobufCMessage *);
bool __wrap_IHS_ClientSendControl(IHS_Client *c, const IHS_HostInfo *host,
                                  const IHS_SocketAddress *source, ERemoteClientBroadcastMsg type,
                                  ProtobufCMessage *m) {
    observe_control_send(c, type, m);
    return __real_IHS_ClientSendControl(c, host, source, type, m);
}
static void response(int fd, const struct sockaddr_in *to, const uint8_t *masked, const char *pin) {
    uint8_t hash[32], public[32], private[32], ours[32], auth[32], id[8], token[64];
    assert(!IHS_CryptoSHA256((const uint8_t *)pin, 4, hash));
    for (unsigned n = 0; n < 32; ++n) {
        public[n] = masked[n] ^ hash[n];
        private[n] = 32 + n;
    }
    assert(!IHS_CryptoX25519PublicKey(private, ours));
    assert(!IHS_CryptoKeyExchange(private, public, peer_secret));
    atomic_store_explicit(&peer_secret_ready, true, memory_order_release);
    for (unsigned n = 0; n < 32; ++n)
        auth[n] = ours[n] ^ hash[n];
    uint64_t device = initial.device_id;
    for (unsigned n = 0; n < 8; ++n)
        id[n] = (uint8_t)(device >> (8 * n));
    size_t count = sizeof(token);
    assert(!IHS_CryptoSymmetricEncrypt(id, 8, peer_secret, 32, token, &count));
    CMsgRemoteDeviceAuthorizationResponse r = CMSG_REMOTE_DEVICE_AUTHORIZATION_RESPONSE__INIT;
    r.result = 0;
    r.has_steamid = r.has_auth_key = r.has_device_token = true;
    r.steamid = 76561198000000001ULL;
    if (compatibility)
        r.has_auth_key = r.has_device_token = false;
    r.auth_key = (ProtobufCBinaryData){32, auth};
    r.device_token = (ProtobufCBinaryData){count, token};
    CMsgRemoteClientBroadcastHeader h = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    h.has_client_id = h.has_msg_type = true;
    h.client_id = 123;
    h.msg_type = k_ERemoteDeviceAuthorizationResponse;
    IHS_Buffer wire = IHS_BUFFER_INIT(1024, 0);
    IHS_BufferAppendMem(&wire, test_discovery_magic, 8);
    IHS_BufferAppendUInt32LE(&wire, cmsg_remote_client_broadcast_header__get_packed_size(&h));
    IHS_BufferAppendMessage(&wire, (void *)&h);
    IHS_BufferAppendUInt32LE(&wire, cmsg_remote_device_authorization_response__get_packed_size(&r));
    IHS_BufferAppendMessage(&wire, (void *)&r);
    assert(sendto(fd, IHS_BufferPointer(&wire), wire.size, 0, (void *)to, sizeof(*to)) ==
           (ssize_t)wire.size);
    IHS_BufferClear(&wire, true);
}
static void one(unsigned mode) {
    char directory[] = "/tmp/nsl-pair-runtime-XXXXXX";
    assert(mkdtemp(directory) && !setenv("NSL_DATA_DIR", directory, 1));
    memset(&initial, 0, sizeof(initial));
    initial.device_id = 0x1122334455667788ULL;
    initial.sound = true;
    initial.bitrate_kbps = 6000;
    strcpy(initial.device_name, "Pair runtime fixture");
    for (unsigned n = 0; n < 32; ++n)
        initial.secret[n] = 32 + n;
    sl_host_registry_init(&initial.registry);
    host = (sl_host){.client_id = 123, .instance_id = 1};
    strcpy(host.address, "127.0.0.1");
    strcpy(host.name, "Controlled authorization peer");
    host = *sl_host_observe(&initial.registry, &host, sl_system_now());
    scenario = mode;
    proof_mode = mode >= 13;
    proof_file_fail = mode == 14 || mode == 16;
    if (mode >= 4 && mode < 8) {
        host.paired = true;
        host.account = 76561198000000002ULL;
        *sl_host_find(&initial.registry, host.id) = host;
    }
    if (proof_mode) {
        host.paired = true;
        host.account = mode <= 14 ? 76561198000000001ULL : mode <= 16 ? 76561198000000002ULL : 0;
        if (mode >= 18) {
            host.account = 76561198000000001ULL;
            host.has_secret = true;
            for (unsigned n = 0; n < 32; ++n)
                host.secret[n] = 96 + n;
            if (mode == 18) {
                uint8_t namespaced[32];
                for (unsigned n = 0; n < 32; ++n)
                    namespaced[n] = 64 + n;
                assert(
                    __real_sl_host_key_save(directory, host.client_id, host.account, namespaced));
            }
        }
        *sl_host_find(&initial.registry, host.id) = host;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(fd, (void *)&a, sizeof(a)));
    socklen_t len = sizeof(a);
    assert(!getsockname(fd, (void *)&a, &len));
    peer_port = ntohs(a.sin_port);
    compatibility = mode == 12;
    automatic = mode >= 4;
    testing = mode >= 8 && !proof_mode;
    fail_save = !proof_mode && mode % 4 == 1;
    stale_snapshot = !proof_mode && mode % 4 == 2;
    discover_universe = !proof_mode && mode % 4 == 3;
    atomic_store(&proof_stage, false);
    atomic_store(&proof_key_calls, 0);
    atomic_store(&proof_sent, 0);
    stream_calls = 0;
    atomic_store(&save_calls, 0);
    atomic_store(&save_completed, 0);
    atomic_store(&allow_queued_save, false);
    atomic_store(&confirmations, 0);
    atomic_store(&random_calls, 0);
    atomic_store(&peer_secret_ready, false);
    runtime = sl_runtime_create(&initial);
    assert(runtime);
    sl_stream_preferences prefs;
    uint64_t revision, deadline = sl_system_now() + 15000;
    while (!sl_runtime_stream_settings(runtime, &prefs, &revision)) {
        assert(sl_system_now() < deadline);
        poll(NULL, 0, 1);
    }
    if (discover_universe) {
        /* Feed real discovery parsing before the command constructs HostInfo. */
        struct pollfd p = {.fd = fd, .events = POLLIN};
        assert(poll(&p, 1, 3000) == 1);
        uint8_t request[4096];
        struct sockaddr_in receiver;
        len = sizeof(receiver);
        assert(recvfrom(fd, request, sizeof(request), 0, (void *)&receiver, &len) > 16);
        CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
        header.has_client_id = header.has_instance_id = header.has_msg_type = true;
        header.client_id = 123;
        header.instance_id = 1;
        header.msg_type = k_ERemoteClientBroadcastMsgStatus;
        CMsgRemoteClientBroadcastStatus status = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
        status.hostname = "Controlled beta peer";
        status.has_euniverse = true;
        status.euniverse = IHS_SteamUniverseBeta;
        IHS_Buffer wire = IHS_BUFFER_INIT(1024, 0);
        IHS_BufferAppendMem(&wire, test_discovery_magic, 8);
        IHS_BufferAppendUInt32LE(&wire,
                                 cmsg_remote_client_broadcast_header__get_packed_size(&header));
        IHS_BufferAppendMessage(&wire, (void *)&header);
        IHS_BufferAppendUInt32LE(&wire,
                                 cmsg_remote_client_broadcast_status__get_packed_size(&status));
        IHS_BufferAppendMessage(&wire, (void *)&status);
        assert(sendto(fd, IHS_BufferPointer(&wire), wire.size, 0, (void *)&receiver,
                      sizeof(receiver)) == (ssize_t)wire.size);
        IHS_BufferClear(&wire, true);
        bool found = false;
        while (!found) {
            assert(sl_system_now() < deadline);
            sl_runtime_event event;
            while (sl_runtime_poll(runtime, &event))
                found |= event.type == SL_EVENT_HOST && event.host.client_id == 123;
            poll(NULL, 0, 1);
        }
    }
    sl_command cmd = {.type = automatic ? SL_CMD_STREAM : SL_CMD_PAIR,
                      .generation = 1,
                      .host = host,
                      .test_only = testing};
    sl_ui_model ui;
    sl_ui_init(&ui, &initial);
    ui.generation = 1;
    ui.intent = cmd;
    ui.page = testing ? SL_NETWORK_TEST : SL_CONNECTING;
    if (automatic)
        strcpy(cmd.text, "9876");
    assert(sl_runtime_submit(runtime, &cmd, &initial));
    char pin[5] = {0};
    uint8_t key[32];
    bool have_key = false, replied = false, authorized = false;
    struct sockaddr_in to = {0};
    bool unauthorized = false, resumed_stream = false;
    uint32_t original_id = 0;
    uint8_t original_pin[64];
    size_t original_pin_len = 0;
    while (!authorized || (!compatibility && !atomic_load(&confirmations)) ||
           (automatic && !resumed_stream)) {
        assert(sl_system_now() < deadline);
        sl_runtime_event e;
        while (sl_runtime_poll(runtime, &e)) {
            if (e.type == SL_EVENT_FAILURE)
                fprintf(stderr, "pair failure: %s\n", e.text);
            assert(e.type != SL_EVENT_FAILURE);
            if (automatic) {
                assert(e.type != SL_EVENT_CODE && e.type != SL_EVENT_AUTHORIZED);
                sl_ui_runtime_event(&ui, &e);
                assert(ui.command.type == SL_CMD_NONE);
            }
            if (e.type == SL_EVENT_CODE || e.type == SL_EVENT_STREAM_AUTHORIZATION) {
                assert(!strcmp(e.text, "0042"));
                strcpy(pin, e.text);
            }
            if (e.type == SL_EVENT_AUTHORIZED || e.type == SL_EVENT_STREAM_RESUMED) {
                assert(e.host.account == 76561198000000001ULL && e.host.paired);
                assert(e.host.has_secret == !compatibility);
                if (!compatibility)
                    assert(!memcmp(e.host.secret, peer_secret, 32));
                authorized = true;
            }
        }
        struct pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 2) > 0) {
            uint8_t wire[4096];
            len = sizeof(to);
            ssize_t n = recvfrom(fd, wire, sizeof(wire), 0, (void *)&to, &len);
            assert(n > 16);
            unsigned hs = test_discovery_u32(wire + 8), size = test_discovery_u32(wire + 12 + hs);
            assert(hs + size + 16u == (size_t)n);
            CMsgRemoteClientBroadcastHeader *h =
                cmsg_remote_client_broadcast_header__unpack(NULL, hs, wire + 12);
            assert(h);
            if (h->msg_type == k_ERemoteDeviceAuthorizationRequest) {
                CMsgRemoteDeviceAuthorizationRequest *r =
                    cmsg_remote_device_authorization_request__unpack(NULL, size, wire + 16 + hs);
                assert(r && r->has_auth_key && r->auth_key.len == 32);
                memcpy(key, r->auth_key.data, 32);
                have_key = true;
                cmsg_remote_device_authorization_request__free_unpacked(r, NULL);
            }
            if (automatic && h->msg_type == k_ERemoteDeviceStreamingRequest) {
                CMsgRemoteDeviceStreamingRequest *request =
                    cmsg_remote_device_streaming_request__unpack(NULL, size, wire + 16 + hs);
                assert(request && request->has_pin && request->network_test == testing);
                if (!unauthorized) {
                    original_id = request->request_id;
                    original_pin_len = request->pin.len;
                    assert(original_pin_len < sizeof(original_pin));
                    memcpy(original_pin, request->pin.data, original_pin_len);
                    CMsgRemoteDeviceStreamingResponse response =
                        CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
                    response.request_id = original_id;
                    response.result = k_ERemoteDeviceStreamingUnauthorized;
                    uint8_t raw[64];
                    size_t count = cmsg_remote_device_streaming_response__pack(&response, raw);
                    test_discovery_send(fd, &to, raw, count);
                    unauthorized = true;
                } else if (compatibility ? replied : atomic_load(&confirmations)) {
                    assert(request->request_id == original_id &&
                           request->pin.len == original_pin_len &&
                           !memcmp(request->pin.data, original_pin, original_pin_len));
                    uint8_t plain[64];
                    size_t plain_len = sizeof(plain);
                    assert(!IHS_CryptoSymmetricDecrypt(request->device_token.data,
                                                       request->device_token.len,
                                                       compatibility ? initial.secret : peer_secret,
                                                       32, plain, &plain_len) &&
                           plain_len == 8);
                    assert(!memcmp(plain, &initial.device_id, 8));
                    resumed_stream = true;
                }
                cmsg_remote_device_streaming_request__free_unpacked(request, NULL);
            }
            cmsg_remote_client_broadcast_header__free_unpacked(h, NULL);
        }
        if (have_key && pin[0] && !replied) {
            response(fd, &to, key, pin);
            replied = true;
        }
    }
    atomic_store(&allow_queued_save, true);
    unsigned expected_saves = compatibility ? 0u : stale_snapshot ? 2u : 1u;
    while (atomic_load_explicit(&save_completed, memory_order_acquire) < expected_saves) {
        assert(sl_system_now() < deadline);
        poll(NULL, 0, 1);
    }
    assert(atomic_load(&random_calls) == 3 && atomic_load(&save_calls) == (compatibility    ? 0u
                                                                           : stale_snapshot ? 2u
                                                                                            : 1u));
    if (stale_snapshot) {
        sl_auth_store loaded;
        assert(sl_auth_load(&loaded, directory) == 0);
        const sl_host *saved = sl_host_find(&loaded.registry, host.id);
        assert(saved && saved->paired && saved->has_secret &&
               !memcmp(saved->secret, peer_secret, 32));
    }
    if (automatic) {
        assert(stream_calls == 1 && ui.command.type == SL_CMD_NONE);
        assert(ui.page == (testing ? SL_NETWORK_TEST : SL_CONNECTING));
        assert(ui.intent.host.account == 76561198000000001ULL && ui.intent.host.paired);
        assert(ui.intent.host.has_secret == !compatibility);
        if (!compatibility)
            assert(!memcmp(ui.intent.host.secret, peer_secret, 32));
    }
    if (proof_mode) {
        static const uint8_t challenge[] = {'p', 0, 'r', 0xff, 'f'};
        uint8_t hash_input[37];
        memcpy(hash_input, peer_secret, 32);
        memcpy(hash_input + 32, challenge, 5);
        assert(!IHS_CryptoSHA256(hash_input, sizeof(hash_input), rotated));
        atomic_store(&proof_stage, true);
        for (unsigned trial = 0; trial < 3; ++trial) {
            CMsgRemoteDeviceProofRequest proof = CMSG_REMOTE_DEVICE_PROOF_REQUEST__INIT;
            proof.challenge = (ProtobufCBinaryData){sizeof(challenge), (uint8_t *)challenge};
            proof.has_update_secret = true;
            proof.update_secret = trial != 1;
            proof.has_request_id = trial != 0; /* Absent ID still replies with owner ID. */
            proof.request_id = original_id;
            CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
            header.has_client_id = header.has_msg_type = true;
            header.client_id = 123;
            header.msg_type = k_ERemoteDeviceProofRequest;
            IHS_Buffer message = IHS_BUFFER_INIT(1024, 0);
            IHS_BufferAppendMem(&message, test_discovery_magic, 8);
            IHS_BufferAppendUInt32LE(&message,
                                     cmsg_remote_client_broadcast_header__get_packed_size(&header));
            IHS_BufferAppendMessage(&message, (void *)&header);
            IHS_BufferAppendUInt32LE(&message,
                                     cmsg_remote_device_proof_request__get_packed_size(&proof));
            IHS_BufferAppendMessage(&message, (void *)&proof);
            assert(sendto(fd, IHS_BufferPointer(&message), message.size, 0, (void *)&to,
                          sizeof(to)) == (ssize_t)message.size);
            IHS_BufferClear(&message, true);
            bool received = false;
            while (!received) {
                assert(sl_system_now() < deadline);
                struct pollfd poller = {.fd = fd, .events = POLLIN};
                if (poll(&poller, 1, 2) > 0) {
                    uint8_t wire[4096];
                    ssize_t count = recv(fd, wire, sizeof(wire), 0);
                    assert(count > 16);
                    unsigned hs = test_discovery_u32(wire + 8),
                             ps = test_discovery_u32(wire + 12 + hs);
                    CMsgRemoteClientBroadcastHeader *h =
                        cmsg_remote_client_broadcast_header__unpack(NULL, hs, wire + 12);
                    assert(h);
                    if (h->msg_type == k_ERemoteDeviceProofResponse) {
                        CMsgRemoteDeviceProofResponse *response =
                            cmsg_remote_device_proof_response__unpack(NULL, ps, wire + 16 + hs);
                        assert(response && response->has_request_id &&
                               response->request_id == original_id &&
                               response->has_updated_secret &&
                               response->updated_secret == (trial != 1));
                        uint8_t plain[64];
                        size_t size = sizeof(plain);
                        assert(!IHS_CryptoSymmetricDecrypt(response->response.data,
                                                           response->response.len, rotated, 32,
                                                           plain, &size) &&
                               size == sizeof(challenge) && !memcmp(plain, challenge, size));
                        cmsg_remote_device_proof_response__free_unpacked(response, NULL);
                        received = true;
                    }
                    cmsg_remote_client_broadcast_header__free_unpacked(h, NULL);
                }
                sl_runtime_event event;
                while (sl_runtime_poll(runtime, &event)) {
                    assert(event.type != SL_EVENT_FAILURE);
                    sl_ui_runtime_event(&ui, &event);
                    assert(ui.command.type == SL_CMD_NONE);
                }
            }
        }
        assert(atomic_load(&proof_key_calls) == 1 && atomic_load(&proof_sent) == 3);
        assert(atomic_load(&save_calls) == (host.account == 76561198000000001ULL ? 2u : 1u));
        assert(ui.intent.host.account == 76561198000000001ULL && ui.intent.host.has_secret);
        assert(!memcmp(ui.intent.host.secret,
                       host.account == 76561198000000001ULL ? rotated : peer_secret, 32));
    }
    sl_runtime_destroy(runtime);
    runtime = NULL;
    close(fd);
    DIR *dir = opendir(directory);
    assert(dir);
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        assert(!unlink(path));
    }
    closedir(dir);
    assert(!rmdir(directory));
    printf("Pair runtime mode=%u: nonzero PIN, actor persistence before ACK, file "
           "readback/failure, stale-snapshot handling and joined teardown passed\n",
           mode);
}
int main(void) {
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    for (unsigned n = 0; n < 20; ++n)
        one(n);
    stream_media_shutdown();
    return 0;
}
