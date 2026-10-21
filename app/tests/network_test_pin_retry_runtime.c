/* Real application/runtime/IHS UDP/Test owners; a controlled loopback host
 * supplies tickets/PIN/results. No Steam, SDK, Qt or Switch is exercised. */
#include "../platforms/common/application.c"
#include "crypto.h"
#include "fixture_cleanup.h"
#include "network_test_discovery_peer.h"
#include "protobuf/remoteplay.pb-c.h"
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <unistd.h>
#if NSL_HAVE_SNS
#include "sns_backend.h"
#include "sns_config_cache.h"
#endif

static uint16_t peer_port;
static bool preinit, cancel_join, completed;
static unsigned startup_failure; /* 1 old SDK BInit fails; 2 old IHS setup fails. */
static atomic_uint creates, joins, destroys, samples, disconnects, backends, backend_destroys;
static atomic_bool allow_old_init;
static atomic_bool new_request_seen, ticket_seen;
static atomic_uint manager_updates;
static unsigned early_disconnects;
static IHS_Session *old_session;
bool __real_IHS_ClientUpdate(IHS_Client *, void (*)(void *), void (*)(void *), void *);
bool __wrap_IHS_ClientUpdate(IHS_Client *c, void (*session)(void *), void (*expire)(void *),
                             void *ctx) {
    bool result = __real_IHS_ClientUpdate(c, session, expire, ctx);
    atomic_fetch_add(&manager_updates, 1);
    if (atomic_load(&new_request_seen) && IHS_ClientHandshakePhase(c) == 6)
        atomic_store(&ticket_seen, true);
    return result;
}
void __real_IHS_ClientSetDiscoveryCallbacks(IHS_Client *, const IHS_ClientDiscoveryCallbacks *,
                                            void *);
void __wrap_IHS_ClientSetDiscoveryCallbacks(IHS_Client *c, const IHS_ClientDiscoveryCallbacks *cb,
                                            void *ctx) {
    __real_IHS_ClientSetDiscoveryCallbacks(c, cb, ctx);
    test_discovery_observed(c, cb, ctx, peer_port);
}
bool __real_IHS_ClientStreamingRequest(IHS_Client *, const IHS_HostInfo *,
                                       const IHS_StreamingRequest *);
bool __wrap_IHS_ClientStreamingRequest(IHS_Client *c, const IHS_HostInfo *h,
                                       const IHS_StreamingRequest *req) {
    IHS_HostInfo direct = *h;
    direct.address.port = peer_port;
    return __real_IHS_ClientStreamingRequest(c, &direct, req);
}
IHS_Session *__real_IHS_SessionCreate(const IHS_ClientConfig *, const IHS_SessionInfo *);
IHS_Session *__wrap_IHS_SessionCreate(const IHS_ClientConfig *c, const IHS_SessionInfo *info) {
    unsigned index = atomic_load(&creates);
    assert(index < 2 && info->sessionKeyLen == 32);
    for (unsigned i = 0; i < 32; ++i)
        assert(info->sessionKey[i] == i + (index || startup_failure == 1 ? 128 : 0));
    /* The SDK/bridge are providers in preinit mode. Route the real IHS worker
     * to our loopback peer, after checking the actual runtime's frozen key. */
    IHS_SessionInfo direct = *info;
    if (preinit)
        direct.address.port = peer_port;
    IHS_Session *s = __real_IHS_SessionCreate(c, &direct);
    if (!index && startup_failure != 1)
        old_session = s;
    assert(s);
    atomic_fetch_add(&creates, 1);
    return s;
}
void __real_IHS_SessionThreadedJoin(IHS_Session *);
void __wrap_IHS_SessionThreadedJoin(IHS_Session *s) {
    __real_IHS_SessionThreadedJoin(s);
    atomic_fetch_add(&joins, 1);
}
void __real_IHS_SessionDestroy(IHS_Session *);
void __wrap_IHS_SessionDestroy(IHS_Session *s) {
    __real_IHS_SessionDestroy(s);
    atomic_fetch_add(&destroys, 1);
}
void __real_IHS_SessionGetNetworkTestResult(IHS_Session *, IHS_NetworkTestResult *);
void __wrap_IHS_SessionGetNetworkTestResult(IHS_Session *s, IHS_NetworkTestResult *r) {
    atomic_fetch_add(&samples, 1);
    __real_IHS_SessionGetNetworkTestResult(s, r);
}
void __real_IHS_SessionDisconnect(IHS_Session *);
void __wrap_IHS_SessionDisconnect(IHS_Session *s) {
    if (s == old_session && !atomic_load(&joins)) {
        IHS_NetworkTestResult result;
        __real_IHS_SessionGetNetworkTestResult(s, &result);
        if (result.status == IHS_NetworkTestRunning)
            ++early_disconnects;
    }
    atomic_fetch_add(&disconnects, 1);
    __real_IHS_SessionDisconnect(s);
}
void __real_IHS_ClientStreamingEstablished(IHS_Client *);
void __wrap_IHS_ClientStreamingEstablished(IHS_Client *c) {
    /* Completing the old BInit behind PIN must not acknowledge the new ID. */
    assert(!preinit || atomic_load(&creates) == (startup_failure == 1 ? 1 : 2));
    __real_IHS_ClientStreamingEstablished(c);
}
#if NSL_HAVE_SNS
static char backend;
static bool backend_live;
sl_sns *__wrap_sl_sns_create_configured(const IHS_ClientConfig *c, const sl_remote_material *m,
                                        bool share, char *error, size_t capacity, const char *cache,
                                        size_t size) {
    (void)c;
    (void)error;
    (void)capacity;
    (void)cache;
    (void)size;
    assert(preinit && share && !backend_live && m->key_size == 32);
    for (unsigned i = 0; i < 32; ++i)
        assert(m->key[i] == i);
    backend_live = true;
    atomic_fetch_add(&backends, 1);
    return (sl_sns *)&backend;
}
void __wrap_sl_sns_update(sl_sns *s, uint64_t now) {
    (void)now;
    assert(s == (sl_sns *)&backend && backend_live);
}
bool __wrap_sl_sns_session_ready(const sl_sns *s) {
    assert(s == (sl_sns *)&backend && backend_live);
    return atomic_load(&allow_old_init) && startup_failure != 1;
}
sl_sns_state __wrap_sl_sns_get_state(const sl_sns *s) {
    assert(s == (sl_sns *)&backend && backend_live);
    return atomic_load(&allow_old_init) ? startup_failure == 1 ? SL_SNS_FAILED : SL_SNS_CONNECTED
                                        : SL_SNS_CONNECTING;
}
void __wrap_sl_sns_get_stats(const sl_sns *s, sl_sns_stats *out) {
    assert(s == (sl_sns *)&backend && backend_live);
    memset(out, 0, sizeof(*out));
}
int __wrap_sl_sns_end_reason(const sl_sns *s) {
    (void)s;
    return 0;
}
void __wrap_sl_sns_destroy(sl_sns *s) {
    if (!s)
        return;
    assert(s == (sl_sns *)&backend && backend_live && atomic_load(&joins) == atomic_load(&creates));
    backend_live = false;
    atomic_fetch_add(&backend_destroys, 1);
}
const IHS_DatagramTransport *__wrap_sl_sns_datagram_transport(void) {
    static const IHS_DatagramTransport provided = {0};
    return &provided;
}
bool __wrap_IHS_SessionSetDatagramTransport(IHS_Session *s, const IHS_DatagramTransport *t,
                                            void *ctx) {
    (void)s;
    (void)t;
    assert(preinit && ctx == &backend && backend_live);
    return startup_failure != 2;
}
void __wrap_sl_sns_config_cache_update(sl_sns_config_cache *c) {
    (void)c;
}
#endif
static void control(int fd, const struct sockaddr_in *to, unsigned local, unsigned type,
                    unsigned id, const uint8_t *body, size_t size) {
    uint8_t wire[256] = {type, 0, 7, local, type == 5 ? 1 : 0};
    assert(size + 13 <= sizeof(wire));
    wire[7] = id;
    wire[8] = id >> 8;
    uint32_t tick = 1000000;
    memcpy(wire + 9, &tick, 4);
    memcpy(wire + 13, body, size);
    assert(sendto(fd, wire, size + 13, 0, (const void *)to, sizeof(*to)) == (ssize_t)(size + 13));
}
static void ticket(int fd, const struct sockaddr_in *to, unsigned id, unsigned result,
                   const sl_auth_store *store, bool replacement) {
    CMsgRemoteDeviceStreamingResponse reply = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
    reply.request_id = id;
    reply.result = result;
    uint8_t key[32], cipher[128], body[256];
    if (result == k_ERemoteDeviceStreamingSuccess) {
        reply.has_port = reply.has_encrypted_session_key = true;
        reply.port = peer_port;
        for (unsigned i = 0; i < 32; ++i)
            key[i] = i + (replacement ? 128 : 0);
        size_t size = sizeof(cipher);
        assert(!IHS_CryptoSymmetricEncrypt(key, 32, store->secret, 32, cipher, &size));
        reply.encrypted_session_key = (ProtobufCBinaryData){size, cipher};
        if (preinit && !replacement) {
            reply.has_transport = true;
            reply.transport = k_EStreamTransportSDR;
            reply.cert = "fixture-certificate";
            reply.relay_server = "stun:fixture.invalid:3478";
        }
    }
    size_t size = cmsg_remote_device_streaming_response__pack(&reply, body);
    test_discovery_send(fd, to, body, size);
}
enum scenario {
    CANCEL_WAIT,
    SUCCESS,
    FAILURE,
    PIN_AGAIN,
    UNAUTHORIZED,
    BUSY,
    DUPLICATE_SUCCESS,
    FAILURE_AFTER_TICKET
};
static const char *names[] = {
    "cancel_wait",  "success", "failure",           "pin",
    "unauthorized", "busy",    "duplicate_success", "failure_after_ticket"};
static void one(enum scenario which, bool manual) {
    fprintf(stderr, "pin_retry scenario=%s manual=%u\n", names[which], manual);
    atomic_store(&creates, 0);
    atomic_store(&joins, 0);
    atomic_store(&destroys, 0);
    atomic_store(&samples, 0);
    atomic_store(&disconnects, 0);
    atomic_store(&backends, 0);
    atomic_store(&backend_destroys, 0);
    atomic_store(&allow_old_init, false);
    early_disconnects = 0;
    old_session = NULL;
    atomic_store(&new_request_seen, false);
    atomic_store(&ticket_seen, false);
    atomic_store(&manager_updates, 0);
    char directory[] = "/tmp/nsl-pin-retry-XXXXXX";
    assert(mkdtemp(directory) && !setenv("NSL_DATA_DIR", directory, 1));
    sl_auth_store store = {.device_id = 1, .sound = true, .bitrate_kbps = 6000};
    strcpy(store.device_name, "PIN retry fixture");
    for (unsigned i = 0; i < 32; ++i)
        store.secret[i] = 32 + i;
    sl_host_registry_init(&store.registry);
    sl_host host = {.client_id = 123, .instance_id = 1, .paired = true, .account = 123456};
    strcpy(host.name, "Controlled peer");
    strcpy(host.address, "127.0.0.1");
    sl_host *saved = sl_host_observe(&store.registry, &host, sl_system_now());
    assert(saved);
    saved->paired = true;
    saved->account = 123456;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(fd, (void *)&local, sizeof(local)));
    socklen_t length = sizeof(local);
    assert(!getsockname(fd, (void *)&local, &length));
    peer_port = ntohs(local.sin_port);
    application a = {0};
    sl_app_lifecycle_init(&a.lifecycle);
    sl_ui_init(&a.ui, &store);
    a.ui.now = sl_system_now();
    a.runtime = sl_runtime_create(&store);
    assert(a.runtime);
    if (manual) {
        sl_ui_action(&a.ui, SL_OPEN_SETTINGS, 0);
        sl_ui_action(&a.ui, SL_OPEN_NETWORK_SETTINGS, 0);
        sl_ui_action(&a.ui, SL_RUN_NETWORK_TEST, 0);
    } else
        sl_ui_action(&a.ui, SL_START, 0);
    sl_command cmd;
    assert(sl_ui_take_command(&a.ui, &cmd) && cmd.type == SL_CMD_STREAM && cmd.test_only == manual);
    assert(command(&a, &cmd));
    unsigned initial_id = 0, retry_id = 0, requests = 0, streaming_cancels = 0, auth_cancels = 0;
    unsigned cancels_before_ack = 0, sample_wait = 0;
    bool initial_started = false, initial_pin = false, retry_submitted = false, responded = false;
    bool retained = false, sample_held = false, held_at_response = false, new_started = false;
    bool ack = false, done = false, unexpected_stop = false;
    bool control_held = false;
    uint64_t ticket_seen_at = 0;
    unsigned updates_at_ticket = 0;
    bool replacement = which == SUCCESS || which == DUPLICATE_SUCCESS;
    uint64_t second_request_at = 0, prompt_at = 0, deadline = sl_system_now() + 10000;
    struct sockaddr_in client = {0};
    while (!done && sl_system_now() < deadline) {
        a.ui.now = sl_system_now();
        runtime_events(&a);
        lifecycle_facts(&a);
        if (preinit && !initial_pin && atomic_load(&backends)) {
            assert(!atomic_load(&creates));
            ticket(fd, &client, initial_id, k_ERemoteDeviceStreamingPINRequired, &store, false);
            initial_pin = initial_started = true;
        }
        if (completed && !initial_pin && a.ui.page == SL_NETWORK_RESULT) {
            assert(initial_started && atomic_load(&creates) == 1 && atomic_load(&joins) == 1 &&
                   !atomic_load(&destroys));
            ticket(fd, &client, initial_id, k_ERemoteDeviceStreamingPINRequired, &store, false);
            initial_pin = true;
        }
        if (a.ui.page == SL_PIN && initial_pin && !retry_submitted) {
            assert(atomic_load(&creates) == (preinit ? 0 : 1) &&
                   atomic_load(&joins) == (unsigned)completed && !atomic_load(&destroys));
            strcpy(a.ui.input, "9876");
            sl_ui_action(&a.ui, SL_SUBMIT, 0);
            assert(sl_ui_take_command(&a.ui, &cmd) && cmd.type == SL_CMD_STREAM &&
                   cmd.security_pin_retry);
            assert(command(&a, &cmd));
            retry_submitted = true;
        }
        uint64_t now = sl_system_now();
        if (atomic_load(&ticket_seen) && !ticket_seen_at) {
            ticket_seen_at = now;
            updates_at_ticket = atomic_load(&manager_updates);
        }
        if (ticket_seen_at && !atomic_load(&joins) && now - ticket_seen_at >= 80)
            control_held |= atomic_load(&manager_updates) == updates_at_ticket;
        if (second_request_at && !responded && now - second_request_at >= 150) {
            retained =
                atomic_load(&creates) == (preinit ? 0 : 1) &&
                atomic_load(&joins) == (unsigned)completed && !atomic_load(&destroys) &&
                (!preinit || (atomic_load(&backends) == 1 && !atomic_load(&backend_destroys)));
            sample_held = atomic_load(&samples) == sample_wait;
            responded = true;
            if (which != CANCEL_WAIT) {
                unsigned result = replacement || which == FAILURE_AFTER_TICKET
                                      ? k_ERemoteDeviceStreamingSuccess
                                  : which == FAILURE      ? k_ERemoteDeviceStreamingFailed
                                  : which == PIN_AGAIN    ? k_ERemoteDeviceStreamingPINRequired
                                  : which == UNAUTHORIZED ? k_ERemoteDeviceStreamingUnauthorized
                                                          : k_ERemoteDeviceStreamingBusy;
                ticket(fd, &client, retry_id, result, &store, true);
                if (which == DUPLICATE_SUCCESS)
                    ticket(fd, &client, retry_id, result, &store, true);
                if (which == FAILURE_AFTER_TICKET)
                    ticket(fd, &client, retry_id, k_ERemoteDeviceStreamingFailed, &store, true);
            }
        }
        /* Deliver the new UDP key first, then finish the old SDK BInit. This
         * exposes using new session_info for the still-pending old backend. */
        if (preinit && responded && now - second_request_at >= (startup_failure ? 450 : 180))
            atomic_store(&allow_old_init, true);
        sl_network_test_view view = {0};
        sl_runtime_network_test(a.runtime, &view);
        bool prompt =
            responded && !ack &&
            (which == CANCEL_WAIT || which == BUSY ? now - second_request_at >= 200
             : replacement                         ? cancel_join ? control_held : new_started
             : which == PIN_AGAIN                  ? a.ui.page == SL_PIN
             : which == UNAUTHORIZED ? a.ui.page == SL_PAIRING && strlen(a.ui.pairing_code) == 4
                                     : a.ui.page == SL_ERROR && a.ui.cancel_only_error);
        if (prompt && (!preinit || atomic_load(&creates))) {
            if (!prompt_at) {
                prompt_at = now;
                held_at_response =
                    replacement && !cancel_join
                        ? atomic_load(&creates) == (startup_failure == 1 ? 1 : 2) &&
                              atomic_load(&joins) == (startup_failure == 1 ? 0 : 1) &&
                              atomic_load(&destroys) == (startup_failure == 1 ? 0 : 1)
                        : atomic_load(&creates) == 1 &&
                              atomic_load(&joins) == (unsigned)completed && !atomic_load(&destroys);
            }
            if (now - prompt_at >= 50) {
                cancels_before_ack = streaming_cancels;
                sl_ui_action(
                    &a.ui, which == FAILURE || which == FAILURE_AFTER_TICKET ? SL_ACCEPT : SL_BACK,
                    0);
                assert(sl_ui_take_command(&a.ui, &cmd) && cmd.type == SL_CMD_CANCEL);
                assert(command(&a, &cmd));
                ack = true;
            }
        }
        if (retry_submitted && second_request_at && a.lifecycle.phase == SL_APP_IDLE && !ack) {
            unexpected_stop = true;
            done = true;
        }
        if (ack && a.lifecycle.phase == SL_APP_IDLE && streaming_cancels + auth_cancels == 2 &&
            a.ui.page == (manual ? SL_NETWORK_SETTINGS : SL_HOME))
            done = true;
        struct pollfd p = {.fd = fd, .events = POLLIN};
        assert(poll(&p, 1, 2) >= 0);
        if (!(p.revents & POLLIN))
            continue;
        uint8_t wire[4096];
        struct sockaddr_in from;
        length = sizeof(from);
        ssize_t n = recvfrom(fd, wire, sizeof(wire), 0, (void *)&from, &length);
        assert(n >= 13);
        if (n > 16 && !memcmp(wire, test_discovery_magic, 8)) {
            unsigned hs = test_discovery_u32(wire + 8), size = test_discovery_u32(wire + 12 + hs);
            assert(hs + 16u + size == (size_t)n);
            CMsgRemoteClientBroadcastHeader *h =
                cmsg_remote_client_broadcast_header__unpack(NULL, hs, wire + 12);
            assert(h);
            unsigned tag = h->msg_type;
            cmsg_remote_client_broadcast_header__free_unpacked(h, NULL);
            const uint8_t *body = wire + 16 + hs;
            if (tag == k_ERemoteDeviceStreamingRequest) {
                CMsgRemoteDeviceStreamingRequest *r =
                    cmsg_remote_device_streaming_request__unpack(NULL, size, body);
                assert(r && r->has_network_test && r->network_test);
                if (r->request_id == initial_id || r->request_id == retry_id) {
                    cmsg_remote_device_streaming_request__free_unpacked(r, NULL);
                    continue; /* Waiting requests may retransmit the same id. */
                }
                ++requests;
                assert(requests <= 2);
                client = from;
                if (requests == 1) {
                    initial_id = r->request_id;
                    assert(!r->has_pin || !r->pin.len);
                    ticket(fd, &client, initial_id, k_ERemoteDeviceStreamingSuccess, &store, false);
                } else {
                    retry_id = r->request_id;
                    assert(retry_submitted && retry_id != initial_id && r->has_pin);
                    uint8_t pin[64];
                    size_t count = sizeof(pin);
                    assert(!IHS_CryptoSymmetricDecrypt(r->pin.data, r->pin.len, store.secret, 32,
                                                       pin, &count));
                    assert(count == 4 && !memcmp(pin, "9876", 4));
                    second_request_at = sl_system_now();
                    sample_wait = atomic_load(&samples);
                    atomic_store(&new_request_seen, true);
                }
                cmsg_remote_device_streaming_request__free_unpacked(r, NULL);
            } else if (tag == k_ERemoteDeviceStreamingCancelRequest) {
                CMsgRemoteDeviceStreamingCancelRequest *r =
                    cmsg_remote_device_streaming_cancel_request__unpack(NULL, size, body);
                assert(r && r->request_id == (streaming_cancels ? retry_id : initial_id));
                ++streaming_cancels;
                assert(streaming_cancels <= 2);
                cmsg_remote_device_streaming_cancel_request__free_unpacked(r, NULL);
            } else if (tag == k_ERemoteDeviceAuthorizationCancelRequest) {
                assert(which == UNAUTHORIZED && ack && !auth_cancels);
                ++auth_cancels;
            }
            continue;
        }
        unsigned type = wire[0] & 127;
        if (type == 1)
            control(fd, &from, wire[2], 2, 0, wire + 9, 4);
        else if (type == 5 && wire[4] == 1) {
            if (wire[13] == 6) {
                const uint8_t reply[] = {7, 10, 3, 8, 0xc0, 0x0b};
                control(fd, &from, wire[2], 5, 0, reply, sizeof(reply));
            } else if (wire[13] == 1) {
                const uint8_t reply[] = {2, 16, 1};
                control(fd, &from, wire[2], 5, 1, reply, sizeof(reply));
            } else if (wire[13] == 8) {
                if (!initial_started) {
                    initial_started = true;
                    if (!completed) {
                        ticket(fd, &client, initial_id, k_ERemoteDeviceStreamingPINRequired, &store,
                               false);
                        initial_pin = true;
                    }
                } else if (replacement && responded &&
                           atomic_load(&creates) == (startup_failure == 1 ? 1 : 2))
                    new_started = true;
            }
        }
    }
    assert(done && requests == 2 && retry_submitted && initial_started);
    sl_runtime_destroy(a.runtime);
    close(fd);
    if (completed) {
        char path[128];
        snprintf(path, sizeof(path), "%s/streaming_stats.bin", directory);
        assert(access(path, F_OK) && errno == ENOENT); /* Unaccepted old result is not saved. */
    }
    sl_fixture_remove_tree(directory);
    assert(atomic_load(&creates) == atomic_load(&joins) &&
           atomic_load(&joins) == atomic_load(&destroys));
    assert(atomic_load(&backends) == atomic_load(&backend_destroys));
    printf("{\"scenario\":\"%s\",\"manual\":%s,\"retained\":%s,\"sample_held\":%s,"
           "\"held_at_response\":%s,\"unexpected_stop\":%s,\"requests\":%u,\"sessions\":%u,"
           "\"joins\":%u,\"before_ack\":%u,\"cancel10\":%u,\"cancel9\":%u,"
           "\"preinit\":%s,\"early_disconnects\":%u,\"backends\":%u,"
           "\"control_held\":%s,\"completed\":%s,\"clean\":true}\n",
           cancel_join            ? "cancel_join"
           : startup_failure == 1 ? "sdk_fail"
           : startup_failure == 2 ? "sdk_session_fail"
                                  : names[which],
           manual ? "true" : "false", retained ? "true" : "false", sample_held ? "true" : "false",
           held_at_response ? "true" : "false", unexpected_stop ? "true" : "false", requests,
           atomic_load(&creates), atomic_load(&joins), cancels_before_ack, streaming_cancels,
           auth_cancels, preinit ? "true" : "false", early_disconnects, atomic_load(&backends),
           control_held ? "true" : "false", completed ? "true" : "false");
    fflush(stdout);
}
int main(int argc, char **argv) {
    assert(argc == 1 || argc == 2);
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    preinit = argc == 2 && !strncmp(argv[1], "--sdk", 5);
    startup_failure = argc == 2 && !strcmp(argv[1], "--sdk-fail")           ? 1
                      : argc == 2 && !strcmp(argv[1], "--sdk-session-fail") ? 2
                                                                            : 0;
    cancel_join = argc == 2 && !strcmp(argv[1], "--cancel-join");
    completed = argc == 2 && !strcmp(argv[1], "--completed");
#if !NSL_HAVE_SNS
    assert(!preinit);
#endif
    unsigned begin = cancel_join || startup_failure        ? SUCCESS
                     : argc == 2 && !preinit && !completed ? (unsigned)atoi(argv[1])
                                                           : 0;
    assert(begin < 8);
    for (unsigned mode = begin;
         mode < (argc == 2 && ((!preinit && !completed) || startup_failure) ? begin + 1 : 8);
         ++mode)
        for (unsigned manual = 0; manual < 2; ++manual)
            one((enum scenario)mode, manual);
    stream_media_shutdown();
    return 0;
}
