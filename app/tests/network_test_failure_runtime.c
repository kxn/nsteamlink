#include "fixture_cleanup.h"
/* Production application admission/facts/event consumer + runtime + actual
 * client/session UDP. Endpoint, authorized identity and peer responses are
 * controlled fixtures; no real Steam, Qt or Switch is exercised. */
#include "../platforms/common/application.c"
#include "crypto.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "network_test_discovery_peer.h"
#include "protobuf/remoteplay.pb-c.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <ihslib/client.h>
#include <poll.h>
#include <unistd.h>
static uint16_t peer_port;
static atomic_bool service_error_pending;
static atomic_uint session_joins, session_destroys, result_polls;
void __real_IHS_SessionThreadedJoin(IHS_Session *);
void __wrap_IHS_SessionThreadedJoin(IHS_Session *s) {
    __real_IHS_SessionThreadedJoin(s);
    atomic_fetch_add(&session_joins, 1);
}
void __real_IHS_SessionDestroy(IHS_Session *);
void __wrap_IHS_SessionDestroy(IHS_Session *s) {
    __real_IHS_SessionDestroy(s);
    atomic_fetch_add(&session_destroys, 1);
}
void __real_IHS_SessionGetNetworkTestResult(IHS_Session *, IHS_NetworkTestResult *);
void __wrap_IHS_SessionGetNetworkTestResult(IHS_Session *s, IHS_NetworkTestResult *out) {
    atomic_fetch_add(&result_polls, 1);
    __real_IHS_SessionGetNetworkTestResult(s, out);
}
typedef struct control_update_provider {
    IHS_Client *client;
    void (*session)(void *), (*expire)(void *);
    void *ctx;
} control_update_provider;
static void control_session(void *ctx) {
    control_update_provider *p = ctx;
    if (p->session)
        p->session(p->ctx);
    if (atomic_exchange(&service_error_pending, false))
        assert(IHS_ClientHandshakeFail(p->client, IHS_AuthorizationFailed));
}
static void control_expiry(void *ctx) {
    control_update_provider *p = ctx;
    if (p->expire)
        p->expire(p->ctx);
}
bool __real_IHS_ClientUpdate(IHS_Client *, void (*)(void *), void (*)(void *), void *);
bool __wrap_IHS_ClientUpdate(IHS_Client *c, void (*session)(void *), void (*expire)(void *),
                             void *ctx) {
    control_update_provider p = {c, session, expire, ctx};
    return __real_IHS_ClientUpdate(c, control_session, control_expiry, &p);
}
void __real_IHS_ClientSetDiscoveryCallbacks(IHS_Client *, const IHS_ClientDiscoveryCallbacks *,
                                            void *);
void __wrap_IHS_ClientSetDiscoveryCallbacks(IHS_Client *c,
                                            const IHS_ClientDiscoveryCallbacks *callbacks,
                                            void *context) {
    __real_IHS_ClientSetDiscoveryCallbacks(c, callbacks, context);
    test_discovery_observed(c, callbacks, context, peer_port);
}
/* Main/test thread only: make the documented try-lock miss deterministic. */
static bool inject_facts_busy;
static unsigned facts_busy_calls;
bool __real_sl_runtime_read_facts(sl_runtime *, sl_runtime_facts *);
bool __wrap_sl_runtime_read_facts(sl_runtime *r, sl_runtime_facts *facts) {
    if (inject_facts_busy) {
        inject_facts_busy = false;
        ++facts_busy_calls;
        return false;
    }
    return __real_sl_runtime_read_facts(r, facts);
}
bool __real_IHS_ClientStreamingRequest(IHS_Client *, const IHS_HostInfo *,
                                       const IHS_StreamingRequest *);
bool __wrap_IHS_ClientStreamingRequest(IHS_Client *c, const IHS_HostInfo *h,
                                       const IHS_StreamingRequest *req) {
    IHS_HostInfo redirected = *h;
    redirected.address.port = peer_port;
    return __real_IHS_ClientStreamingRequest(c, &redirected, req);
}
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
static void one(bool manual, bool press_a, unsigned mode) {
    /* 0 auth refusal; 1 late UDP failure; 2 owner-delivered service failure;
     * 3 connect PIN; 4 Unauthorized; 5 Busy; 6 duplicate Success. */
    atomic_store(&session_joins, 0);
    atomic_store(&session_destroys, 0);
    atomic_store(&result_polls, 0);
    atomic_store(&service_error_pending, false);
    char directory[] = "/tmp/nsl-test-failure-XXXXXX";
    assert(mkdtemp(directory));
    assert(!setenv("NSL_DATA_DIR", directory, 1));
    sl_auth_store store = {.device_id = 1, .sound = true, .bitrate_kbps = 6000};
    strcpy(store.device_name, "Failure fixture");
    for (unsigned i = 0; i < 32; ++i)
        store.secret[i] = 32 + i;
    sl_host_registry_init(&store.registry);
    sl_host host = {.client_id = 123, .instance_id = 1, .paired = true, .account = 123456};
    strcpy(host.name, "Controlled peer");
    strcpy(host.address, "127.0.0.1");
    sl_host *saved = sl_host_observe(&store.registry, &host, sl_system_now());
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
    }
    sl_ui_action(&a.ui, manual ? SL_RUN_NETWORK_TEST : SL_START, 0);
    sl_command cmd;
    assert(sl_ui_take_command(&a.ui, &cmd) && cmd.type == SL_CMD_STREAM && cmd.test_only == manual);
    assert(command(&a, &cmd));
    bool requested = false, handshake = false, refused = false, prompt = false, ack = false,
         progress = false, done = false, test_started = false, late_sent = false;
    bool busy_injected = false;
    facts_busy_calls = 0;
    unsigned id = 0, cancels = 0;
    unsigned auth_cancels = 0, prompt_polls = 0, cancels_before_ack = 0;
    uint64_t late_sent_at = 0;
    bool fatal = mode <= 2;
    uint8_t good_reply[256];
    size_t good_reply_size = 0;
    uint64_t prompt_at = 0, deadline = sl_system_now() + 8000;
    struct sockaddr_in client_address = {0};
    while (!done && sl_system_now() < deadline) {
        a.ui.now = sl_system_now();
        runtime_events(&a);
        lifecycle_facts(&a);
        sl_network_test_view view;
        bool failed_view =
            sl_runtime_network_test(a.runtime, &view) && view.phase == SL_TEST_FAILED && !ack;
        if (failed_view && !busy_injected) {
            inject_facts_busy = true;
            busy_injected = true;
        }
        sl_runtime_facts facts;
        bool ready_prompt =
            fatal ? failed_view
                  : test_started && late_sent && !ack && sl_system_now() - late_sent_at >= 200;
        if ((mode == 1 || mode == 2) && late_sent && !ack &&
            sl_runtime_read_facts(a.runtime, &facts) && facts.failed)
            assert(facts.test_failure_pending); /* Old generic failure auto-stopped here. */
        if (ready_prompt && sl_runtime_read_facts(a.runtime, &facts)) {
            if (!fatal) {
                assert(!facts.failed && !facts.test_failure_pending &&
                       a.lifecycle.phase == SL_APP_STARTING);
                assert(a.ui.page == (mode == 3 ? SL_PIN : SL_NETWORK_TEST));
            } else {
                assert(facts.failed && facts.test_failure_pending &&
                       a.lifecycle.phase == SL_APP_STARTING);
                assert(a.ui.page == SL_ERROR && a.ui.cancel_only_error);
                if (!mode) {
                    char expected[16];
                    snprintf(expected, sizeof(expected), "%u", peer_port);
                    assert(strstr(a.ui.error, expected));
                }
            }
            if (!prompt) {
                prompt = true;
                prompt_at = sl_system_now();
                prompt_polls = atomic_load(&result_polls);
            }
            if (!mode && !progress && sl_system_now() - prompt_at >= 30) {
                CMsgRemoteDeviceStreamingResponse p = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
                p.request_id = id;
                p.result = k_ERemoteDeviceStreamingInProgress;
                uint8_t body[64];
                size_t size = cmsg_remote_device_streaming_response__pack(&p, body);
                test_discovery_send(fd, &client_address, body, size);
                progress = true;
            }
            if (sl_system_now() - prompt_at >= 120) {
                assert(cancels == (mode >= 1 && mode <= 3 ? 1u : 0u));
                assert(mode || progress);
                if (fatal || mode == 3)
                    assert(atomic_load(&result_polls) == prompt_polls);
                else
                    assert(atomic_load(&result_polls) > prompt_polls);
                if (fatal) {
                    sl_ui_action(&a.ui, SL_RETRY, 0);
                    assert(!sl_ui_take_command(&a.ui, &cmd));
                }
                assert(atomic_load(&session_destroys) == (!mode ? 1u : 0u));
                cancels_before_ack = cancels;
                sl_ui_action(&a.ui, fatal && press_a ? SL_ACCEPT : SL_BACK, 0);
                assert(sl_ui_take_command(&a.ui, &cmd) && cmd.type == SL_CMD_CANCEL);
                ack = true;
                assert(command(&a, &cmd));
            }
        }
        if (ack && cancels + auth_cancels == 1 && a.lifecycle.phase == SL_APP_IDLE &&
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
            if (tag == k_ERemoteDeviceStreamingRequest) {
                assert(!requested);
                requested = true;
                client_address = from;
                CMsgRemoteDeviceStreamingRequest *r =
                    cmsg_remote_device_streaming_request__unpack(NULL, size, wire + 16 + hs);
                assert(r && r->has_network_test && r->network_test);
                id = r->request_id;
                cmsg_remote_device_streaming_request__free_unpacked(r, NULL);
                CMsgRemoteDeviceStreamingResponse reply =
                    CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
                reply.request_id = id;
                reply.result = k_ERemoteDeviceStreamingSuccess;
                reply.has_port = reply.has_encrypted_session_key = true;
                reply.port = peer_port;
                uint8_t key[32], cipher[128], body[256];
                for (unsigned i = 0; i < 32; ++i)
                    key[i] = i;
                size_t capacity = sizeof(cipher);
                assert(!IHS_CryptoSymmetricEncrypt(key, 32, store.secret, 32, cipher, &capacity));
                reply.encrypted_session_key = (ProtobufCBinaryData){capacity, cipher};
                size = cmsg_remote_device_streaming_response__pack(&reply, body);
                memcpy(good_reply, body, size);
                good_reply_size = size;
                test_discovery_send(fd, &from, body, size);
            } else if (tag == k_ERemoteDeviceStreamingCancelRequest) {
                assert(ack || (late_sent && mode >= 1 && mode <= 3));
                CMsgRemoteDeviceStreamingCancelRequest *r =
                    cmsg_remote_device_streaming_cancel_request__unpack(NULL, size, wire + 16 + hs);
                assert(r && r->request_id == id);
                cmsg_remote_device_streaming_cancel_request__free_unpacked(r, NULL);
                ++cancels;
                assert(cancels == 1);
            } else if (tag == k_ERemoteDeviceAuthorizationCancelRequest) {
                assert(mode == 4 && ack && !auth_cancels);
                ++auth_cancels;
            }
            continue;
        }
        unsigned type = wire[0] & 127;
        if (type == 1)
            control(fd, &from, wire[2], 2, 0, wire + 9, 4);
        else if (type == 5 && wire[4] == 1) {
            if (wire[13] == 6 && !handshake) {
                const uint8_t reply[] = {7, 10, 3, 8, 0xc0, 0x0b};
                control(fd, &from, wire[2], 5, 0, reply, sizeof(reply));
                handshake = true;
            } else if (wire[13] == 1 && !refused) {
                if (!mode) {
                    const uint8_t denied[] = {2, 8, 1, 16, 1};
                    control(fd, &from, wire[2], 5, 1, denied, sizeof(denied));
                } else {
                    const uint8_t accepted[] = {2, 16, 1};
                    control(fd, &from, wire[2], 5, 1, accepted, sizeof(accepted));
                }
                refused = true;
            } else if (mode && wire[13] == 8 && !test_started) {
                test_started = true;
                late_sent = true;
                late_sent_at = sl_system_now();
                if (mode == 2)
                    atomic_store(&service_error_pending, true);
                else if (mode == 6)
                    test_discovery_send(fd, &client_address, good_reply, good_reply_size);
                else {
                    CMsgRemoteDeviceStreamingResponse p =
                        CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
                    p.request_id = id;
                    p.result = mode == 1   ? k_ERemoteDeviceStreamingFailed
                               : mode == 3 ? k_ERemoteDeviceStreamingPINRequired
                               : mode == 4 ? k_ERemoteDeviceStreamingUnauthorized
                                           : k_ERemoteDeviceStreamingBusy;
                    uint8_t body[64];
                    size_t n = cmsg_remote_device_streaming_response__pack(&p, body);
                    test_discovery_send(fd, &client_address, body, n);
                }
            } else if (!mode)
                assert(wire[13] != 8); /* Auth refusal must not reach the test producer. */
        }
    }
    assert(done && requested && refused && prompt && ack && cancels + auth_cancels == 1 &&
           (!fatal || (busy_injected && facts_busy_calls == 1 && !inject_facts_busy)));
    char stats[512];
    snprintf(stats, sizeof(stats), "%s/streaming_stats.bin", directory);
    assert(access(stats, F_OK) != 0);
    sl_runtime_destroy(a.runtime);
    assert(atomic_load(&session_joins) == 1 && atomic_load(&session_destroys) == 1);
    close(fd);
    sl_fixture_remove_tree(directory);
    if (mode)
        printf("{\"mode\":%u,\"manual\":%s,\"before_ack\":%u,\"cancel10\":%u,\"cancel9\":%u,"
               "\"clean\":true}\n",
               mode, manual ? "true" : "false", cancels_before_ack, cancels, auth_cancels);
    else
        printf("failure manual=%d acknowledge=%s: real application held ID through prompt/matching "
               "InProgress, one matching cancel10 after ack, no save/retry/ordinary ticket, joined "
               "cleanup and one injected facts-busy retry passed\n",
               manual, press_a ? "A" : "B");
}
int main(int argc, char **argv) {
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    unsigned mode = argc == 2 ? (unsigned)atoi(argv[1]) : 0;
    assert(argc <= 2 && mode <= 6);
    for (unsigned manual = 0; manual < 2; ++manual)
        for (unsigned a = 0; a < 2; ++a)
            one(manual, a, mode);
    stream_media_shutdown();
    return 0;
}
