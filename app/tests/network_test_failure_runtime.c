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
static void one(bool manual, bool press_a) {
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
         progress = false, done = false;
    unsigned id = 0, cancels = 0;
    uint64_t prompt_at = 0, deadline = sl_system_now() + 8000;
    struct sockaddr_in client_address = {0};
    while (!done && sl_system_now() < deadline) {
        a.ui.now = sl_system_now();
        runtime_events(&a);
        lifecycle_facts(&a);
        sl_network_test_view view;
        if (sl_runtime_network_test(a.runtime, &view) && view.phase == SL_TEST_FAILED && !ack) {
            sl_runtime_facts facts;
            assert(sl_runtime_read_facts(a.runtime, &facts));
            assert(facts.failed && facts.test_failure_pending &&
                   a.lifecycle.phase == SL_APP_STARTING);
            assert(a.ui.page == SL_ERROR && a.ui.cancel_only_error);
            char expected[16];
            snprintf(expected, sizeof(expected), "%u", peer_port);
            assert(strstr(a.ui.error, expected));
            if (!prompt) {
                prompt = true;
                prompt_at = sl_system_now();
            }
            if (!progress && sl_system_now() - prompt_at >= 30) {
                CMsgRemoteDeviceStreamingResponse p = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
                p.request_id = id;
                p.result = k_ERemoteDeviceStreamingInProgress;
                uint8_t body[64];
                size_t size = cmsg_remote_device_streaming_response__pack(&p, body);
                test_discovery_send(fd, &client_address, body, size);
                progress = true;
            }
            if (sl_system_now() - prompt_at >= 120) {
                assert(!cancels && progress);
                sl_ui_action(&a.ui, SL_RETRY, 0);
                assert(!sl_ui_take_command(&a.ui, &cmd));
                sl_ui_action(&a.ui, press_a ? SL_ACCEPT : SL_BACK, 0);
                assert(sl_ui_take_command(&a.ui, &cmd) && cmd.type == SL_CMD_CANCEL);
                ack = true;
                assert(command(&a, &cmd));
            }
        }
        if (ack && cancels == 1 && a.lifecycle.phase == SL_APP_IDLE &&
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
                test_discovery_send(fd, &from, body, size);
            } else if (tag == k_ERemoteDeviceStreamingCancelRequest) {
                assert(ack);
                CMsgRemoteDeviceStreamingCancelRequest *r =
                    cmsg_remote_device_streaming_cancel_request__unpack(NULL, size, wire + 16 + hs);
                assert(r && r->request_id == id);
                cmsg_remote_device_streaming_cancel_request__free_unpacked(r, NULL);
                ++cancels;
                assert(cancels == 1);
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
                const uint8_t denied[] = {2, 8, 1, 16, 1};
                control(fd, &from, wire[2], 5, 1, denied, sizeof(denied));
                refused = true;
            } else
                assert(wire[13] != 8); /* Auth refusal must not reach the test producer. */
        }
    }
    assert(done && requested && refused && prompt && ack && cancels == 1);
    char stats[512];
    snprintf(stats, sizeof(stats), "%s/streaming_stats.bin", directory);
    assert(access(stats, F_OK) != 0);
    sl_runtime_destroy(a.runtime);
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
    printf("failure manual=%d acknowledge=%s: real application held ID through prompt/matching "
           "InProgress, one matching cancel10 after ack, no save/retry/ordinary ticket, joined "
           "cleanup passed\n",
           manual, press_a ? "A" : "B");
}
int main(void) {
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    for (unsigned manual = 0; manual < 2; ++manual)
        for (unsigned a = 0; a < 2; ++a)
            one(manual, a);
    stream_media_shutdown();
    return 0;
}
