/* Production runtime + real discovery/session UDP. Only the discovery endpoint
 * is redirected to an ephemeral loopback peer. Identity, replies, media and
 * timing are controlled fixtures, not a real Steam or Switch observation. */
#include "crc32c.h"
#include "crypto.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "media.h"
#include "network_stats_file.h"
#include "network_test_discovery_peer.h"
#include "platform/runtime.h"
#include "platform/system.h"
#include "protobuf/remoteplay.pb-c.h"
#include "session/session_pri.h"
#include "stream_settings.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <ihslib/client.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint16_t peer_port;
static sl_runtime *runtime;
static sl_auth_store store;
static bool cancel_on_save, fail_save;
static unsigned saves;
bool __real_IHS_ClientStreamingRequest(IHS_Client *, const IHS_HostInfo *,
                                       const IHS_StreamingRequest *);
bool __wrap_IHS_ClientStreamingRequest(IHS_Client *c, const IHS_HostInfo *h,
                                       const IHS_StreamingRequest *req) {
    IHS_HostInfo redirected = *h;
    redirected.address.port = peer_port;
    return __real_IHS_ClientStreamingRequest(c, &redirected, req);
}
bool __real_sl_network_stats_save_session(const char *, IHS_Session *);
bool __wrap_sl_network_stats_save_session(const char *dir, IHS_Session *s) {
    ++saves;
    bool ok = !fail_save && __real_sl_network_stats_save_session(dir, s);
    if (cancel_on_save) {
        sl_command cancel = {.type = SL_CMD_CANCEL, .generation = 2};
        assert(sl_runtime_submit(runtime, &cancel, &store));
    }
    return ok;
}
static void send_peer(int fd, const struct sockaddr_in *to, unsigned local, unsigned type,
                      unsigned ch, unsigned id, const uint8_t *body, size_t count, bool crc) {
    uint8_t wire[4096] = {type, 0, 7, local, ch};
    assert(count + 17 < sizeof(wire));
    wire[7] = id;
    wire[8] = id >> 8;
    uint32_t stamp = 1000000;
    memcpy(wire + 9, &stamp, 4);
    if (count)
        memcpy(wire + 13, body, count);
    count += 13;
    if (crc) {
        wire[0] |= 128;
        uint32_t sum = IHS_CRC32C(wire, count);
        memcpy(wire + count, &sum, 4);
        count += 4;
    }
    assert(sendto(fd, wire, count, 0, (const void *)to, sizeof(*to)) == (ssize_t)count);
}
static void encrypted(IHS_Session *codec, int fd, const struct sockaddr_in *to, unsigned local,
                      unsigned id, unsigned tag, const uint8_t *plain, size_t count, unsigned seq,
                      bool crc) {
    uint8_t body[4096] = {tag};
    size_t size = sizeof(body) - 1;
    assert(!IHS_SessionFrameEncrypt(codec, plain, count, body + 1, &size, seq));
    send_peer(fd, to, local, 5, 1, id, body, size + 1, crc);
}
static void target(IHS_Session *codec, int fd, const struct sockaddr_in *to, unsigned local,
                   unsigned id, unsigned kbps, unsigned seq, bool crc) {
    uint8_t body[8] = {8};
    size_t n = 1;
    do {
        body[n++] = (kbps & 127) | (kbps > 127 ? 128 : 0);
        kbps >>= 7;
    } while (kbps);
    encrypted(codec, fd, to, local, id, 94, body, n, seq, crc);
}
typedef enum Scenario {
    FIXED,
    FAST_ACCEPT,
    FAST_REJECT,
    ENHANCED_MANUAL,
    SAVE_FAILURE,
    CANCEL_RUNNING,
    EXIT_RESULT,
    CANCEL_SAVE,
    SKIP_READABLE,
    VIDEO_DISABLED
} Scenario;
static void one(Scenario scenario, bool crc) {
    char directory[] = "/tmp/nsl-test-runtime-XXXXXX";
    assert(mkdtemp(directory) && !setenv("NSL_DATA_DIR", directory, 1));
    memset(&store, 0, sizeof(store));
    store.device_id = 1;
    store.sound = true;
    store.bitrate_kbps = scenario == FIXED || scenario == SAVE_FAILURE || scenario == CANCEL_SAVE
                             ? 6000
                             : UINT32_MAX;
    strcpy(store.device_name, "Switch runtime fixture");
    for (unsigned i = 0; i < 32; ++i)
        store.secret[i] = 32 + i;
    sl_host_registry_init(&store.registry);
    sl_host host = {.client_id = 123, .instance_id = 1, .paired = true, .account = 123456};
    strcpy(host.address, "127.0.0.1");
    strcpy(host.name, "Controlled UDP peer");
    host = *sl_host_observe(&store.registry, &host, sl_system_now());
    bool skip_test = scenario == SKIP_READABLE || scenario == VIDEO_DISABLED;
    if (scenario == SKIP_READABLE || scenario == ENHANCED_MANUAL || scenario == VIDEO_DISABLED) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", directory,
                 scenario == VIDEO_DISABLED ? "streaming_settings.bin" : "streaming_stats.bin");
        FILE *f = fopen(path, "wb");
        assert(f);
        if (scenario == VIDEO_DISABLED) {
            const uint8_t disabled[] = {0x48, 0}; /* Full config field9: video=false. */
            assert(fwrite(disabled, 1, sizeof(disabled), f) == sizeof(disabled));
        }
        assert(!fclose(f));
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(fd, (void *)&addr, sizeof(addr)));
    socklen_t len = sizeof(addr);
    assert(!getsockname(fd, (void *)&addr, &len));
    peer_port = ntohs(addr.sin_port);
    cancel_on_save = scenario == CANCEL_SAVE;
    fail_save = scenario == SAVE_FAILURE;
    saves = 0;
    runtime = sl_runtime_create(&store);
    assert(runtime);
    uint64_t deadline = sl_system_now() + 15000;
    sl_stream_preferences prefs;
    uint64_t revision;
    while (!sl_runtime_stream_settings(runtime, &prefs, &revision)) {
        assert(sl_system_now() < deadline);
        poll(NULL, 0, 1);
    }
    IHS_ClientConfig cc = {.deviceId = 1, .secretKey = store.secret, .deviceName = "codec fixture"};
    IHS_SessionInfo info = {.sessionKeyLen = 32};
    for (unsigned i = 0; i < 32; ++i)
        info.sessionKey[i] = i;
    IHS_Session *codec = IHS_SessionCreate(&cc, &info);
    assert(codec);
    IHS_TimerTaskStopImmediate(codec->retransmission.timer);
    bool manual = scenario == ENHANCED_MANUAL;
    bool bandwidth = store.bitrate_kbps == UINT32_MAX;
    bool expected_fec = scenario == FAST_ACCEPT || manual;
    sl_command cmd = {
        .type = SL_CMD_STREAM, .generation = 1, .host = host, .test_only = manual, .game_id = 570};
    assert(sl_runtime_submit(runtime, &cmd, &store));
    unsigned ticket_count = 0, sequence = 0, keepalives = 0;
    bool ordinary = false, handshake = false, auth = false, start = false;
    bool decision = false, done = false, config_seen = false, complete = false;
    struct sockaddr_in from = {0};
    unsigned local = 0;
    uint64_t settle = 0;
    while (!done && sl_system_now() < deadline) {
        sl_network_test_view view;
        if (sl_runtime_network_test(runtime, &view)) {
            if (!decision && scenario == CANCEL_RUNNING && start) {
                cmd = (sl_command){.type = SL_CMD_CANCEL, .generation = 2};
                assert(sl_runtime_submit(runtime, &cmd, &store));
                decision = true;
            } else if (!decision && view.phase == SL_TEST_RESULT) {
                assert(view.generation == 1 && view.test_only == manual &&
                       view.bandwidth_test == bandwidth);
                assert(view.recommendation == (bandwidth ? (manual ? 2u : 1u) : 0u));
                assert(!bandwidth || view.previous_target_kbps == (manual ? 100000u : 99999u));
                if (scenario == EXIT_RESULT) {
                    /* This fixture's independent codec also belongs before
                     * runtime shutdown/IHS_Quit, even though it has no workers. */
                    IHS_SessionDestroy(codec);
                    codec = NULL;
                    sl_runtime_request_exit(runtime);
                } else {
                    cmd = (sl_command){.type = SL_CMD_TEST_CONFIRM,
                                       .generation = 1,
                                       .accept_recommendation = scenario != FAST_REJECT};
                    assert(sl_runtime_submit(runtime, &cmd, &store));
                }
                decision = true;
            }
        }
        sl_runtime_event event;
        while (sl_runtime_poll(runtime, &event)) {
            if (event.type == SL_EVENT_FAILURE) {
                fprintf(stderr, "scenario=%d runtime failure: %s\n", scenario, event.text);
                assert(false);
            }
            if (event.type == SL_EVENT_STOPPED && decision) {
                assert(manual || scenario == CANCEL_RUNNING || scenario == CANCEL_SAVE);
                settle = sl_system_now() + 100;
            }
        }
        if (scenario == EXIT_RESULT && sl_runtime_finished(runtime))
            done = true;
        if (settle && sl_system_now() >= settle)
            done = true;
        if (complete) {
            sl_runtime_facts facts;
            if (sl_runtime_read_facts(runtime, &facts) && facts.connected)
                done = true;
        }
        struct pollfd p = {.fd = fd, .events = POLLIN};
        assert(poll(&p, 1, 2) >= 0);
        if (!(p.revents & POLLIN))
            continue;
        uint8_t wire[8192];
        len = sizeof(from);
        ssize_t count = recvfrom(fd, wire, sizeof(wire), 0, (void *)&from, &len);
        assert(count > 0);
        if (count > 16 && !memcmp(wire, test_discovery_magic, 8)) {
            uint32_t hs = test_discovery_u32(wire + 8);
            assert(hs + 16u <= (size_t)count);
            CMsgRemoteClientBroadcastHeader *header =
                cmsg_remote_client_broadcast_header__unpack(NULL, hs, wire + 12);
            assert(header);
            unsigned tag = header->msg_type;
            cmsg_remote_client_broadcast_header__free_unpacked(header, NULL);
            if (tag != k_ERemoteDeviceStreamingRequest)
                continue;
            unsigned size = test_discovery_u32(wire + 12 + hs);
            assert(size + hs + 16u == (size_t)count);
            CMsgRemoteDeviceStreamingRequest *req =
                cmsg_remote_device_streaming_request__unpack(NULL, size, wire + 16 + hs);
            assert(req && req->has_network_test);
            ++ticket_count;
            ordinary = !req->network_test;
            assert(ticket_count == (ordinary && !skip_test ? 2u : 1u));
            assert(!ordinary || (!manual && scenario != CANCEL_SAVE && scenario != CANCEL_RUNNING &&
                                 scenario != EXIT_RESULT));
            assert(req->gameid == (ordinary ? 570u : 0u));
            CMsgRemoteDeviceStreamingResponse reply = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
            reply.request_id = req->request_id;
            reply.result = k_ERemoteDeviceStreamingSuccess;
            reply.has_port = reply.has_encrypted_session_key = true;
            reply.port = peer_port;
            uint8_t cipher[128], body[256];
            size_t capacity = sizeof(cipher);
            assert(!IHS_CryptoSymmetricEncrypt(info.sessionKey, 32, store.secret, 32, cipher,
                                               &capacity));
            reply.encrypted_session_key = (ProtobufCBinaryData){capacity, cipher};
            size = cmsg_remote_device_streaming_response__pack(&reply, body);
            test_discovery_send(fd, &from, body, size);
            cmsg_remote_device_streaming_request__free_unpacked(req, NULL);
            handshake = auth = false;
            sequence = 0;
            continue;
        }
        assert(count >= 13);
        local = wire[2];
        unsigned type = wire[0] & 127;
        if (wire[0] & 128) {
            uint32_t sum;
            assert(count >= 17);
            memcpy(&sum, wire + count - 4, 4);
            assert(IHS_CRC32C(wire, count - 4) == sum);
            count -= 4;
        }
        if (type == 1) {
            send_peer(fd, &from, local, 2, 0, 0, wire + 9, 4, crc);
            continue;
        }
        if (type != 5 || wire[4] != 1)
            continue;
        unsigned tag = wire[13];
        if (tag == 6) {
            if (!handshake) {
                assert(count == (ordinary ? 16 : 18));
                assert(!memcmp(wire + 13, ordinary ? "\x06\x0a\x00" : "\x06\x0a\x02\x10\x01",
                               ordinary ? 3 : 5));
                const uint8_t body[] = {7, 10, 3, 8, 0xc0, 0x0b};
                send_peer(fd, &from, local, 5, 1, 0, body, sizeof(body), crc);
                handshake = true;
            }
            continue;
        }
        if (tag == 1) {
            if (!auth) {
                CAuthenticationRequestMsg *request =
                    cauthentication_request_msg__unpack(NULL, count - 14, wire + 14);
                assert(request && request->has_steamid == ordinary && request->token.len == 32);
                cauthentication_request_msg__free_unpacked(request, NULL);
                const uint8_t body[] = {2, 16, 1};
                send_peer(fd, &from, local, 5, 1, 1, body, sizeof(body), crc);
                if (ordinary) {
                    const uint8_t init[] = {8, 0, 16, 3, 24, 4};
                    encrypted(codec, fd, &from, local, 2, 3, init, sizeof(init), 0, crc);
                }
                auth = true;
            }
            continue;
        }
        if (tag != 8 && tag != 9 && tag != 4 && tag != 5)
            continue;
        IHS_Buffer in = IHS_BUFFER_WRAP(wire + 14, count - 14), plain = IHS_BUFFER_INIT(4096, 0);
        uint64_t actual;
        IHS_SessionFrameDecryptResult decrypted =
            IHS_SessionFrameDecrypt(codec, &in, &plain, sequence, &actual);
        assert(decrypted == IHS_SessionFrameDecryptOK ||
               decrypted == IHS_SessionFrameDecryptOldSequence);
        if (decrypted == IHS_SessionFrameDecryptOldSequence) {
            IHS_BufferClear(&plain, true);
            continue;
        }
        ++sequence;
        if (tag == 9 && !ordinary) {
            assert(!plain.size);
            ++keepalives;
        } else if (tag == 8 && !start) {
            CStartNetworkTestMsg *request =
                cstart_network_test_msg__unpack(NULL, plain.size, IHS_BufferPointer(&plain));
            assert(request && request->frames == 600 && request->framerate == 60 &&
                   request->bandwidth_test == bandwidth &&
                   request->bitrate_kbps == (bandwidth ? 15000 : 6000) && keepalives == 3);
            cstart_network_test_msg__free_unpacked(request, NULL);
            start = true;
            if (scenario != CANCEL_RUNNING) {
                if (bandwidth) {
                    target(codec, fd, &from, local, 2, manual ? 100000 : 99999, 0, crc);
                    target(codec, fd, &from, local, 3, manual ? 99999 : 100000, 1, crc);
                }
                uint8_t data[13] = {1};
                unsigned frame = bandwidth ? 0 : 599;
                data[1] = frame;
                data[2] = frame >> 8;
                send_peer(fd, &from, local, 3, 3, 0, data, sizeof(data), crc);
            }
        } else if (tag == 4 && ordinary && !config_seen) {
            CNegotiationSetConfigMsg *selected =
                cnegotiation_set_config_msg__unpack(NULL, plain.size, IHS_BufferPointer(&plain));
            assert(selected && selected->config && selected->streaming_client_config);
            CStreamingClientConfig *c = selected->streaming_client_config;
            assert(c->enable_unreliable_fec == expected_fec && !c->enable_video_hevc);
            assert(c->quality ==
                   (scenario == FAST_ACCEPT ? k_EStreamQualityFast : k_EStreamQualityBalanced));
            assert(c->desired_resolution_x == 1280 && c->desired_resolution_y == 720 &&
                   c->desired_framerate_numerator == 60);
            CNegotiationSetConfigMsg reply = CNEGOTIATION_SET_CONFIG_MSG__INIT;
            reply.config = selected->config;
            uint8_t body[4096];
            size_t size = cnegotiation_set_config_msg__pack(&reply, body);
            encrypted(codec, fd, &from, local, 3, 4, body, size, 1, crc);
            cnegotiation_set_config_msg__free_unpacked(selected, NULL);
            config_seen = true;
        } else if (tag == 5 && ordinary) {
            assert(config_seen && !plain.size);
            complete = true;
        }
        IHS_BufferClear(&plain, true);
    }
    assert(done && (skip_test || (start && decision)));
    bool no_save = scenario == CANCEL_RUNNING || scenario == EXIT_RESULT || skip_test;
    assert(saves == (no_save ? 0u : 1u));
    assert(ticket_count == (manual || no_save || scenario == CANCEL_SAVE ? 1u : 2u));
    assert(sl_network_stats_load(directory, NULL) ==
           ((!no_save && !fail_save) || scenario == SKIP_READABLE));
    sl_auth_store projected = store;
    sl_stream_settings_preview(&projected, directory);
    assert(projected.unreliable_fec == expected_fec);
    if (manual)
        assert(projected.quality == 2 && projected.bitrate_kbps == 0);
    if (scenario == FAST_ACCEPT)
        assert(projected.quality == 1 && projected.bitrate_kbps == UINT32_MAX);
    if (codec)
        IHS_SessionDestroy(codec); /* Before runtime's IHS_Quit. */
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
    printf("runtime scenario=%d crc=%d tickets=%u stats_saves=%u passed\n", scenario, crc,
           ticket_count, saves);
}
int main(void) {
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    for (Scenario s = FIXED; s <= VIDEO_DISABLED; ++s)
        one(s, s & 1);
    stream_media_shutdown();
    puts("Production runtime: first-test/ordinary negotiation, accepted/rejected full presets, "
         "manual test, save failure, running cancel, result exit and save-overlap cancel passed");
    return 0;
}
