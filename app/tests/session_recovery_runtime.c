/* Actual runtime actor, IHS UDP/control/crypto/media workers and SDL frontend.
 * Accepted launch material/handoff and an offline cloud provider are inputs;
 * this is not Steam discovery/authentication or an SDR/NAT acceptance test.
 * The loopback peer negotiates, sends encoded media and either sends type 9 or
 * stays silent through the real transport lease. No production clock changes.
 */
#include "../platforms/common/runtime.c"
#include "fixture_cleanup.h"
#include "crc32c.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "session/session_pri.h"
#include "session/channels/ch_control.h"
#include "session/channels/video/ch_data_video.h"
#include "ui/ui_model.h"
#include "ui/ui_events.h"
#include <assert.h>
#include <poll.h>

static _Atomic(sl_runtime *) actor;
static _Atomic(IHS_Session *) launched;
static atomic_uint requested, destroyed, disconnects;
static atomic_uint channels_ready;
static atomic_bool last_timed_out, last_host_stop;
static atomic_uint audio_opens, audio_closes;
static atomic_uint stream_audio_device;
#ifndef NSL_RECOVERY_MANAGER
static unsigned admitted;
#endif
static IHS_SocketAddress endpoint;
static bool joins_clean = true;
static _Thread_local bool opening_ihs;
#ifdef NSL_RECOVERY_MANAGER
static struct sockaddr_in fixture_control_address;
static int fixture_control_fd;
static atomic_uint manager_handoffs, manager_ticket_phases;
#endif
#if defined(NSL_RECOVERY_APPLICATION) && !defined(NSL_RECOVERY_MANAGER)
/* Published by the main-thread application submit adapter, before requested. */
static sl_command admitted_command;
#endif
void __wrap_sl_log(const char *line) { fprintf(stderr, "%s\n", line); }
bool __wrap_IHS_ClientStreamingHandoff(IHS_Client *c) {
#ifdef NSL_RECOVERY_MANAGER
    bool __real_IHS_ClientStreamingHandoff(IHS_Client *);
    if (IHS_ClientHandshakePhase(c) == 6) atomic_fetch_add(&manager_ticket_phases, 1);
    bool ok = __real_IHS_ClientStreamingHandoff(c);
    if (ok) atomic_fetch_add(&manager_handoffs, 1);
    return ok;
#else
    assert(c && admitted == atomic_load(&requested));
    return true; /* Ticket/authorization handoff is outside this fixture. */
#endif
}

sl_remote_connection *__wrap_sl_remote_connection_create(const IHS_ClientConfig *c,
    const sl_remote_callbacks *cb, void *ctx) {
    (void)c; (void)cb; (void)ctx;
    return NULL; /* No external CM/DNS/TLS. */
}
void __wrap_sl_remote_connection_update(sl_remote_connection *c, uint64_t now) {
    (void)c; (void)now;
#ifdef NSL_RECOVERY_MANAGER
    return; /* Real local manager produces the launch; no CM network. */
#else
    sl_runtime *r = atomic_load(&actor);
    unsigned next = atomic_load(&requested);
    if (!r || next == admitted) return;
    assert(!r->session && !r->waiting_video && sl_media_video_clean());
    admitted = next;
    pthread_mutex_lock(&r->lock);
#ifdef NSL_RECOVERY_APPLICATION
    r->active = admitted_command;
#else
    r->active = (sl_command){.type = SL_CMD_STREAM, .generation = next};
#endif
    r->facts = (sl_runtime_facts){.request_id = next};
    pthread_mutex_unlock(&r->lock);
    r->stream_limits = (sl_stream_request_limits){1280, 720, 60, false, false};
    /* The accepted-request fixture includes request_stream's prior admission
     * edge; normal product requests open this before sending launch material. */
    sl_media_allow_video();
    uint8_t key[32];
    for (unsigned i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    accept_session(r, &endpoint, key, sizeof(key), 0);
#endif
}
#if NSL_HAVE_SNS
void __wrap_sl_sns_config_cache_update(sl_sns_config_cache *c) { (void)c; }
#endif
IHS_UDPSocket *__real_IHS_UDPSocketOpen(bool);
IHS_UDPSocket *__wrap_IHS_UDPSocketOpen(bool broadcast) {
    opening_ihs = true;
    IHS_UDPSocket *s = __real_IHS_UDPSocketOpen(broadcast);
    opening_ihs = false;
    return s;
}
int __real_socket(int, int, int);
int __wrap_socket(int family, int type, int protocol) {
    if (!opening_ihs) { errno = EACCES; return -1; } /* Debug listener only. */
    return __real_socket(family, type, protocol);
}
ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t __wrap_sendto(int fd, const void *data, size_t size, int flags,
                      const struct sockaddr *to, socklen_t length) {
    const struct sockaddr_in *v4 = (const void *)to;
#ifdef NSL_RECOVERY_MANAGER
    /* Only the initial saved-address discovery port is remapped to the local
     * peer's ephemeral listener. Status then publishes its real source port. */
    if (to && to->sa_family == AF_INET && ntohl(v4->sin_addr.s_addr) == INADDR_LOOPBACK && ntohs(v4->sin_port) == 27036)
        return __real_sendto(fd, data, size, flags, (const void *)&fixture_control_address, sizeof(fixture_control_address));
#endif
    if (to && to->sa_family == AF_INET && ntohl(v4->sin_addr.s_addr) == INADDR_LOOPBACK)
        return __real_sendto(fd, data, size, flags, to, length);
    return (ssize_t)size; /* Discard discovery broadcasts; nothing leaves loopback. */
}
IHS_Session *__real_IHS_SessionCreate(const IHS_ClientConfig *, const IHS_SessionInfo *);
IHS_Session *__wrap_IHS_SessionCreate(const IHS_ClientConfig *c, const IHS_SessionInfo *i) {
    IHS_Session *s = __real_IHS_SessionCreate(c, i);
    atomic_store(&launched, s);
    return s;
}
void __real_IHS_SessionDestroy(IHS_Session *);
void __wrap_IHS_SessionDestroy(IHS_Session *s) {
    joins_clean &= !s->base.worker && !s->sendThread;
    atomic_store(&last_timed_out, s->transport.timedOut);
    atomic_store(&last_host_stop, IHS_SessionHostRequestedStop(s));
    __real_IHS_SessionDestroy(s);
    atomic_store(&launched, NULL);
    atomic_fetch_add(&destroyed, 1);
}
SDL_AudioDeviceID __real_SDL_OpenAudioDevice(const char *, int, const SDL_AudioSpec *, SDL_AudioSpec *, int);
SDL_AudioDeviceID __wrap_SDL_OpenAudioDevice(const char *name, int capture,
    const SDL_AudioSpec *want, SDL_AudioSpec *have, int changes) {
    SDL_AudioDeviceID id = __real_SDL_OpenAudioDevice(name, capture, want, have, changes);
    if (id && want->samples == 1024) {
        assert(!atomic_exchange(&stream_audio_device, id));
        atomic_fetch_add(&audio_opens, 1);
    }
    return id;
}
void __real_SDL_CloseAudioDevice(SDL_AudioDeviceID);
void __wrap_SDL_CloseAudioDevice(SDL_AudioDeviceID id) {
    __real_SDL_CloseAudioDevice(id);
    if (id && id == atomic_load(&stream_audio_device)) {
        atomic_store(&stream_audio_device, 0);
        atomic_fetch_add(&audio_closes, 1);
    }
}
void __real_IHS_SessionChannelAdd(IHS_Session *, IHS_SessionChannel *);
void __wrap_IHS_SessionChannelAdd(IHS_Session *s, IHS_SessionChannel *ch) {
    __real_IHS_SessionChannelAdd(s, ch);
    if (ch->id == 3 || ch->id == 4)
        atomic_fetch_or(&channels_ready, 1u << ch->id);
}
static const IHS_StreamSessionCallbacks *original_callbacks;
static IHS_StreamSessionCallbacks observed_callbacks;
static void observe_disconnected(IHS_Session *s, void *context) {
    original_callbacks->disconnected(s, context);
    atomic_fetch_add(&disconnects, 1);
}
void __real_IHS_SessionSetSessionCallbacks(IHS_Session *, const IHS_StreamSessionCallbacks *, void *);
void __wrap_IHS_SessionSetSessionCallbacks(IHS_Session *s, const IHS_StreamSessionCallbacks *c, void *context) {
    original_callbacks = c;
    observed_callbacks = *c;
    observed_callbacks.disconnected = observe_disconnected;
    __real_IHS_SessionSetSessionCallbacks(s, &observed_callbacks, context);
}
static uint64_t now_ms(void) {
    struct timespec t;
    assert(!clock_gettime(CLOCK_MONOTONIC, &t));
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static void wire(int fd, const struct sockaddr_in *to, uint8_t type, uint8_t local,
                 uint8_t channel, uint16_t id, int16_t fragment,
                 const uint8_t *body, size_t count) {
    uint8_t bytes[2048] = {type | 128, 0, 7, local, channel};
    assert(count <= sizeof(bytes) - 17);
    bytes[5] = (uint8_t)fragment; bytes[6] = (uint8_t)((uint16_t)fragment >> 8);
    bytes[7] = (uint8_t)id; bytes[8] = (uint8_t)(id >> 8);
    uint32_t tick = IHS_SessionPacketTimestamp();
    for (unsigned i = 0; i < 4; ++i) bytes[9+i] = (uint8_t)(tick >> (8*i));
    if (count) memcpy(bytes+13, body, count);
    size_t size = count+13;
    uint32_t crc = IHS_CRC32C(bytes, size);
    for (unsigned i = 0; i < 4; ++i) bytes[size++] = (uint8_t)(crc >> (8*i));
    assert(sendto(fd, bytes, size, 0, (const void *)to, sizeof(*to)) == (ssize_t)size);
}
static void encrypted(int fd, const struct sockaddr_in *to, uint8_t local,
                      uint16_t id, uint8_t tag, const uint8_t *plain, size_t count,
                      uint64_t sequence) {
    IHS_Session *s = atomic_load(&launched);
    assert(s);
    uint8_t bytes[2048] = {tag}, empty = 0;
    size_t size = sizeof(bytes)-1;
    assert(!IHS_SessionFrameEncrypt(s, count ? plain : &empty, count, bytes+1, &size, sequence));
    wire(fd, to, 5, local, 1, id, 0, bytes, size+1);
}
static void message(int fd, const struct sockaddr_in *to, uint8_t local,
                    uint16_t id, uint8_t tag, const ProtobufCMessage *m, uint64_t seq) {
    uint8_t bytes[1024];
    size_t size = protobuf_c_message_get_packed_size(m);
    assert(size <= sizeof(bytes));
    protobuf_c_message_pack(m, bytes);
    encrypted(fd, to, local, id, tag, bytes, size, seq);
}
static void media(int fd, const struct sockaddr_in *to, uint8_t local, uint8_t channel,
                  const uint8_t *encoded, size_t count, bool video) {
    IHS_Buffer b = IHS_BUFFER_INIT(1024, 32768);
    IHS_BufferAppendUInt8(&b, k_EStreamDataPacket);
    IHS_BufferAppendUInt16LE(&b, 1);
    IHS_BufferAppendUInt32LE(&b, IHS_SessionPacketTimestamp());
    IHS_BufferAppendUInt16LE(&b, 0);
    IHS_BufferAppendUInt32LE(&b, 0);
    if (video) {
        IHS_BufferAppendUInt16LE(&b, 0); /* Prior video frame ID, before flags. */
        IHS_BufferAppendUInt8(&b, VideoFrameFlagFrameFinish | VideoFrameFlagKeyFrame);
        IHS_BufferAppendUInt16LE(&b, 0);
        IHS_BufferAppendUInt16LE(&b, 0);
    }
    IHS_BufferAppendMem(&b, encoded, count);
    unsigned parts = (unsigned)((b.size+999)/1000);
    size_t offset = 0;
    for (unsigned i = 0; i < parts; ++i) {
        size_t bytes = b.size-offset < 1000 ? b.size-offset : 1000;
        wire(fd, to, i ? 6 : 5, local, channel, (uint16_t)i,
             i ? (int16_t)(i-1) : (int16_t)(parts-1), IHS_BufferPointer(&b)+offset, bytes);
        offset += bytes;
    }
    IHS_BufferClear(&b, true);
}
typedef struct {
    bool displayed, audio, stopped, unexpected, ui_error, ui_home, video_clean, hid_unbound;
    bool timed_out, host_stop, audio_closed;
    bool returned_home;
    unsigned callbacks, destroys;
    uint64_t session_id;
} observation;
#ifndef NSL_RECOVERY_APPLICATION
static observation round_trip(sl_runtime *r, sl_ui_model *ui, unsigned round,
                               const uint8_t *video, size_t video_size) {
    int fd = __real_socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(fd, (void *)&address, sizeof(address)));
    socklen_t len = sizeof(address);
    assert(!getsockname(fd, (void *)&address, &len));
    endpoint = (IHS_SocketAddress){.port = ntohs(address.sin_port)};
    assert(IHS_IPAddressFromString(&endpoint.ip, "127.0.0.1"));
    uint64_t generation = ++ui->generation;
    ui->page = SL_CONNECTING; ui->streaming = false; /* Accepted launch boundary. */
    atomic_store(&channels_ready, 0);
    atomic_store(&requested, (unsigned)generation);
    unsigned callbacks_before = atomic_load(&disconnects), destroys_before = atomic_load(&destroyed);
    bool hello = false, auth = false, configured = false, started = false, stop_sent = false;
    bool media_sent = false;
    struct sockaddr_in client = {0};
    uint8_t local = 0;
    observation out = {0};
    uint64_t deadline = now_ms()+25000;
    while (!out.stopped) {
        assert(now_ms() < deadline);
        stream_media_present();
        sl_runtime_event e;
        while (sl_runtime_poll(r, &e)) {
            sl_ui_runtime_event(ui, &e);
            if (e.type == SL_EVENT_STOPPED && e.generation == generation) {
                out.stopped = true; out.unexpected = e.account != 0;
            }
            if (e.type == SL_EVENT_FAILURE)
                fprintf(stderr, "round=%u failure=%s hello=%d auth=%d configured=%d started=%d\n",
                        round, e.text, hello, auth, configured, started);
            assert(e.type != SL_EVENT_FAILURE);
        }
        stream_media_snapshot snap;
        stream_media_get_snapshot(&snap);
        sl_runtime_facts facts;
        if (started && sl_runtime_read_facts(r, &facts) && facts.request_id == generation &&
            facts.session_id && snap.session_id == facts.session_id) {
            out.session_id = facts.session_id;
            out.displayed |= snap.first_frame_displayed;
            out.audio |= snap.audio_frames > 0 && snap.audio_active;
        }
        sl_media_gate(ui->streaming);
        /* Explicit local-peer producer boundary: publish channels before
         * sending media. Early channel admission has separate SDK fixtures. */
        if (started && !media_sent && atomic_load(&channels_ready) == ((1u<<3)|(1u<<4))) {
            media(fd, &client, local, 3, video, video_size, true);
            const uint8_t opus[] = {0xf0, 0xff, 0xfe};
            media(fd, &client, local, 4, opus, sizeof(opus), false);
            media_sent = true;
        }
        if (out.displayed && out.audio && ui->streaming && !stop_sent) {
            assert(started);
            stop_sent = true;
            /* Round 2 is a real silent peer, not a controlled timeout clock. */
            if (round != 2) wire(fd, &client, 9, local, 0, 0, 0, NULL, 0);
        }
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int ready = poll(&p, 1, 1);
        assert(ready >= 0);
        if (!ready || out.stopped) continue;
        uint8_t raw[4096];
        len = sizeof(client);
        ssize_t size = recvfrom(fd, raw, sizeof(raw), 0, (void *)&client, &len);
        assert(size >= 13);
        unsigned type = raw[0]&127;
        local = raw[2];
        if (round == 2 && stop_sent) continue; /* No keepalive/ACK after silence. */
        if (type == 1) {
            wire(fd, &client, 2, local, 0, 0, 0, raw+9, 4);
        } else if (type == 5 && raw[4] == 1) {
            uint16_t id = (uint16_t)(raw[7] | (unsigned)raw[8]<<8);
            wire(fd, &client, 7, local, 1, id, 0, raw+9, 4);
            if (raw[13] == 6 && !hello) {
                const uint8_t server[] = {7, 10, 3, 8, 0xc0, 0x0b};
                wire(fd, &client, 5, local, 1, 0, 0, server, sizeof(server)); hello = true;
            } else if (raw[13] == 1 && !auth) {
                const uint8_t response[] = {2, 8, 0, 16, 1};
                const uint8_t init[] = {8, 1, 16, 3, 24, 4};
                wire(fd, &client, 5, local, 1, 1, 0, response, sizeof(response));
                encrypted(fd, &client, local, 2, 3, init, sizeof(init), 0); auth = true;
            } else if (raw[13] == 4 && !configured) {
                IHS_Session *s = atomic_load(&launched);
                IHS_Buffer in = IHS_BUFFER_WRAP(raw+14, (size_t)size-18), plain = IHS_BUFFER_INIT(1024, 4096);
                uint64_t sequence;
                assert(IHS_SessionFrameDecrypt(s, &in, &plain, 0, &sequence) == IHS_SessionFrameDecryptOK);
                CNegotiationSetConfigMsg *m = cnegotiation_set_config_msg__unpack(NULL, plain.size, IHS_BufferPointer(&plain));
                assert(m && m->config);
                message(fd, &client, local, 3, 4, &m->base, 1);
                cnegotiation_set_config_msg__free_unpacked(m, NULL); IHS_BufferClear(&plain, true);
                configured = true;
            } else if (raw[13] == 5 && !started) {
                assert(configured);
                CStartVideoDataMsg v = CSTART_VIDEO_DATA_MSG__INIT;
                v.channel = 3; v.has_codec = true; v.codec = k_EStreamVideoCodecH264;
                v.has_width = v.has_height = true; v.width = 128; v.height = 72;
                message(fd, &client, local, 4, 52, &v.base, 2);
                CStartAudioDataMsg a = CSTART_AUDIO_DATA_MSG__INIT;
                a.channel = 4; a.has_codec = a.has_frequency = a.has_channels = true;
                a.codec = k_EStreamAudioCodecOpus; a.frequency = 48000; a.channels = 2;
                message(fd, &client, local, 5, 50, &a.base, 3);
                started = true;
            }
        }
    }
    out.callbacks = atomic_load(&disconnects)-callbacks_before;
    out.destroys = atomic_load(&destroyed)-destroys_before;
    out.timed_out = atomic_load(&last_timed_out);
    out.host_stop = atomic_load(&last_host_stop);
    out.audio_closed = atomic_load(&stream_audio_device) == 0;
    out.ui_error = ui->page == SL_ERROR && !ui->streaming;
    out.ui_home = ui->page == SL_HOME && !ui->streaming;
    deadline = now_ms()+5000;
    while (!sl_media_video_clean()) { assert(now_ms() < deadline); sl_media_collect(); SDL_Delay(1); }
    out.video_clean = true;
    /* STOPPED follows actual SessionDestroy; provider unbinding precedes it. */
    out.hid_unbound = r->provider && r->provider->manager == NULL;
    if (round == 2) {
        assert(ui->page == SL_ERROR);
        sl_ui_action(ui, SL_BACK, 0);
        sl_command cancel;
        assert(sl_ui_take_command(ui, &cancel) && cancel.type == SL_CMD_CANCEL && ui->page == SL_STOPPING);
        assert(sl_runtime_submit(r, &cancel, &ui->store));
        deadline = now_ms()+5000;
        while (ui->page != SL_HOME) {
            assert(now_ms() < deadline);
            sl_media_collect();
            sl_runtime_event e;
            while (sl_runtime_poll(r, &e)) sl_ui_runtime_event(ui, &e);
            SDL_Delay(1);
        }
    }
    out.returned_home = ui->page == SL_HOME;
    close(fd);
    return out;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    char directory[] = "/tmp/nsl-session-recovery-XXXXXX";
    assert(mkdtemp(directory) && !setenv("NSL_DATA_DIR", directory, 1));
    FILE *file = fopen(argv[1], "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long count = ftell(file); assert(count > 0 && count < 16000); rewind(file);
    uint8_t *video = malloc((size_t)count); assert(video);
    assert(fread(video, 1, (size_t)count, file) == (size_t)count && !fclose(file));
    assert(stream_media_init(NULL));
    int controller = SDL_JoystickAttachVirtual(SDL_JOYSTICK_TYPE_GAMECONTROLLER, 6, 16, 0);
    assert(controller >= 0);
    sl_gfx *root = sl_media_gfx();
    sl_auth_store store = {.device_id = 1, .sound = true};
    strcpy(store.device_name, "loopback recovery"); sl_host_registry_init(&store.registry);
    sl_ui_model ui; sl_ui_init(&ui, &store);
    sl_runtime *r = sl_runtime_create(&store); assert(r);
    atomic_store(&actor, r);
    observation rounds[3];
    for (unsigned i = 0; i < 3; ++i) rounds[i] = round_trip(r, &ui, i+1, video, (size_t)count);
    bool root_retained = root == sl_media_gfx();
    sl_runtime_request_exit(r);
    uint64_t deadline = now_ms()+5000;
    while (!sl_runtime_finished(r)) { assert(now_ms() < deadline); sl_media_collect(); SDL_Delay(1); }
    sl_runtime_destroy(r); atomic_store(&actor, NULL);
    assert(!SDL_JoystickDetachVirtual(controller));
    stream_media_shutdown(); free(video); sl_fixture_remove_tree(directory);
    bool final_clean = !sl_media_gfx() && !atomic_load(&stream_audio_device);
    printf("{\"rounds\":[");
    for (unsigned i = 0; i < 3; ++i) {
        observation o = rounds[i];
        printf("%s{\"displayed\":%s,\"audio\":%s,\"stopped\":%s,\"unexpected\":%s,"
               "\"ui_error\":%s,\"ui_home\":%s,\"video_clean\":%s,\"hid_unbound\":%s,"
               "\"timed_out\":%s,\"host_stop\":%s,\"audio_closed\":%s,"
               "\"returned_home\":%s,"
               "\"callbacks\":%u,\"destroys\":%u,\"session_id\":%llu}", i ? "," : "", o.displayed?"true":"false",
               o.audio?"true":"false",o.stopped?"true":"false",o.unexpected?"true":"false",
               o.ui_error?"true":"false",o.ui_home?"true":"false",o.video_clean?"true":"false",
               o.hid_unbound?"true":"false",o.timed_out?"true":"false",o.host_stop?"true":"false",
               o.audio_closed?"true":"false",o.returned_home?"true":"false",o.callbacks,o.destroys,
               (unsigned long long)o.session_id);
    }
    printf("],\"root_retained\":%s,\"joins_clean\":%s,\"final_clean\":%s,\"audio_opens\":%u,\"audio_closes\":%u}\n",
           root_retained?"true":"false",joins_clean?"true":"false",final_clean?"true":"false",
           atomic_load(&audio_opens),atomic_load(&audio_closes));
    return 0;
}
#endif
