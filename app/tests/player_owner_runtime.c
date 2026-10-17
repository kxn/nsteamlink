/* Include the production translation unit to exercise its private stop_session
 * without adding a test-only session injection API to the application. */
#include "../platforms/common/runtime.c"
#include "audio_jitter.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "session/channels/ch_control.h"
#include "session/reliable.h"
#include "session/session_pri.h"
#include "test_session.h"
#include <assert.h>

static SDL_AudioDeviceID stream_device;
static sl_audio_jitter *ring;
static bool joined, destroyed, owner_called, expected_focus;
static unsigned order;
static unsigned join_at, destroy_at, owner_at, close_at;
SDL_AudioDeviceID __real_SDL_OpenAudioDevice(const char *, int, const SDL_AudioSpec *,
                                             SDL_AudioSpec *, int);
SDL_AudioDeviceID __wrap_SDL_OpenAudioDevice(const char *n, int c, const SDL_AudioSpec *w,
                                             SDL_AudioSpec *h, int a) {
    SDL_AudioDeviceID id = __real_SDL_OpenAudioDevice(n, c, w, h, a);
    if (w->samples == 1024)
        stream_device = id;
    return id;
}
void __real_SDL_PauseAudioDevice(SDL_AudioDeviceID, int);
void __wrap_SDL_PauseAudioDevice(SDL_AudioDeviceID id, int pause) {
    if (id != stream_device || pause)
        __real_SDL_PauseAudioDevice(id, pause);
}
void __real_SDL_CloseAudioDevice(SDL_AudioDeviceID);
void __wrap_SDL_CloseAudioDevice(SDL_AudioDeviceID id) {
    __real_SDL_CloseAudioDevice(id);
    if (id == stream_device) {
        stream_device = 0;
        if (owner_called)
            close_at = ++order;
    }
}
bool __real_sl_audio_jitter_init(sl_audio_jitter *, int, int);
bool __wrap_sl_audio_jitter_init(sl_audio_jitter *j, int rate, int channels) {
    ring = j;
    return __real_sl_audio_jitter_init(j, rate, channels);
}
void __real_IHS_SessionThreadedJoin(IHS_Session *);
void __wrap_IHS_SessionThreadedJoin(IHS_Session *s) {
    __real_IHS_SessionThreadedJoin(s);
    joined = true;
    join_at = ++order;
}
void __real_IHS_SessionDestroy(IHS_Session *);
void __wrap_IHS_SessionDestroy(IHS_Session *s) {
    assert(joined);
    __real_IHS_SessionDestroy(s);
    destroyed = true;
    destroy_at = ++order;
}
void __real_sl_media_end_stream_player(bool, bool, bool);
void __wrap_sl_media_end_stream_player(bool focus, bool hard, bool background) {
    assert(joined && destroyed && !hard && !background && focus == expected_focus);
    owner_called = true;
    owner_at = ++order;
    __real_sl_media_end_stream_player(focus, hard, background);
}
bool __wrap_IHS_BaseSend(IHS_Base *base, IHS_SocketAddress address, const IHS_Buffer *wire) {
    (void)base;
    (void)address;
    (void)wire;
    return true;
}
uint32_t __wrap_IHS_SessionPacketTimestamp(void) {
    return 1000000;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    expected_focus = atoi(argv[1]) != 0;
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    IHS_Init();
    sl_runtime r = {0};
    pthread_mutex_init(&r.lock, NULL);
    atomic_init(&r.player_input_focus, !expected_focus);
    atomic_init(&r.foreground_generation, 0);
    sl_runtime_player_focus(&r, false);
    assert(atomic_load(&r.foreground_generation) == 0); /* Focus is not Pause. */
    if (expected_focus)
        sl_runtime_foreground(&r, false);
    unsigned lifecycle = atomic_load(&r.foreground_generation);
    sl_runtime_player_focus(&r, expected_focus);
    assert(atomic_load(&r.foreground_generation) == lifecycle);
    /* Both crossed combinations exercise cleanup independently of lifecycle:
     * focused+app-background closes; unfocused+app-foreground retains. */
    r.session = IHS_TestSessionCreate();
    assert(r.session);
    IHS_TimerTaskStopImmediate(r.session->retransmission.timer);
    r.session->state.connectionState = IHS_SessionConnectionStateConnected;
    IHS_SessionSetAudioCallbacks(r.session, sl_media_audio_callbacks(), NULL);
    IHS_Buffer body = IHS_BUFFER_INIT(256, 4096);
    CStartAudioDataMsg start = CSTART_AUDIO_DATA_MSG__INIT;
    start.channel = 3;
    start.has_codec = 1;
    start.codec = k_EStreamAudioCodecOpus;
    start.has_frequency = 1;
    start.frequency = 48000;
    start.has_channels = 1;
    start.channels = 2;
    IHS_BufferAppendMessage(&body, (const ProtobufCMessage *)&start);
    IHS_SessionPacketHeader h = {0};
    IHS_SessionChannelControlOnMessageReceived(r.session->channels[1],
                                               k_EStreamControlStartAudioData, &body, &h);
    IHS_BufferClear(&body, true);
    assert(stream_device && ring && ring->ring);
    IHS_SessionFrame frame = {.header = {.type = IHS_SessionPacketTypeReliable,
                                         .channelId = 3,
                                         .sendTimestamp = 1100011,
                                         .receiveTimestamp = 1100021,
                                         .receiveBegin = 1100021}};
    IHS_BufferInit(&frame.body, 256, 4096);
    IHS_BufferAppendUInt8(&frame.body, k_EStreamDataPacket);
    IHS_BufferAppendUInt16LE(&frame.body, 1);
    IHS_BufferAppendUInt32LE(&frame.body, 1100001);
    IHS_BufferAppendUInt16LE(&frame.body, 0);
    IHS_BufferAppendUInt32LE(&frame.body, 0);
    const uint8_t payload[] = {0xf0, 0xff, 0xfe};
    IHS_BufferAppendMem(&frame.body, payload, sizeof(payload));
    IHS_SessionDeliverReliableFrame(r.session, &frame);
    IHS_SessionFrameClear(&frame, true);
    stream_media_snapshot snapshot = {0};
    for (unsigned n = 0; n < 5000; ++n) {
        stream_media_get_snapshot(&snapshot);
        if (snapshot.audio_frames == 1)
            break;
        SDL_Delay(1);
    }
    assert(snapshot.audio_frames == 1 && snapshot.audio_queued_bytes == 480 * 2 * 2);
    assert(!stop_session(&r));
    assert(!r.session && joined && destroyed && owner_called);
    assert(join_at < destroy_at && destroy_at < owner_at);
    if (expected_focus)
        assert(!stream_device && !ring->ring && close_at > owner_at);
    else
        assert(stream_device && ring->ring && sl_audio_jitter_queued(ring) == 480 && !close_at);
    printf("{\"focus\":%s,\"retained\":%s,\"join_before_destroy_before_owner\":true}\n",
           expected_focus ? "true" : "false", stream_device ? "true" : "false");
    IHS_Quit();
    stream_media_shutdown();
    pthread_mutex_destroy(&r.lock);
    assert(!stream_device && !ring->ring);
    return 0;
}
