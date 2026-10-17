/* Full production control/pending/RX/worker -> app decoder -> float jitter ->
 * actual SDL callback. SDL dummy is paused for deterministic player schedules.
 * IO failure, clock and terminal observations are controlled, never golden-fed. */
#include "audio_jitter.h"
#include "audio_recovery.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "media.h"
#include "session/channels/ch_control.h"
#include "session/channels/ch_data.h"
#include "session/reliable.h"
#include "session/session_pri.h"
#include "session/session_queue.h"
#include "test_session.h"
#include <SDL.h>
#include <assert.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool playerOK = true, requestedRunning;
static SDL_AudioDeviceID device;
static SDL_AudioSpec requested;
static SDL_AudioCallback productionCallback;
static void *productionContext;
static unsigned serial, stream;
static sl_audio_jitter *jitter;
static unsigned expected;
static atomic_uint completed;
static pthread_t caller;
static _Thread_local IHS_StreamAudioFrameInfo current;
static char *pcm[512];
static unsigned pcmCount;
static uint8_t *output;
static size_t outputSize;
static void onCaller(void) {
    assert(pthread_equal(caller, pthread_self()));
}
static void hex(FILE *f, const void *data, size_t size) {
    const uint8_t *p = data;
    for (size_t i = 0; i < size; ++i)
        fprintf(f, "%02x", p[i]);
}
static void digest(const void *data, size_t size) {
    uint8_t hash[32];
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    assert(!mbedtls_sha256(data, size, hash, 0));
#else
    assert(!mbedtls_sha256_ret(data, size, hash, 0));
#endif
    putchar('"');
    hex(stdout, hash, sizeof(hash));
    putchar('"');
}
static uint32_t bits(float f) {
    uint32_t v;
    memcpy(&v, &f, 4);
    return v;
}
SDL_AudioDeviceID __real_SDL_OpenAudioDevice(const char *, int, const SDL_AudioSpec *,
                                             SDL_AudioSpec *, int);
SDL_AudioDeviceID __wrap_SDL_OpenAudioDevice(const char *name, int capture,
                                             const SDL_AudioSpec *want, SDL_AudioSpec *have,
                                             int allowed) {
    bool streaming = want->samples == 1024;
    if (streaming) {
        onCaller();
        requested = *want;
        assert(!device);
    }
    if (streaming && !playerOK)
        return 0;
    SDL_AudioDeviceID result = __real_SDL_OpenAudioDevice(name, capture, want, have, allowed);
    if (streaming && result) {
        device = result;
        stream = ++serial;
        productionCallback = want->callback;
        productionContext = want->userdata;
    }
    return result;
}
void __real_SDL_PauseAudioDevice(SDL_AudioDeviceID, int);
void __wrap_SDL_PauseAudioDevice(SDL_AudioDeviceID id, int pause) {
    if (id == device)
        requestedRunning = pause == 0;
    if (id != device || pause)
        __real_SDL_PauseAudioDevice(id, pause);
}
void __real_SDL_CloseAudioDevice(SDL_AudioDeviceID);
void __wrap_SDL_CloseAudioDevice(SDL_AudioDeviceID id) {
    __real_SDL_CloseAudioDevice(id);
    if (id == device) {
        onCaller();
        device = 0;
        stream = 0;
        requestedRunning = false;
    }
}
void __real_sl_audio_suspend(void);
void __wrap_sl_audio_suspend(void) {
    /* Resetting UI voices while the retained stream callback runs races its
     * mixer. Production prepare must close/join that stream first. */
    assert(!device);
    __real_sl_audio_suspend();
}
bool __real_sl_audio_jitter_init(sl_audio_jitter *, int, int);
bool __wrap_sl_audio_jitter_init(sl_audio_jitter *j, int rate, int channels) {
    jitter = j;
    return __real_sl_audio_jitter_init(j, rate, channels);
}
int __real_sl_audio_jitter_push(sl_audio_jitter *, const float *, int);
int __wrap_sl_audio_jitter_push(sl_audio_jitter *j, const float *data, int count) {
    assert(pcmCount < 512);
    size_t ignored;
    FILE *f = open_memstream(&pcm[pcmCount++], &ignored);
    assert(f);
    fprintf(f, "{\"id\":%u,\"timestamp\":%u,\"data\":\"", current.id, current.timestamp);
    hex(f, data, (size_t)count * j->channels * sizeof(float));
    fprintf(f, "\"}");
    assert(!fclose(f));
    return __real_sl_audio_jitter_push(j, data, count);
}
typedef struct DecodeObserver {
    int (*callback)(void *, const sl_audio_decode_step *);
    void *context;
} DecodeObserver;
static int decode(void *context, const sl_audio_decode_step *step) {
    DecodeObserver *observer = context;
    current = (IHS_StreamAudioFrameInfo){.id = step->id, .timestamp = step->timestamp};
    return observer->callback(observer->context, step);
}
int __real_sl_audio_recovery_run(sl_audio_recovery *, uint16_t, uint32_t,
                                 int (*)(void *, const sl_audio_decode_step *), void *);
int __wrap_sl_audio_recovery_run(sl_audio_recovery *r, uint16_t id, uint32_t timestamp,
                                 int (*callback)(void *, const sl_audio_decode_step *),
                                 void *context) {
    DecodeObserver observer = {.callback = callback, .context = context};
    return __real_sl_audio_recovery_run(r, id, timestamp, decode, &observer);
}
uint32_t __wrap_IHS_SessionPacketTimestamp(void) {
    return 1000000;
}
void __real_IHS_SessionChannelDataReceiveReliableFrame(IHS_SessionChannel *, IHS_SessionFrame *);
void __wrap_IHS_SessionChannelDataReceiveReliableFrame(IHS_SessionChannel *ch,
                                                       IHS_SessionFrame *f) {
    onCaller();
    assert(f->mediaPrepared);
    IHS_SessionChannelData *d = (void *)ch;
    if (d->worker && !d->discardFrames && !d->interrupted)
        ++expected;
    __real_IHS_SessionChannelDataReceiveReliableFrame(ch, f);
}
static int prepare(IHS_Session *s, const IHS_StreamAudioConfig *c, void *ctx) {
    (void)ctx;
    onCaller();
    return sl_media_audio_callbacks()->prepare(s, c, NULL);
}
static int start(IHS_Session *s, const IHS_StreamAudioConfig *c, void *ctx) {
    (void)ctx;
    onCaller();
    return sl_media_audio_callbacks()->start(s, c, NULL);
}
static void stop(IHS_Session *s, void *ctx) {
    (void)ctx;
    onCaller();
    sl_media_audio_callbacks()->stop(s, NULL);
}
static int submit(IHS_Session *s, const IHS_StreamAudioFrameInfo *info, IHS_Buffer *data,
                  void *ctx) {
    (void)ctx;
    assert(!pthread_equal(caller, pthread_self()));
    current = *info;
    int result = sl_media_audio_callbacks()->submitFrame(s, info, data, NULL);
    atomic_fetch_add(&completed, 1);
    return result;
}
static void parseHex(IHS_Buffer *b, const char *raw) {
    for (size_t n = 0; strcmp(raw, "-") && raw[n]; n += 2) {
        unsigned v;
        assert(raw[n + 1] && sscanf(raw + n, "%2x", &v) == 1);
        IHS_BufferAppendUInt8(b, v);
    }
}
static void report(IHS_Session *s) {
    for (unsigned n = 0; n < 5000 && atomic_load(&completed) != expected; ++n)
        usleep(1000);
    assert(atomic_load(&completed) == expected);
    IHS_SessionChannelData *d =
        (void *)IHS_SessionChannelForType(s, IHS_SessionChannelTypeDataAudio);
    stream_media_snapshot state;
    stream_media_get_snapshot(&state);
    printf("{\"channel\":%u,\"decoder\":%s,\"logical\":[%d,%d],\"requested\":[%d,%u],\"stream\":%u,"
           "\"pcm\":[",
           d ? d->base.id : 0, d && !d->discardFrames ? "true" : "false", state.audio_frequency,
           state.audio_channels, requested.freq, requested.channels, stream);
    for (unsigned n = 0; n < pcmCount; ++n) {
        printf("%s%s", n ? "," : "", pcm[n]);
        free(pcm[n]);
    }
    pcmCount = 0;
    printf("],\"running\":%s,\"pending\":[", requestedRunning ? "true" : "false");
    for (unsigned n = 0; n < s->pendingDataCount; ++n) {
        IHS_QueueItem *item = IHS_QueuePoll(s->pendingData);
        assert(item);
        IHS_SessionPacket *p = &((QueuedPacket *)item)->packet;
        printf("%s{\"kind\":%u,\"channel\":%u,\"fragment\":%u,\"id\":%u,\"sent\":%u,\"first\":%u,"
               "\"received\":%u,\"body\":\"",
               n ? "," : "", p->header.type, p->header.channelId, p->header.fragmentId,
               p->header.packetId, p->header.sendTimestamp, p->header.receiveBegin,
               p->header.receiveTimestamp);
        hex(stdout, IHS_BufferPointer(&p->body), p->body.size);
        printf("\"}");
        IHS_QueueAppend(s->pendingData, item);
    }
    printf("],\"output\":\"");
    hex(stdout, output, outputSize);
    printf("\",\"queued\":");
    bool have = jitter && jitter->ring;
    if (have)
        printf("%d", sl_audio_jitter_queued(jitter));
    else
        printf("null");
    printf(",\"ring_sha256\":");
    if (have)
        digest(jitter->ring, (size_t)SL_AUDIO_JITTER_CAPACITY * jitter->channels * 4);
    else
        printf("null");
    printf(",\"params\":");
    if (have) {
        putchar('[');
        for (unsigned n = 0; n < 10; ++n)
            printf("%s%u", n ? "," : "", (uint32_t)jitter->params[n]);
        putchar(']');
    } else
        printf("null");
    printf(",\"jitter_state\":");
    if (have) {
        sl_audio_jitter *j = jitter;
        const uint32_t offsets[] = {56,   60,   68,   72,   108,  112,  120,  124,  128,  132,
                                    136,  4236, 4240, 4244, 4248, 4252, 4256, 4260, 4264, 4268,
                                    4272, 4276, 4280, 4284, 4288, 4292, 4296, 4300};
        const uint32_t values[] = {j->channels,
                                   SL_AUDIO_JITTER_CAPACITY,
                                   j->write,
                                   j->read,
                                   j->tracked_write,
                                   j->attempts,
                                   bits(j->fade),
                                   bits(j->fade_step),
                                   bits(j->cross),
                                   bits(j->cross_step),
                                   j->alternate_read,
                                   j->dropped,
                                   j->missing,
                                   j->last_queued,
                                   j->min,
                                   j->max,
                                   j->mean,
                                   j->variance,
                                   j->expands,
                                   j->shrinks,
                                   j->underflow_fades,
                                   j->running_min,
                                   j->running_max,
                                   j->observations,
                                   j->interval,
                                   bits(j->running_mean),
                                   bits(j->running_m2),
                                   j->adjustment};
        _Static_assert(sizeof(offsets) == sizeof(values), "scalar observers");
        putchar('{');
        for (unsigned n = 0; n < sizeof(offsets) / sizeof(offsets[0]); ++n)
            printf("%s\"%u\":%u", n ? "," : "", offsets[n], values[n]);
        printf(",\"priming\":%s,\"overrun\":%s}", j->priming ? "true" : "false",
               j->overrun ? "true" : "false");
    } else
        printf("null");
    puts("}");
    free(output);
    output = NULL;
    outputSize = 0;
}
int main(void) {
    caller = pthread_self();
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    IHS_Init();
    IHS_Session *s = IHS_TestSessionCreate();
    assert(s);
    IHS_TimerTaskStopImmediate(s->retransmission.timer);
    s->state.connectionState = IHS_SessionConnectionStateConnected;
    s->state.connectionId = 12;
    s->state.hostConnectionId = 34;
    s->negotiatedConfig = cnegotiated_config__unpack(NULL, 0, NULL);
    assert(s->negotiatedConfig);
    s->negotiatedConfig->has_selected_audio_codec = 1;
    s->negotiatedConfig->selected_audio_codec = 3;
    IHS_StreamAudioCallbacks callbacks = {
        .prepare = prepare, .start = start, .stop = stop, .submitFrame = submit};
    IHS_SessionSetAudioCallbacks(s, &callbacks, NULL);
    char *line = NULL;
    size_t capacity = 0;
    char raw[131073];
    while (getline(&line, &capacity, stdin) >= 0) {
        unsigned kind, channel, id, timestamp, sent, received;
        switch (line[0]) {
        case 'C': {
            assert(sscanf(line, "C %u %131072s", &kind, raw) == 2);
            IHS_Buffer body = IHS_BUFFER_INIT(256, 131073);
            parseHex(&body, raw);
            IHS_SessionPacketHeader header = {.type = IHS_SessionPacketTypeReliable,
                                              .channelId = 1};
            IHS_SessionChannelControlHandoff(s->channels[1], kind, &body, &header);
            IHS_SessionChannelControlDrainIncoming(s->channels[1]);
            IHS_BufferClear(&body, true);
            break;
        }
        case 'M': {
            assert(sscanf(line, "M %u %u %u %u %u %131072s", &channel, &id, &timestamp, &sent,
                          &received, raw) == 6);
            IHS_SessionFrame f = {.header = {.type = IHS_SessionPacketTypeReliable,
                                             .channelId = channel,
                                             .sendTimestamp = sent,
                                             .receiveTimestamp = received,
                                             .receiveBegin = received}};
            IHS_BufferInit(&f.body, 256, 131073);
            IHS_BufferAppendUInt8(&f.body, k_EStreamDataPacket);
            IHS_BufferAppendUInt16LE(&f.body, id);
            IHS_BufferAppendUInt32LE(&f.body, timestamp);
            IHS_BufferAppendUInt16LE(&f.body, 0);
            IHS_BufferAppendUInt32LE(&f.body, 0);
            parseHex(&f.body, raw);
            IHS_SessionDeliverReliableFrame(s, &f);
            IHS_SessionFrameClear(&f, true);
            break;
        }
        case 'K': {
            int offset;
            assert(sscanf(line, "K %d", &offset) == 1);
            s->clock.offset = offset;
            break;
        }
        case 'P':
            assert(sscanf(line, "P %u", &kind) == 1);
            playerOK = kind != 0;
            break;
        case 'A':
            assert(sscanf(line, "A %u", &kind) == 1 && device && kind <= 16384);
            outputSize = (size_t)kind * requested.channels * 2;
            output = malloc(outputSize + 32);
            assert(output);
            memset(output, 0xa5, outputSize + 32);
            productionCallback(productionContext, output, (int)outputSize);
            for (unsigned n = 0; n < 32; ++n)
                assert(output[outputSize + n] == 0xa5);
            break;
        case 'X':
            stream_media_audio_close(NULL);
            break;
        case 'S':
            break; /* Original CStreamPlayer::OnStreamStopped is exactly RET. */
        default:
            assert(false);
        }
        report(s);
    }
    free(line);
    IHS_SessionDestroy(s);
    IHS_Quit();
    stream_media_shutdown();
    assert(!device && (!jitter || !jitter->ring));
    return 0;
}
