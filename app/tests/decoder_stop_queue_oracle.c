/* Real complete-frame FIFO/worker/Opus with controlled entry/codec/idle gates.
 * All wrappers forward production calls. Fixture gates never enter product code. */
#include "audio_jitter.h"
#include "audio_recovery.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "ihslib.h"
#include "media.h"
#include "session/channels/ch_data.h"
#include "session/channels/ch_data_audio.h"
#include "session/reliable.h"
#include "test_session.h"
#include <SDL.h>
#include <assert.h>
#include <opus_multistream.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct frame {
    unsigned id, stamp;
    uint8_t payload[3];
} frame;
static frame initial[32], pending[32], after;
static unsigned initial_count, pending_count;
static enum { ENTRY, DECODE, THINK } stage;
static IHS_Thread *audio_worker;
static IHS_ThreadFunction *worker_fn;
static void *worker_context;
static IHS_SessionChannelData *channel;
static atomic_uint entry_ready, entry_release, gate_ready, gate_release, join_entered;
static atomic_uint worker_returned, join_returned, destroyed, stopped, event_count;
static const char *events[16];
static unsigned consumed[64][3], decoded[64][6], outputs[64][3], releases[64], thinks[64];
static unsigned consume_count, decode_count, output_count, release_count, think_count;
static sl_audio_decode_step active_step;
static _Thread_local bool releasing;
static _Thread_local uint16_t release_id;
static SDL_AudioDeviceID controlled_device;
static unsigned device_closed, queue_after, bytes_after;

static void wait_for(atomic_uint *value) {
    uint64_t deadline = SDL_GetTicks64() + 15000;
    while (!atomic_load(value) && SDL_GetTicks64() < deadline)
        usleep(1000);
    assert(atomic_load(value));
}
static void event(const char *name) {
    unsigned n = atomic_fetch_add(&event_count, 1);
    assert(n < 16);
    events[n] = name;
}
static void worker(void *unused) {
    (void)unused;
    atomic_store(&entry_ready, 1);
    wait_for(&entry_release);
    worker_fn(worker_context);
    event("consumer_return");
    atomic_store(&worker_returned, 1);
}
IHS_Thread *__real_IHS_ThreadCreate(IHS_ThreadFunction *, const char *, void *);
IHS_Thread *__wrap_IHS_ThreadCreate(IHS_ThreadFunction *fn, const char *name, void *context) {
    if (strcmp(name, "IHSAudio"))
        return __real_IHS_ThreadCreate(fn, name, context);
    worker_fn = fn;
    worker_context = context;
    audio_worker = __real_IHS_ThreadCreate(worker, name, NULL);
    return audio_worker;
}
void __real_IHS_ThreadJoin(IHS_Thread *);
void __wrap_IHS_ThreadJoin(IHS_Thread *thread) {
    bool watched = thread && thread == audio_worker;
    if (watched) {
        assert(channel->interrupted && !atomic_load(&destroyed));
        event("join_enter");
        atomic_store(&join_entered, 1);
    }
    __real_IHS_ThreadJoin(thread);
    if (watched) {
        assert(atomic_load(&worker_returned) && !atomic_load(&destroyed));
        event("join_return");
        atomic_store(&join_returned, 1);
    }
}
uint32_t __real_IHS_SessionChannelDataThink(IHS_SessionChannel *);
uint32_t __wrap_IHS_SessionChannelDataThink(IHS_SessionChannel *ch) {
    assert(think_count < 64);
    thinks[think_count++] = !channel->interrupted;
    uint32_t result = __real_IHS_SessionChannelDataThink(ch);
    if (stage == THINK && !atomic_load(&gate_ready)) {
        atomic_store(&gate_ready, 1);
        wait_for(&gate_release);
    }
    return result;
}
void __real_IHS_SessionChannelDataReceiveFrame(IHS_SessionChannelData *, IHS_SessionFrame *);
void __wrap_IHS_SessionChannelDataReceiveFrame(IHS_SessionChannelData *ch, IHS_SessionFrame *f) {
    assert(!releasing && f->body.size >= 14);
    uint8_t *p = IHS_BufferPointer(&f->body);
    release_id = (uint16_t)p[1] | (uint16_t)p[2] << 8;
    releasing = true;
    __real_IHS_SessionChannelDataReceiveFrame(ch, f);
}
void __real_IHS_SessionPacketsWindowReleaseFrame(IHS_SessionFrame *);
void __wrap_IHS_SessionPacketsWindowReleaseFrame(IHS_SessionFrame *f) {
    if (releasing) {
        assert(release_count < 64);
        releases[release_count++] = release_id;
        releasing = false;
    }
    __real_IHS_SessionPacketsWindowReleaseFrame(f);
}
static int (*forward_step)(void *, const sl_audio_decode_step *);
static void *forward_context;
static int observe_step(void *unused, const sl_audio_decode_step *step) {
    (void)unused;
    active_step = *step;
    return forward_step(forward_context, step);
}
int __real_sl_audio_recovery_run(sl_audio_recovery *, uint16_t, uint32_t,
                                 int (*)(void *, const sl_audio_decode_step *), void *);
int __wrap_sl_audio_recovery_run(sl_audio_recovery *s, uint16_t id, uint32_t stamp,
                                 int (*fn)(void *, const sl_audio_decode_step *), void *context) {
    forward_step = fn;
    forward_context = context;
    return __real_sl_audio_recovery_run(s, id, stamp, observe_step, NULL);
}
int __real_opus_multistream_decode_float(OpusMSDecoder *, const unsigned char *, opus_int32,
                                         float *, int, int);
int __wrap_opus_multistream_decode_float(OpusMSDecoder *d, const unsigned char *packet,
                                         opus_int32 size, float *pcm, int max_samples, int fec) {
    assert(consume_count);
    if (stage == DECODE && !atomic_load(&gate_ready) &&
        consumed[consume_count - 1][0] == initial[initial_count - 1].id) {
        atomic_store(&gate_ready, 1);
        wait_for(&gate_release);
    }
    assert(!atomic_load(&destroyed) && decode_count < 64);
    unsigned *row = decoded[decode_count++];
    row[0] = active_step.id;
    row[1] = active_step.timestamp;
    row[2] = max_samples;
    row[3] = !!packet;
    row[4] = fec;
    int result = __real_opus_multistream_decode_float(d, packet, size, pcm, max_samples, fec);
    assert(result == 480);
    row[5] = (unsigned)result;
    return result;
}
int __real_sl_audio_jitter_push(sl_audio_jitter *, const float *, int);
int __wrap_sl_audio_jitter_push(sl_audio_jitter *j, const float *pcm, int samples) {
    assert(output_count < 64);
    unsigned *row = outputs[output_count++];
    row[0] = active_step.id;
    row[1] = active_step.timestamp;
    row[2] = samples;
    return __real_sl_audio_jitter_push(j, pcm, samples);
}
void __real_opus_multistream_decoder_destroy(OpusMSDecoder *);
void __wrap_opus_multistream_decoder_destroy(OpusMSDecoder *decoder) {
    assert(atomic_load(&join_returned) && !atomic_load(&destroyed));
    event("stop_codec");
    __real_opus_multistream_decoder_destroy(decoder);
    atomic_store(&destroyed, 1);
}
SDL_AudioDeviceID __real_SDL_OpenAudioDevice(const char *, int, const SDL_AudioSpec *,
                                             SDL_AudioSpec *, int);
SDL_AudioDeviceID __wrap_SDL_OpenAudioDevice(const char *name, int capture,
                                             const SDL_AudioSpec *want, SDL_AudioSpec *have,
                                             int allowed) {
    SDL_AudioDeviceID id = __real_SDL_OpenAudioDevice(name, capture, want, have, allowed);
    if (want->samples == 1024)
        controlled_device = id;
    return id;
}
void __real_SDL_PauseAudioDevice(SDL_AudioDeviceID, int);
void __wrap_SDL_PauseAudioDevice(SDL_AudioDeviceID device, int paused) {
    if (device == controlled_device && !paused)
        return;
    __real_SDL_PauseAudioDevice(device, paused);
}
void __real_SDL_CloseAudioDevice(SDL_AudioDeviceID);
void __wrap_SDL_CloseAudioDevice(SDL_AudioDeviceID device) {
    if (device == controlled_device)
        ++device_closed;
    __real_SDL_CloseAudioDevice(device);
}
static int start(IHS_Session *s, const IHS_StreamAudioConfig *config, void *unused) {
    (void)unused;
    return stream_media_audio_start(s, config);
}
static int submit(IHS_Session *s, const IHS_StreamAudioFrameInfo *info, IHS_Buffer *body,
                  void *unused) {
    (void)unused;
    assert(consume_count < 64);
    unsigned *row = consumed[consume_count++];
    row[0] = info->id;
    row[1] = info->timestamp;
    row[2] = !channel->interrupted;
    return stream_media_audio_submit_frame(s, info, body);
}
static void stop(IHS_Session *s, void *unused) {
    (void)unused;
    assert(atomic_load(&join_returned) && !device_closed);
    queue_after = channel->fecQueuedCount;
    bytes_after = channel->fecQueuedBytes;
    assert(!queue_after && !bytes_after);
    stream_media_audio_stop(s);
    assert(atomic_load(&destroyed) == 1 && !device_closed);
    atomic_store(&stopped, 1);
}
static void *remove_channel(void *context) {
    IHS_SessionChannelRemove(context, 3);
    return NULL;
}
static void feed(IHS_Session *s, const frame *input) {
    IHS_SessionFrame f = {.header = {.type = IHS_SessionPacketTypeReliable,
                                     .channelId = 3,
                                     .sendTimestamp = input->stamp + 100,
                                     .receiveBegin = input->stamp + 400,
                                     .receiveTimestamp = input->stamp + 400}};
    IHS_BufferInit(&f.body, 64, 65536);
    IHS_BufferAppendUInt8(&f.body, k_EStreamDataPacket);
    IHS_BufferAppendUInt16LE(&f.body, (uint16_t)input->id);
    IHS_BufferAppendUInt32LE(&f.body, input->stamp);
    IHS_BufferAppendUInt16LE(&f.body, 0);
    IHS_BufferAppendUInt32LE(&f.body, 0);
    IHS_BufferAppendMem(&f.body, input->payload, sizeof(input->payload));
    assert(IHS_SessionDeliverReliableFrame(s, &f) == IHS_ReliableData);
    IHS_BufferClear(&f.body, true);
}
static unsigned queued(void) {
    IHS_MutexLock(channel->windowLock);
    unsigned n = channel->fecQueuedCount;
    IHS_MutexUnlock(channel->windowLock);
    return n;
}
static void rows(const char *name, unsigned *data, unsigned count, unsigned width) {
    printf("\"%s\":[", name);
    for (unsigned i = 0; i < count; ++i) {
        printf("%s[", i ? "," : "");
        for (unsigned j = 0; j < width; ++j)
            printf("%s%u", j ? "," : "", data[i * width + j]);
        printf("]");
    }
    printf("]");
}
int main(int argc, char **argv) {
    assert(argc == 2);
    stage = !strcmp(argv[1], "entry") ? ENTRY : !strcmp(argv[1], "decode") ? DECODE : THINK;
    assert(stage != THINK || !strcmp(argv[1], "think"));
    char kind, hex[16];
    unsigned id, stamp;
    while (scanf(" %c %u %u %15s", &kind, &id, &stamp, hex) == 4) {
        frame *f;
        if (kind == 'I') {
            assert(initial_count < 32);
            f = &initial[initial_count++];
        } else if (kind == 'P') {
            assert(pending_count < 32);
            f = &pending[pending_count++];
        } else {
            assert(kind == 'A');
            f = &after;
        }
        assert(id <= 65535 && !strcmp(hex, "f0fffe"));
        *f = (frame){.id = id, .stamp = stamp, .payload = {0xf0, 0xff, 0xfe}};
    }
    assert(stage != DECODE || initial_count);
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    IHS_Init();
    assert(stream_media_init(NULL));
    IHS_Session *s = IHS_TestSessionCreate();
    IHS_TimerTaskStopImmediate(s->retransmission.timer);
    s->state.connectionState = IHS_SessionConnectionStateConnected;
    IHS_StreamAudioCallbacks callbacks = {.start = start, .submitFrame = submit, .stop = stop};
    IHS_SessionSetAudioCallbacks(s, &callbacks, NULL);
    CStartAudioDataMsg m = CSTART_AUDIO_DATA_MSG__INIT;
    m.has_codec = m.has_channels = m.has_frequency = true;
    m.channel = 3;
    m.codec = 3;
    m.channels = 2;
    m.frequency = 48000;
    IHS_SessionChannel *ch = IHS_SessionChannelDataAudioCreate(s, &m);
    assert(ch);
    channel = (void *)ch;
    IHS_SessionChannelAdd(s, ch);
    wait_for(&entry_ready);
    for (unsigned i = 0; i < initial_count; ++i)
        feed(s, &initial[i]);
    if (stage != ENTRY) {
        atomic_store(&entry_release, 1);
        wait_for(&gate_ready);
    }
    for (unsigned i = 0; i < pending_count; ++i)
        feed(s, &pending[i]);
    unsigned admitted = queued();
    pthread_t remover;
    assert(!pthread_create(&remover, NULL, remove_channel, s));
    wait_for(&join_entered);
    assert(channel->interrupted && !atomic_load(&join_returned));
    feed(s, &after);
    assert(queued() == admitted);
    atomic_store(&entry_release, 1);
    atomic_store(&gate_release, 1);
    assert(!pthread_join(remover, NULL));
    assert(atomic_load(&stopped) && atomic_load(&destroyed));
    stream_media_snapshot snapshot;
    stream_media_get_snapshot(&snapshot);
    assert(!device_closed && snapshot.audio_decode_errors == 0);
    IHS_SessionDestroy(s);
    IHS_Quit();
    stream_media_shutdown();
    assert(device_closed == 1);
    printf("{");
    rows("consumed", &consumed[0][0], consume_count, 3);
    printf(",");
    rows("decoded", &decoded[0][0], decode_count, 6);
    printf(",");
    rows("outputs", &outputs[0][0], output_count, 3);
    printf(",\"released\":[");
    for (unsigned i = 0; i < release_count; ++i)
        printf("%s%u", i ? "," : "", releases[i]);
    printf("],\"thinks\":[");
    for (unsigned i = 0; i < think_count; ++i)
        printf("%s%u", i ? "," : "", thinks[i]);
    printf("],\"events\":[");
    for (unsigned i = 0; i < atomic_load(&event_count); ++i)
        printf("%s\"%s\"", i ? "," : "", events[i]);
    printf("],\"admitted_count\":%u,\"queue_after\":%u,\"bytes_after\":%u,"
           "\"codec_after\":false,\"player_retained\":true,\"device_closed\":%u,\"queued_audio\":%"
           "u}\n",
           admitted, queue_after, bytes_after, device_closed, snapshot.audio_queued_bytes);
    return 0;
}
