/* Real complete-frame dispatch -> audio FIFO/worker -> app Opus -> SDL queue.
 * Wrappers observe actual recovery callbacks, codec arguments/results and PCM.
 * Every consumer is stopped/joined before SDL/session dependencies are freed. */
#include "audio_jitter.h"
#include "audio_recovery.h"
#include "crypto.h"
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
#include <math.h>
#include <opus.h>
#include <opus_multistream.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct decode_record {
    sl_audio_decode_step step;
    char payload[8192];
    int result;
} decode_record;
typedef struct pcm_record {
    sl_audio_decode_step step;
    uint8_t *data;
    uint32_t size;
} pcm_record;
typedef struct observation {
    sl_audio_recovery state;
    decode_record decodes[64];
    pcm_record pcm[64];
    unsigned count, outputs;
    IHS_StreamAudioFrameInfo info;
} observation;
static observation observed[64];
static observation *current;
static sl_audio_decode_step activeStep;
static sl_audio_recovery recovery;
static unsigned decoderConfig[6], decoderConfigCount;
static atomic_uint started, completed, stopped;
static bool legacy, guard, stop_probe;
static unsigned pause_index;
static IHS_Thread *audio_worker;
static atomic_uint codec_blocked, codec_release, codec_calls;
static atomic_uint join_entered, join_returned, decoder_destroyed, remove_done;
static uint8_t stop_tokens[32769 * 12];
static unsigned stop_steps;
static void wait_for(atomic_uint *value, unsigned target);

void __real_IHS_ThreadJoin(IHS_Thread *);
void __wrap_IHS_ThreadJoin(IHS_Thread *thread) {
    bool watched = stop_probe && thread == audio_worker;
    if (watched) {
        assert(atomic_load(&codec_blocked) && !atomic_load(&decoder_destroyed));
        assert(atomic_load(&completed) == 1);
        atomic_store(&join_entered, 1);
    }
    __real_IHS_ThreadJoin(thread);
    if (watched) {
        assert(atomic_load(&completed) == 2 && !atomic_load(&decoder_destroyed));
        atomic_store(&join_returned, 1);
    }
}
void __real_opus_multistream_decoder_destroy(OpusMSDecoder *);
void __wrap_opus_multistream_decoder_destroy(OpusMSDecoder *decoder) {
    if (stop_probe) {
        assert(atomic_load(&join_returned) && atomic_load(&completed) == 2);
        atomic_fetch_add(&decoder_destroyed, 1);
    }
    __real_opus_multistream_decoder_destroy(decoder);
}
static void *remove_channel(void *context) {
    IHS_SessionChannelRemove(context, 3);
    atomic_store(&remove_done, 1);
    return NULL;
}
static int (*forwardDecode)(void *, const sl_audio_decode_step *);
static void *forwardContext;

void __real_sl_audio_recovery_reset(sl_audio_recovery *);
void __wrap_sl_audio_recovery_reset(sl_audio_recovery *s) {
    __real_sl_audio_recovery_reset(s);
    recovery = *s;
}
static int record_step(void *unused, const sl_audio_decode_step *step) {
    (void)unused;
    activeStep = *step;
    if (stop_probe && atomic_load(&completed) == 1) {
        assert(stop_steps < 32769);
        uint8_t *p = stop_tokens + stop_steps++ * 12;
        p[0] = step->id;
        p[1] = step->id >> 8;
        for (unsigned i = 0; i < 4; ++i) {
            p[2 + i] = step->timestamp >> (8 * i);
            p[6 + i] = (uint32_t)step->max_samples >> (8 * i);
        }
        p[10] = step->use_packet;
        p[11] = step->fec;
    }
    return forwardDecode(forwardContext, step);
}
int __real_sl_audio_recovery_run(sl_audio_recovery *, uint16_t, uint32_t,
                                 int (*)(void *, const sl_audio_decode_step *), void *);
int __wrap_sl_audio_recovery_run(sl_audio_recovery *s, uint16_t id, uint32_t timestamp,
                                 int (*fn)(void *, const sl_audio_decode_step *), void *ctx) {
    forwardDecode = fn;
    forwardContext = ctx;
    int result = __real_sl_audio_recovery_run(s, id, timestamp, record_step, NULL);
    recovery = *s;
    return result;
}
OpusMSDecoder *__real_opus_multistream_decoder_create(opus_int32, int, int, int,
                                                      const unsigned char *, int *);
OpusMSDecoder *__wrap_opus_multistream_decoder_create(opus_int32 rate, int channels, int streams,
                                                      int coupled, const unsigned char *mapping,
                                                      int *error) {
    decoderConfig[0] = rate;
    decoderConfig[1] = channels;
    decoderConfig[2] = streams;
    decoderConfig[3] = coupled;
    assert(channels == 1 || channels == 2);
    for (int i = 0; i < channels; ++i)
        decoderConfig[4 + i] = mapping[i];
    decoderConfigCount = 4 + channels;
    return __real_opus_multistream_decoder_create(rate, channels, streams, coupled, mapping, error);
}
int __real_opus_multistream_decode_float(OpusMSDecoder *, const unsigned char *, opus_int32,
                                         float *, int, int);
int __wrap_opus_multistream_decode_float(OpusMSDecoder *d, const unsigned char *packet,
                                         opus_int32 size, float *pcm, int maxSamples, int fec) {
    if (stop_probe && atomic_load(&completed) == 1) {
        if (atomic_fetch_add(&codec_calls, 1) == pause_index) {
            atomic_store(&codec_blocked, 1);
            wait_for(&codec_release, 1); /* Fixture gate, never a product wait. */
            assert(atomic_load(&join_entered) && !atomic_load(&decoder_destroyed));
        }
    }
    if (guard)
        return __real_opus_multistream_decode_float(d, packet, size, pcm, maxSamples, fec);
    assert(current && current->count < 64 && size >= 0 && size < 4096);
    decode_record *r = &current->decodes[current->count++];
    r->step = activeStep;
    r->step.max_samples = maxSamples;
    r->step.fec = fec;
    for (int i = 0; i < size; ++i)
        sprintf(r->payload + 2 * i, "%02x", packet[i]);
    r->result = __real_opus_multistream_decode_float(d, packet, size, pcm, maxSamples, fec);
    return r->result;
}
SDL_AudioDeviceID __real_SDL_OpenAudioDevice(const char *, int, const SDL_AudioSpec *,
                                             SDL_AudioSpec *, int);
void __real_SDL_PauseAudioDevice(SDL_AudioDeviceID, int);
static SDL_AudioDeviceID controlled_device;
SDL_AudioDeviceID __wrap_SDL_OpenAudioDevice(const char *name, int capture,
                                             const SDL_AudioSpec *want, SDL_AudioSpec *have,
                                             int allowed) {
    SDL_AudioDeviceID id = __real_SDL_OpenAudioDevice(name, capture, want, have, allowed);
    if (guard && want->samples == 1024)
        controlled_device = id;
    return id;
}
void __wrap_SDL_PauseAudioDevice(SDL_AudioDeviceID device, int paused) {
    if (guard && device == controlled_device && !paused)
        return; /* Real SDL device remains paused before first callback. */
    __real_SDL_PauseAudioDevice(device, paused);
}
int __real_sl_audio_jitter_push(sl_audio_jitter *, const float *, int);
int __wrap_sl_audio_jitter_push(sl_audio_jitter *j, const float *pcm, int count) {
    if (!guard) {
        assert(current && current->outputs < 64);
        pcm_record *r = &current->pcm[current->outputs++];
        r->step = activeStep;
        r->size = (unsigned)count * j->channels * 2;
        r->data = malloc(r->size ? r->size : 1);
        assert(r->data);
        for (unsigned i = 0; i < r->size / 2; ++i) {
            float v = pcm[i] * 32768.0f;
            int16_t sample = v >= 32767.0f ? 32767 : v <= -32768.0f ? -32768 : (int16_t)lrintf(v);
            memcpy(r->data + i * 2, &sample, 2);
        }
    }
    return __real_sl_audio_jitter_push(j, pcm, count);
}
static int audio_start(IHS_Session *s, const IHS_StreamAudioConfig *config, void *unused) {
    (void)unused;
    int result = stream_media_audio_start(s, config);
    atomic_fetch_add(&started, 1);
    return result;
}
static int audio_frame(IHS_Session *s, const IHS_StreamAudioFrameInfo *info, IHS_Buffer *b,
                       void *ctx) {
    (void)ctx;
    current->info = *info;
    int result = stream_media_audio_submit_frame(s, info, b);
    current->state = recovery;
    atomic_fetch_add(&completed, 1);
    return result;
}
static int audio_legacy(IHS_Session *s, IHS_Buffer *b, void *ctx) {
    (void)ctx;
    assert(legacy); /* New submitFrame takes precedence when both are supplied. */
    activeStep = (sl_audio_decode_step){.max_samples = 5760, .use_packet = true};
    int result = stream_media_audio_submit(s, b);
    current->state = recovery;
    atomic_fetch_add(&completed, 1);
    return result;
}
static void audio_stop(IHS_Session *s, void *unused) {
    (void)unused;
    if (stop_probe)
        assert(atomic_load(&join_returned) && atomic_load(&completed) == 2);
    stream_media_audio_stop(s);
    atomic_fetch_add(&stopped, 1);
}
static void wait_for(atomic_uint *value, unsigned target) {
    /* Fixture bound for a full half-range PLC burst under sanitizers; this
     * does not change any product timeout or recovery policy. */
    uint64_t until = SDL_GetTicks64() + (guard ? 15000 : 3000);
    while (atomic_load(value) < target && SDL_GetTicks64() < until)
        usleep(1000);
    assert(atomic_load(value) == target);
}
static IHS_SessionChannel *configure(IHS_Session *s, unsigned channels) {
    CStartAudioDataMsg m = CSTART_AUDIO_DATA_MSG__INIT;
    m.has_codec = m.has_channels = m.has_frequency = true;
    m.channel = 3;
    m.codec = 3;
    m.frequency = 48000;
    m.channels = channels;
    IHS_SessionChannel *ch = IHS_SessionChannelDataAudioCreate(s, &m);
    assert(ch);
    IHS_SessionChannelAdd(s, ch);
    wait_for(&started, atomic_load(&stopped) + 1);
    return ch;
}
int main(int argc, char **argv) {
    assert(argc == 2 || argc == 3);
    legacy = argc == 3 && strcmp(argv[2], "legacy") == 0;
    guard = argc == 3 && strcmp(argv[2], "guard") == 0;
    stop_probe = argc == 3 && strncmp(argv[2], "stop-", 5) == 0;
    if (stop_probe) {
        char *end;
        unsigned long value = strtoul(argv[2] + 5, &end, 10);
        assert(!*end && value <= 32768);
        pause_index = (unsigned)value;
        guard = true;
    }
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    IHS_Init();
    assert(stream_media_init(NULL));
    IHS_Session *s = IHS_TestSessionCreate();
    IHS_TimerTaskStopImmediate(s->retransmission.timer);
    s->state.connectionState = IHS_SessionConnectionStateConnected;
    IHS_MutexLock(s->clock.lock);
    s->clock.offset = 100;
    IHS_MutexUnlock(s->clock.lock);
    IHS_StreamAudioCallbacks callbacks = {.start = audio_start,
                                          .submit = audio_legacy,
                                          .stop = audio_stop,
                                          .submitFrame = legacy ? NULL : audio_frame};
    IHS_SessionSetAudioCallbacks(s, &callbacks, NULL);
    unsigned channels = (unsigned)atoi(argv[1]);
    IHS_SessionChannel *ch = configure(s, channels);
    audio_worker = ((IHS_SessionChannelData *)ch)->worker;
    assert(audio_worker);
    unsigned rows = 0, fed = 0;
    char line[8192];
    while (fgets(line, sizeof(line), stdin)) {
        assert(rows < 64);
        current = &observed[rows++];
        if (line[0] == 'R') {
            IHS_SessionChannelRemove(s, ch->id);
            ch = configure(s, channels);
            current->state = recovery;
        } else {
            unsigned id, stamp;
            char hex[4096];
            assert(sscanf(line, "F %u %u %4095s", &id, &stamp, hex) == 3);
            IHS_SessionFrame f = {.header = {.type = IHS_SessionPacketTypeReliable,
                                             .channelId = 3,
                                             .sendTimestamp = stamp + 100,
                                             .receiveBegin = stamp + 300,
                                             .receiveTimestamp = stamp + 400}};
            IHS_BufferInit(&f.body, 4096, 65536);
            IHS_BufferAppendUInt8(&f.body, k_EStreamDataPacket);
            IHS_BufferAppendUInt16LE(&f.body, (uint16_t)id);
            IHS_BufferAppendUInt32LE(&f.body, stamp + 100);
            IHS_BufferAppendUInt16LE(&f.body, 0);
            IHS_BufferAppendUInt32LE(&f.body, 0);
            for (size_t i = 0; hex[i]; i += 2) {
                unsigned v;
                assert(hex[i + 1] && sscanf(hex + i, "%2x", &v) == 1);
                IHS_BufferAppendUInt8(&f.body, (uint8_t)v);
            }
            assert(IHS_SessionDeliverReliableFrame(s, &f) == IHS_ReliableData);
            IHS_BufferClear(&f.body, true);
            ++fed;
            if (stop_probe && fed == 2) {
                wait_for(&codec_blocked, 1);
                pthread_t remover;
                assert(!pthread_create(&remover, NULL, remove_channel, s));
                wait_for(&join_entered, 1);
                assert(!atomic_load(&join_returned) && !atomic_load(&remove_done));
                assert(!atomic_load(&decoder_destroyed) && atomic_load(&completed) == 1);
                atomic_store(&codec_release, 1);
                assert(!pthread_join(remover, NULL));
                assert(atomic_load(&remove_done) && atomic_load(&join_returned));
                assert(atomic_load(&decoder_destroyed) == 1 && atomic_load(&stopped) == 1);
                assert(atomic_load(&completed) == 2 && stop_steps == 32769);
                ch = NULL;
            } else {
                wait_for(&completed, fed);
            }
        }
    }
    stream_media_snapshot snapshot;
    stream_media_get_snapshot(&snapshot);
    if (ch)
        IHS_SessionChannelRemove(s, ch->id);
    assert(atomic_load(&started) == atomic_load(&stopped));
    IHS_SessionDestroy(s);
    IHS_Quit();
    stream_media_shutdown();
    if (stop_probe) {
        assert(rows == 2 && fed == 2 && snapshot.audio_frames == 32770);
        uint8_t sha[32];
        assert(!IHS_CryptoSHA256(stop_tokens, stop_steps * 12, sha));
        printf("{\"pause_index\":%u,\"steps\":%u,\"frames\":%u,\"errors\":%u,"
               "\"joined\":%u,\"destroyed\":%u,\"trace_sha256\":\"",
               pause_index, stop_steps, snapshot.audio_frames, snapshot.audio_decode_errors,
               atomic_load(&join_returned), atomic_load(&decoder_destroyed));
        for (unsigned i = 0; i < sizeof(sha); ++i)
            printf("%02x", sha[i]);
        puts("\"}");
        return 0;
    }
    if (guard) {
        printf("{\"frames\":%u,\"queued\":%u,\"drops\":%u,\"errors\":%u}\n", snapshot.audio_frames,
               snapshot.audio_queued_bytes, snapshot.audio_queue_drops,
               snapshot.audio_decode_errors);
        return 0;
    }
    puts("[");
    for (unsigned n = 0; n < rows; ++n) {
        observation *o = &observed[n];
        printf("%s{\"first\":%s,\"next\":%u,\"backend\":\"%s\",\"info\":[%u,%u],\"config\":[",
               n ? "," : "", o->state.first ? "true" : "false", o->state.next,
               opus_get_version_string(), o->info.id, o->info.timestamp);
        for (unsigned i = 0; i < decoderConfigCount; ++i)
            printf("%s%u", i ? "," : "", decoderConfig[i]);
        printf("],\"decodes\":[");
        for (unsigned i = 0; i < o->count; ++i) {
            decode_record *r = &o->decodes[i];
            printf("%s{\"id\":%u,\"timestamp\":%u,\"max_samples\":%d,\"fec\":%d,"
                   "\"payload\":\"%s\",\"result\":%d}",
                   i ? "," : "", r->step.id, r->step.timestamp, r->step.max_samples, r->step.fec,
                   r->payload, r->result);
        }
        printf("],\"submitted\":[");
        for (unsigned i = 0; i < o->outputs; ++i) {
            pcm_record *r = &o->pcm[i];
            printf("%s{\"id\":%u,\"timestamp\":%u,\"pcm\":\"", i ? "," : "", r->step.id,
                   r->step.timestamp);
            for (unsigned j = 0; j < r->size; ++j)
                printf("%02x", r->data[j]);
            printf("\"}");
            free(r->data);
        }
        printf("]}");
    }
    puts("]");
    return 0;
}
