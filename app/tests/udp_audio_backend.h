/* Actual session audio callbacks, decoder worker, fixed Opus, jitter and SDL2.
 * Observe borrowed calls without changing packets/results or pausing the device.
 * Only atomics run in the device callback; PCM observations stay on decoder. */
#include "audio_jitter.h"
#include "audio_recovery.h"
#include "media.h"
#include <SDL.h>
#include <math.h>
#include <opus_multistream.h>

static bool udpAudioEnabled;
static atomic_uint audFrames, audCalls, audStarts, audStops, audPlayed;
static _Thread_local sl_audio_decode_step audStep;
static _Thread_local uint32_t audOffset;
static struct {
    unsigned id, timestamp, next, first;
} audInputs[256];
static struct {
    sl_audio_decode_step step;
    char payload[8192];
    int result;
    uint8_t pcm[5760 * 2 * 2];
    size_t bytes;
} audRecords[256];
static unsigned audConfig[6];
static unsigned audQueuedCount;
static struct {
    size_t bytes;
    uint8_t pcm[5760 * 2 * 2];
} audQueued[256];
static SDL_AudioSpec audSpec;
typedef struct AudForward {
    int (*callback)(void *, const sl_audio_decode_step *);
    void *context;
} AudForward;
static int audForward(void *opaque, const sl_audio_decode_step *step) {
    AudForward *f = opaque;
    audStep = *step;
    return f->callback(f->context, step);
}
int __real_sl_audio_recovery_run(sl_audio_recovery *, uint16_t, uint32_t,
                                 int (*)(void *, const sl_audio_decode_step *), void *);
int __wrap_sl_audio_recovery_run(sl_audio_recovery *r, uint16_t id, uint32_t stamp,
                                 int (*callback)(void *, const sl_audio_decode_step *),
                                 void *context) {
    if (!udpAudioEnabled)
        return __real_sl_audio_recovery_run(r, id, stamp, callback, context);
    AudForward f = {callback, context};
    int result = __real_sl_audio_recovery_run(r, id, stamp, audForward, &f);
    unsigned n = atomic_load(&audFrames);
    assert(n < 256);
    audInputs[n].next = r->next;
    audInputs[n].first = r->first;
    return result;
}
OpusMSDecoder *__real_opus_multistream_decoder_create(opus_int32, int, int, int,
                                                      const unsigned char *, int *);
OpusMSDecoder *__wrap_opus_multistream_decoder_create(opus_int32 rate, int channels, int streams,
                                                      int coupled, const unsigned char *mapping,
                                                      int *error) {
    if (udpAudioEnabled) {
        assert(channels == 2);
        audConfig[0] = rate;
        audConfig[1] = channels;
        audConfig[2] = streams;
        audConfig[3] = coupled;
        audConfig[4] = mapping[0];
        audConfig[5] = mapping[1];
    }
    return __real_opus_multistream_decoder_create(rate, channels, streams, coupled, mapping, error);
}
int __real_opus_multistream_decode_float(OpusMSDecoder *, const unsigned char *, opus_int32,
                                         float *, int, int);
int __wrap_opus_multistream_decode_float(OpusMSDecoder *d, const unsigned char *p, opus_int32 bytes,
                                         float *out, int maximum, int fec) {
    if (!udpAudioEnabled)
        return __real_opus_multistream_decode_float(d, p, bytes, out, maximum, fec);
    unsigned n = atomic_load(&audCalls);
    assert(n < 256 && bytes >= 0 && bytes < 4096);
    audRecords[n].step = audStep;
    audRecords[n].step.timestamp += audOffset;
    audRecords[n].step.max_samples = maximum;
    audRecords[n].step.fec = fec;
    for (int i = 0; i < bytes; ++i)
        sprintf(audRecords[n].payload + i * 2, "%02x", p[i]);
    int result = __real_opus_multistream_decode_float(d, p, bytes, out, maximum, fec);
    audRecords[n].result = result;
    if (result >= 0 && result <= maximum) {
        audRecords[n].bytes = (size_t)result * 2 * 2;
        assert(audRecords[n].bytes <= sizeof(audRecords[n].pcm));
        for (int i = 0; i < result * 2; ++i) {
            float v = out[i] * 32768.0f;
            int16_t sample = v >= 32767 ? 32767 : v <= -32768 ? -32768 : (int16_t)lrintf(v);
            audRecords[n].pcm[2 * i] = (uint8_t)sample;
            audRecords[n].pcm[2 * i + 1] = (uint8_t)((uint16_t)sample >> 8);
        }
    }
    atomic_fetch_add(&audCalls, 1);
    return result;
}
int __real_sl_audio_jitter_pop(sl_audio_jitter *, float *, int);
int __real_sl_audio_jitter_push(sl_audio_jitter *, const float *, int);
int __wrap_sl_audio_jitter_push(sl_audio_jitter *j, const float *pcm, int frames) {
    if (udpAudioEnabled) {
        unsigned n = audQueuedCount++;
        assert(n < 256 && frames >= 0 && frames <= 5760 && j->channels == 2);
        audQueued[n].bytes = (size_t)frames * j->channels * 2;
        for (int i = 0; i < frames * j->channels; ++i) {
            float v = pcm[i] * 32768.0f;
            int16_t sample = v >= 32767 ? 32767 : v <= -32768 ? -32768 : (int16_t)lrintf(v);
            audQueued[n].pcm[2 * i] = (uint8_t)sample;
            audQueued[n].pcm[2 * i + 1] = (uint8_t)((uint16_t)sample >> 8);
        }
    }
    return __real_sl_audio_jitter_push(j, pcm, frames);
}
int __wrap_sl_audio_jitter_pop(sl_audio_jitter *j, float *out, int count) {
    int result = __real_sl_audio_jitter_pop(j, out, count);
    if (udpAudioEnabled && result > 0)
        atomic_fetch_add(&audPlayed, (unsigned)result);
    return result;
}
SDL_AudioDeviceID __real_SDL_OpenAudioDevice(const char *, int, const SDL_AudioSpec *,
                                             SDL_AudioSpec *, int);
SDL_AudioDeviceID __wrap_SDL_OpenAudioDevice(const char *name, int capture,
                                             const SDL_AudioSpec *want, SDL_AudioSpec *have,
                                             int allowed) {
    if (udpAudioEnabled && want->samples == 1024)
        audSpec = *want;
    return __real_SDL_OpenAudioDevice(name, capture, want, have, allowed);
}
static int audPrepare(IHS_Session *s, const IHS_StreamAudioConfig *c, void *ctx) {
    return sl_media_audio_callbacks()->prepare(s, c, ctx);
}
static int audStart(IHS_Session *s, const IHS_StreamAudioConfig *c, void *ctx) {
    int result = sl_media_audio_callbacks()->start(s, c, ctx);
    atomic_fetch_add(&audStarts, 1);
    return result;
}
static int audSubmit(IHS_Session *s, const IHS_StreamAudioFrameInfo *info, IHS_Buffer *b,
                     void *ctx) {
    unsigned n = atomic_load(&audFrames);
    assert(n < 256);
    audOffset = (uint32_t)IHS_StreamClockOffset(&s->clock);
    audInputs[n].id = info->id;
    audInputs[n].timestamp = info->timestamp + audOffset;
    int result = sl_media_audio_callbacks()->submitFrame(s, info, b, ctx);
    atomic_fetch_add(&audFrames, 1);
    return result;
}
static void audStop(IHS_Session *s, void *ctx) {
    sl_media_audio_callbacks()->stop(s, ctx);
    atomic_fetch_add(&audStops, 1);
}
static void audInstall(IHS_Session *session) {
    assert(stream_media_init(NULL));
    udpAudioEnabled = true;
    static const IHS_StreamAudioCallbacks callbacks = {
        .prepare = audPrepare, .start = audStart, .submitFrame = audSubmit, .stop = audStop};
    IHS_SessionSetAudioCallbacks(session, &callbacks, NULL);
}
static void audReport(unsigned frames, unsigned calls, bool blocked) {
    assert(atomic_load(&audFrames) == frames && atomic_load(&audCalls) == calls);
    assert(atomic_load(&audStarts) == 1 && atomic_load(&audStops) == 1);
    assert(blocked || atomic_load(&audPlayed) > 0);
    assert(audSpec.freq == 48000 && audSpec.channels == 2 && audSpec.format == AUDIO_S16LSB);
    printf(",\"audio\":{\"config\":[");
    for (unsigned n = 0; n < 6; ++n)
        printf("%s%u", n ? "," : "", audConfig[n]);
    printf("],\"backend\":\"%s\",\"frames\":[", opus_get_version_string());
    for (unsigned n = 0; n < frames; ++n)
        printf("%s{\"id\":%u,\"timestamp\":%u,\"first\":%s,\"next\":%u}", n ? "," : "",
               audInputs[n].id, audInputs[n].timestamp, audInputs[n].first ? "true" : "false",
               audInputs[n].next);
    printf("],\"decodes\":[");
    for (unsigned n = 0; n < calls; ++n) {
        sl_audio_decode_step *s = &audRecords[n].step;
        printf("%s{\"id\":%u,\"timestamp\":%u,\"max_samples\":%d,\"fec\":%d,\"payload\":\"%s\","
               "\"result\":%d,\"pcm\":\"",
               n ? "," : "", s->id, s->timestamp, s->max_samples, s->fec, audRecords[n].payload,
               audRecords[n].result);
        for (size_t i = 0; i < audRecords[n].bytes; ++i)
            printf("%02x", audRecords[n].pcm[i]);
        printf("\"}");
    }
    printf("],\"queued\":[");
    for (unsigned n = 0; n < audQueuedCount; ++n) {
        printf("%s\"", n ? "," : "");
        for (size_t i = 0; i < audQueued[n].bytes; ++i)
            printf("%02x", audQueued[n].pcm[i]);
        printf("\"");
    }
    printf("],\"played\":%u,\"starts\":1,\"stops\":1}", atomic_load(&audPlayed));
}
