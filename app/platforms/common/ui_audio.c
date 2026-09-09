#include "ui_audio.h"
#include <SDL.h>
#include <math.h>
#include <stdatomic.h>
#include <string.h>
#define RATE        48000
#define CAP         32768
#define CUE_SAMPLES 5760
static SDL_AudioDeviceID device;
static SDL_AudioStream *converter;
static int input_rate = RATE, input_channels = 2;
static int16_t ring[CAP], tones[SL_CUE_COUNT][CUE_SAMPLES];
static unsigned read_at, used;
static int lengths[SL_CUE_COUNT];
static atomic_int pending;
static atomic_bool enabled;
static struct {
    int kind, at;
} voices[4];
static unsigned next_voice;
static void callback(void *ctx, Uint8 *bytes, int length) {
    (void)ctx;
    int16_t *out = (int16_t *)bytes;
    memset(bytes, 0, length);
    bool audible = atomic_load(&enabled);
    int cue = atomic_exchange(&pending, SL_CUE_NONE);
    if (!audible)
        memset(voices, 0, sizeof(voices));
    else if (cue > SL_CUE_NONE && cue < SL_CUE_COUNT) {
        unsigned v = next_voice++ % 4;
        voices[v].kind = cue;
        voices[v].at = 0;
    }
    for (int i = 0; i + 1 < length / 2; i += 2) {
        int tone = 0;
        for (int v = 0; v < 4; ++v)
            if (voices[v].kind) {
                tone += tones[voices[v].kind][voices[v].at++];
                if (voices[v].at >= lengths[voices[v].kind])
                    voices[v].kind = 0;
            }
        for (int c = 0; c < 2; ++c) {
            int sample = 0;
            if (used) {
                sample = ring[read_at];
                read_at = (read_at + 1) % CAP;
                --used;
            }
            sample += tone;
            out[i + c] = sample > 32767 ? 32767 : sample < -32768 ? -32768 : sample;
        }
    }
}
static void make_tones(void) {
    for (int kind = 1; kind < SL_CUE_COUNT; ++kind) {
        int count = kind == SL_CUE_MOVE ? 1920 : kind == SL_CUE_CONFIRM ? 4800 : 3360;
        lengths[kind] = count;
        for (int i = 0; i < count; ++i) {
            double t = (double)i / RATE, u = (double)i / count;
            double hz = kind == SL_CUE_MOVE     ? 1050
                        : kind == SL_CUE_BACK   ? 610
                        : kind == SL_CUE_TOGGLE ? 920
                                                : 830;
            double envelope = fmin(1., t / .004) * pow(1. - u, 2.5);
            double wave = sin(6.283185307 * hz * t) + .18 * sin(6.283185307 * hz * 2 * t);
            if (kind == SL_CUE_CONFIRM && t > .026) {
                double dt = t - .026;
                wave += .8 * fmin(1., dt / .004) * sin(6.283185307 * 1245 * dt);
            }
            tones[kind][i] = (int16_t)(wave * envelope * (kind == SL_CUE_MOVE ? 1400 : 2000));
        }
    }
}
bool sl_audio_init(void) {
    if (device)
        return true;
    make_tones();
    read_at = used = next_voice = 0;
    memset(voices, 0, sizeof(voices));
    atomic_store(&pending, SL_CUE_NONE);
    atomic_store(&enabled, true);
    SDL_AudioSpec want = {.freq = RATE,
                          .format = AUDIO_S16SYS,
                          .channels = 2,
                          .samples = 512,
                          .callback = callback},
                  have;
    device = SDL_OpenAudioDevice(NULL, 0, &want, &have, SDL_AUDIO_ALLOW_SAMPLES_CHANGE);
    if (!device)
        return false;
    if (have.freq != RATE || have.format != AUDIO_S16SYS || have.channels != 2) {
        SDL_CloseAudioDevice(device);
        device = 0;
        return false;
    }
    SDL_PauseAudioDevice(device, 0);
    return true;
}
void sl_audio_shutdown(void) {
    if (device) {
        SDL_CloseAudioDevice(device);
        device = 0;
    }
    SDL_FreeAudioStream(converter);
    converter = NULL;
    atomic_store(&pending, SL_CUE_NONE);
}
void sl_audio_clear(void) {
    if (device) {
        SDL_LockAudioDevice(device);
        used = read_at = 0;
        SDL_UnlockAudioDevice(device);
    }
    if (converter)
        SDL_AudioStreamClear(converter);
}
bool sl_audio_configure(int frequency, int channels) {
    if (!device && !sl_audio_init())
        return false;
    SDL_AudioStream *next =
        SDL_NewAudioStream(AUDIO_S16LSB, channels, frequency, AUDIO_S16SYS, 2, RATE);
    if (!next)
        return false;
    sl_audio_clear();
    SDL_FreeAudioStream(converter);
    converter = next;
    input_rate = frequency;
    input_channels = channels;
    return true;
}
uint32_t sl_audio_queued(void) {
    if (!device)
        return 0;
    SDL_LockAudioDevice(device);
    unsigned n = used;
    SDL_UnlockAudioDevice(device);
    return (uint32_t)((uint64_t)n * input_rate * input_channels / (RATE * 2)) * 2;
}
int sl_audio_queue(const void *pcm, uint32_t bytes) {
    if (!converter || !device || SDL_AudioStreamPut(converter, pcm, bytes))
        return -1;
    int16_t buffer[4096];
    int n;
    while ((n = SDL_AudioStreamGet(converter, buffer, sizeof(buffer))) > 0) {
        unsigned count = (unsigned)n / 2;
        SDL_LockAudioDevice(device);
        if (count > CAP - used)
            used = read_at = 0;
        for (unsigned i = 0; i < count; ++i)
            ring[(read_at + used + i) % CAP] = buffer[i];
        used += count;
        SDL_UnlockAudioDevice(device);
    }
    return n < 0 ? -1 : 0;
}
void sl_audio_feedback(sl_ui_cue cue, bool on) {
    atomic_store(&enabled, on);
    if (!on)
        atomic_store(&pending, SL_CUE_NONE);
    else if (cue > SL_CUE_NONE && cue < SL_CUE_COUNT)
        atomic_store(&pending, cue);
}
