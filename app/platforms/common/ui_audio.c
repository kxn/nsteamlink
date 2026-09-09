#include "ui_audio.h"
#include <SDL.h>
#include <math.h>
#include <stdatomic.h>
#include <string.h>
#define RATE        48000
#define CUE_SAMPLES 5760
static SDL_AudioDeviceID device;
static int16_t tones[SL_CUE_COUNT][CUE_SAMPLES];
static int lengths[SL_CUE_COUNT];
static atomic_int pending;
static atomic_bool enabled = true;
static bool prepared;
static struct {
    int kind;
    double at;
} voices[4];
static unsigned next_voice;
/* UI callback and stream submit are mutually exclusive owners. The device is
 * closed/joined before media transfers ownership under audio_lock. */
void sl_audio_mix(int16_t *out, int frames, int rate, int channels) {
    bool audible = atomic_load(&enabled);
    int cue = atomic_exchange(&pending, SL_CUE_NONE);
    if (!audible) {
        memset(voices, 0, sizeof(voices));
        return;
    }
    if (cue > SL_CUE_NONE && cue < SL_CUE_COUNT) {
        unsigned v = next_voice++ % 4;
        voices[v].kind = cue;
        voices[v].at = 0;
    }
    bool active = false;
    for (int v = 0; v < 4; ++v)
        active |= voices[v].kind != 0;
    if (!active)
        return; /* No sample loop, conversion, gain change, or queue. */
    if (rate <= 0 || channels < 1 || channels > 2)
        return;
    for (int frame = 0; frame < frames; ++frame) {
        int tone = 0;
        for (int v = 0; v < 4; ++v)
            if (voices[v].kind) {
                tone += tones[voices[v].kind][(int)voices[v].at];
                voices[v].at += (double)RATE / rate;
                if (voices[v].at >= lengths[voices[v].kind])
                    voices[v].kind = 0;
            }
        for (int c = 0; c < channels; ++c) {
            int sample = out[frame * channels + c] + tone;
            out[frame * channels + c] = sample > 32767 ? 32767 : sample < -32768 ? -32768 : sample;
        }
    }
}
static void callback(void *ctx, Uint8 *bytes, int length) {
    (void)ctx;
    memset(bytes, 0, length);
    sl_audio_mix((int16_t *)bytes, length / 4, RATE, 2);
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
    if (!prepared) {
        make_tones();
        prepared = true;
    }
    memset(voices, 0, sizeof(voices));
    next_voice = 0;
    atomic_store(&pending, SL_CUE_NONE);
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
void sl_audio_suspend(void) {
    if (device) {
        SDL_CloseAudioDevice(device);
        device = 0;
    }
    memset(voices, 0, sizeof(voices));
    atomic_store(&pending, SL_CUE_NONE);
}
void sl_audio_shutdown(void) {
    sl_audio_suspend();
}
void sl_audio_feedback(sl_ui_cue cue, bool on) {
    atomic_store(&enabled, on);
    if (!on)
        atomic_store(&pending, SL_CUE_NONE);
    else if (cue > SL_CUE_NONE && cue < SL_CUE_COUNT)
        atomic_store(&pending, cue);
}
