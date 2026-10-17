/* Actual Raw media start/submit -> production SDL callback -> S16 output.
 * Device runs paused for deterministic official schedules. The live mode runs
 * real SDL dummy callbacks concurrently with input and repeated stop/start. */
#include "media.h"
#include <SDL.h>
#include <assert.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static SDL_AudioDeviceID stream_device;
static SDL_AudioCallback production_callback;
static void *production_userdata;
static bool live;
static atomic_uint callbacks;
static void trampoline(void *userdata, Uint8 *data, int size) {
    production_callback(userdata, data, size);
    atomic_fetch_add(&callbacks, 1);
}
SDL_AudioDeviceID __real_SDL_OpenAudioDevice(const char *, int, const SDL_AudioSpec *,
                                             SDL_AudioSpec *, int);
void __real_SDL_PauseAudioDevice(SDL_AudioDeviceID, int);
SDL_AudioDeviceID __wrap_SDL_OpenAudioDevice(const char *name, int capture,
                                             const SDL_AudioSpec *want, SDL_AudioSpec *have,
                                             int allowed) {
    SDL_AudioSpec copy = *want;
    bool streaming = want->samples == 1024;
    if (streaming) {
        production_callback = want->callback;
        production_userdata = want->userdata;
        assert(production_callback);
        copy.callback = trampoline;
    }
    SDL_AudioDeviceID device = __real_SDL_OpenAudioDevice(name, capture, &copy, have, allowed);
    if (streaming)
        stream_device = device;
    return device;
}
void __wrap_SDL_PauseAudioDevice(SDL_AudioDeviceID device, int paused) {
    if (!live && device == stream_device && !paused)
        return;
    __real_SDL_PauseAudioDevice(device, paused);
}
static void digest(const void *data, size_t size) {
    unsigned char out[32];
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    assert(!mbedtls_sha256(data, size, out, 0));
#else
    assert(!mbedtls_sha256_ret(data, size, out, 0));
#endif
    for (unsigned i = 0; i < sizeof(out); ++i)
        printf("%02x", out[i]);
}
static void start(int rate, int channels) {
    /* CAudioFormat frequency field 2, channels field 3. */
    uint8_t format[16];
    size_t n = 0;
    format[n++] = 8;
    format[n++] = 1;
    format[n++] = 16;
    unsigned value = (unsigned)rate;
    while (value >= 128) {
        format[n++] = (value & 127) | 128;
        value >>= 7;
    }
    format[n++] = value;
    format[n++] = 24;
    format[n++] = (uint8_t)channels;
    IHS_StreamAudioConfig config = {.codec = IHS_StreamAudioCodecRaw,
                                    .frequency = (uint32_t)rate,
                                    .channels = (uint32_t)channels,
                                    .codecData = format,
                                    .codecDataLen = n};
    assert(stream_media_audio_start(NULL, &config) == 0);
}
static void push(int count, int channels, int offset, const char *kind, int16_t *pcm) {
    for (int n = 0; n < count; ++n)
        for (int ch = 0; ch < channels; ++ch) {
            int v;
            if (!strcmp(kind, "zero"))
                v = 0;
            else if (!strcmp(kind, "constant"))
                v = (ch + 1) * 2048;
            else if (!strcmp(kind, "cancel"))
                v = (((offset + n) * 37 % 257) - 128) * 128 * (ch & 1 ? -1 : 1);
            else
                v = ((((offset + n) * 37 + ch * 71) % 257) - 128) * 128;
            pcm[n * channels + ch] = (int16_t)v;
        }
    IHS_Buffer data = {.data = (void *)pcm,
                       .size = (size_t)count * channels * 2,
                       .capacity = (size_t)count * channels * 2};
    assert(!stream_media_audio_submit(NULL, &data));
}
int main(int argc, char **argv) {
    assert(argc == 3 || argc == 4);
    int rate = atoi(argv[1]), channels = atoi(argv[2]);
    live = argc == 4;
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    int16_t *pcm = malloc(65536 * 2 * 2);
    uint8_t *out = malloc(65536 * 2 * 2 + 32);
    assert(pcm && out);
    start(rate, channels);
    if (live) {
        for (int run = 0; run < 3; ++run) {
            if (run)
                start(rate, channels);
            unsigned before = atomic_load(&callbacks);
            uint64_t deadline = SDL_GetTicks64() + 3000;
            for (int n = 0; n < 300 && atomic_load(&callbacks) < before + 3; ++n) {
                push(480, channels, n * 480, "wave", pcm);
                SDL_Delay(2);
                assert(SDL_GetTicks64() < deadline);
            }
            assert(atomic_load(&callbacks) >= before + 3);
            stream_media_audio_stop(NULL); /* Decoder stop retains the device. */
            unsigned tail = atomic_load(&callbacks);
            deadline = SDL_GetTicks64() + 3000;
            while (atomic_load(&callbacks) < tail + 3) {
                SDL_Delay(2);
                assert(SDL_GetTicks64() < deadline);
            }
            if (run == 1)
                continue; /* Next prepare must join this retained callback before reuse. */
            stream_media_audio_close(NULL); /* Player close joins before ring free. */
            unsigned stopped = atomic_load(&callbacks);
            SDL_Delay(25);
            assert(atomic_load(&callbacks) == stopped);
        }
        printf("{\"launches\":3,\"callbacks\":%u}\n", atomic_load(&callbacks));
    } else {
        puts("[");
        char op[16], kind[16];
        int count, offset;
        unsigned row = 0;
        while (scanf("%15s %d %15s %d", op, &count, kind, &offset) == 4) {
            assert(count >= 0 && count <= 65536);
            size_t size = 0;
            if (!strcmp(op, "push"))
                push(count, channels, offset, kind, pcm);
            else {
                assert(!strcmp(op, "pop") || !strcmp(op, "play"));
                size = (size_t)count * channels * 2;
                assert(count <= 16384);
                memset(out, 0xa5, size + 32);
                production_callback(production_userdata, out, (int)size);
                for (int i = 0; i < 32; ++i)
                    assert(out[size + i] == 0xa5);
            }
            stream_media_snapshot state;
            stream_media_get_snapshot(&state);
            printf("%s{\"queued\":%u,\"dropped\":%u,\"pcm_sha256\":\"", row++ ? "," : "",
                   state.audio_queued_bytes, state.audio_queue_drops);
            digest(out, size);
            printf("\"}");
        }
        puts("]");
        stream_media_audio_stop(NULL);
    }
    free(pcm);
    free(out);
    stream_media_shutdown();
    return 0;
}
