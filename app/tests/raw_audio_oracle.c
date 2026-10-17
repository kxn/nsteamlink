/* Real Raw decoder -> float jitter input. This observes decoded PCM before
 * jitter/device output; jitter playback has its own official vectors. */
#include "audio_jitter.h"
#include "media.h"
#include <SDL.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bool recording;
static uint8_t *queued;
static size_t queuedSize;
int __real_sl_audio_jitter_push(sl_audio_jitter *, const float *, int);
int __wrap_sl_audio_jitter_push(sl_audio_jitter *j, const float *data, int count) {
    if (recording) {
        assert(!queued);
        queuedSize = (size_t)count * j->channels * 2;
        queued = malloc(queuedSize ? queuedSize : 1);
        assert(queued);
        for (size_t i = 0; i < queuedSize / 2; ++i) {
            int16_t v = (int16_t)(data[i] * 32768.0f);
            memcpy(queued + 2 * i, &v, 2);
        }
    }
    return __real_sl_audio_jitter_push(j, data, count);
}
static IHS_Buffer bytes(const char *text) {
    IHS_Buffer b = {.size = strlen(text) / 2};
    b.capacity = b.size;
    b.data = malloc(b.size ? b.size : 1);
    assert(b.data);
    for (size_t i = 0; text[i]; i += 2) {
        unsigned v;
        assert(text[i + 1] && sscanf(text + i, "%2x", &v) == 1);
        b.data[i / 2] = v;
    }
    return b;
}
int main(int argc, char **argv) {
    assert(argc == 3);
    assert(setenv("SDL_AUDIODRIVER", "dummy", 1) == 0);
    assert(setenv("SDL_VIDEODRIVER", "dummy", 1) == 0);
    assert(setenv("SDL_RENDER_DRIVER", "software", 1) == 0);
    assert(stream_media_init(NULL));
    IHS_Buffer format = bytes(argv[1]), payload = bytes(argv[2]);
    /* Deliberately conflicting outer metadata: the Raw codec_data is authoritative. */
    IHS_StreamAudioConfig config = {.codec = IHS_StreamAudioCodecRaw,
                                    .frequency = 8000,
                                    .channels = 2,
                                    .codecData = IHS_BufferPointer(&format),
                                    .codecDataLen = format.size};
    assert(stream_media_audio_start(NULL, &config) == 0);
    recording = true;
    assert(stream_media_audio_submit(NULL, &payload) == 0);
    recording = false;
    stream_media_snapshot state;
    stream_media_get_snapshot(&state);
    printf("{\"frequency\":%d,\"channels\":%d,\"frames\":%u,\"samples\":%llu,\"pcm\":\"",
           state.audio_frequency, state.audio_channels, state.audio_frames,
           (unsigned long long)state.audio_decoded_samples);
    for (size_t i = 0; i < queuedSize; ++i)
        printf("%02x", queued[i]);
    puts("\"}");
    free(queued);
    stream_media_audio_stop(NULL);
    /* Malformed metadata and partial sample frames must fail cleanly. */
    config.codecDataLen = 1;
    assert(stream_media_audio_start(NULL, &config) == -1);
    config.codecDataLen = format.size;
    assert(stream_media_audio_start(NULL, &config) == 0);
    payload.size = 1;
    assert(stream_media_audio_submit(NULL, &payload) == -1);
    stream_media_audio_stop(NULL);
    free(format.data);
    free(payload.data);
    stream_media_shutdown();
    return 0;
}
