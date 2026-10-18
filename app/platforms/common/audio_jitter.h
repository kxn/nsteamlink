#pragma once
#include <stdbool.h>
#include <stdint.h>

#define SL_AUDIO_JITTER_CAPACITY 16384

typedef struct sl_audio_jitter {
    int params[10];
    int channels, write, read;
    bool priming, overrun;
    int tracked_write, attempts;
    float fade, fade_step, cross, cross_step;
    int alternate_read;
    float table[1024];
    uint32_t dropped, missing;
    int last_queued, min, max, mean, variance;
    uint32_t expands, shrinks, underflow_fades;
    int running_min, running_max, observations, interval;
    float running_mean, running_m2;
    int adjustment;
    float *ring;
} sl_audio_jitter;

/* Official float jitter strategy (§73). Caller serializes Push/Pop/Destroy.
 * Initialization allocates once; Push and Pop allocate/log nothing. */
bool sl_audio_jitter_init(sl_audio_jitter *, int frequency, int channels);
void sl_audio_jitter_destroy(sl_audio_jitter *);
int sl_audio_jitter_queued(const sl_audio_jitter *);
int sl_audio_jitter_push(sl_audio_jitter *, const float *, int frames);
int sl_audio_jitter_pop(sl_audio_jitter *, float *, int frames);
