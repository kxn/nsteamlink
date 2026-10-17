/* Original CFrameJitterTracker: fixed Video constructor batch of 60. */
#include "video_timing.h"
#include <math.h>
#include <string.h>
static float age_ms(uint32_t frame, uint32_t now) {
    uint32_t delta = now - frame;
    bool negative = (int32_t)delta < 0;
    uint32_t magnitude = negative ? 0u - delta : delta;
    float value = (float)((magnitude >> 16) * 1000u) +
                  (float)((magnitude & 65535u) * 1000u) / 65536.0f;
    return negative ? -value : value;
}
void sl_video_timing_reset(sl_video_timing *t) { memset(t, 0, sizeof(*t)); }
void sl_video_timing_update(sl_video_timing *t, uint32_t frame, uint32_t now, bool surface) {
    if (surface) return;
    float age = age_ms(frame, now);
    if (age < 0) return;
    if (age > 150.0f) { t->count = 0; t->sum = 0; return; }
    t->sum += age;
    t->samples[t->count++] = age;
    if (t->count != SL_VIDEO_TIMING_BATCH) return;
    float mean = t->sum / (float)t->count;
    float squared = 0;
    unsigned vectorEnd = t->count & ~7u;
    for (unsigned n = 0; n < vectorEnd; ++n) {
        float delta = t->samples[n] - mean;
        volatile float square = delta * delta;
        squared += square;
    }
    for (unsigned n = vectorEnd; n < t->count; ++n) {
        float delta = t->samples[n] - mean;
        squared = fmaf(delta, delta, squared);
    }
    float stddev = sqrtf(squared / (float)(t->count - 1));
    int32_t budget = (int32_t)fmaf(stddev, 2.0f, mean);
    if (t->budget) budget = (t->budget + budget) / 2;
    t->budget = budget;
    t->count = 0;
    t->sum = 0;
}
bool sl_video_timing_ready(const sl_video_timing *t, uint32_t frame, uint32_t now) {
    return !t->budget || age_ms(frame, now) >= (float)t->budget;
}
int32_t sl_video_timing_wait(const sl_video_timing *t, uint32_t frame, uint32_t now) {
    if (!t->budget) return 0;
    int32_t wait = t->budget - (int32_t)age_ms(frame, now);
    return wait > 0 ? wait : 0;
}
