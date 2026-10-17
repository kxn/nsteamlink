#pragma once
#include <stdbool.h>
#include <stdint.h>
#define SL_VIDEO_TIMING_BATCH 60
typedef struct sl_video_timing {
    unsigned count;
    float sum, samples[SL_VIDEO_TIMING_BATCH];
    int32_t budget;
} sl_video_timing;
void sl_video_timing_reset(sl_video_timing *);
void sl_video_timing_update(sl_video_timing *, uint32_t frame, uint32_t now, bool surface);
bool sl_video_timing_ready(const sl_video_timing *, uint32_t frame, uint32_t now);
int32_t sl_video_timing_wait(const sl_video_timing *, uint32_t frame, uint32_t now);

/* Original Android input-to-SDK PTS accumulator; independent of transport RX. */
typedef struct sl_video_timestamp_state { uint32_t media; uint64_t pts; } sl_video_timestamp_state;
uint64_t sl_video_timestamp_next(sl_video_timestamp_state *, uint32_t media);
