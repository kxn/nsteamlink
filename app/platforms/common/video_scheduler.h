#pragma once
#include "frame_pacer.h"
#include "video_pipeline.h"
typedef struct sl_video_scheduler {
    sl_frame_pacer control;
    sl_video_key key;
} sl_video_scheduler;
void sl_video_scheduler_init(sl_video_scheduler *, bool);
bool sl_video_scheduler_wait(sl_video_scheduler *, sl_video_pipeline *, uint64_t now);
void sl_video_scheduler_feedback(sl_video_scheduler *, sl_video_pipeline *,
    const sl_video_frame *candidate, uint64_t take_us, uint64_t submit_us, bool success);
