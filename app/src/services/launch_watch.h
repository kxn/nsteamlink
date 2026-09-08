#pragma once
#include <stdbool.h>
#include <stdint.h>
/* No wall-clock/frame timeout is evidence of game completion. State is owned
 * by one connection and protected by runtime.lock. */
typedef struct sl_launch_watch {
    uint64_t target;
    uint32_t stamp, frame_floor;
    int kind;
    bool target_active, played, running_seen, have_stamp;
    unsigned empty_statuses;
} sl_launch_watch;
static inline void sl_launch_activity(sl_launch_watch *s, int kind, uint64_t id,
                                      uint32_t displayed) {
    if (s->kind == kind && s->target_active == (kind == 2 && id == s->target))
        return;
    s->kind = kind;
    s->target_active = s->target && kind == 2 && id == s->target;
    s->frame_floor = displayed;
    s->empty_statuses = 0;
}
static inline void sl_launch_frame(sl_launch_watch *s, uint32_t displayed) {
    if (s->target_active && displayed > s->frame_floor)
        s->played = true;
}
static inline void sl_launch_status(sl_launch_watch *s, bool present, bool running,
                                    bool timestamp_present, uint32_t stamp) {
    if (!present || !timestamp_present) {
        s->empty_statuses = 0;
        return;
    }
    if (s->have_stamp && (int32_t)(stamp - s->stamp) <= 0)
        return;
    s->have_stamp = true;
    s->stamp = stamp;
    if (s->target_active && s->played && running)
        s->running_seen = true;
    if (!running && s->kind == 3 && s->played && s->running_seen) {
        if (s->empty_statuses < 2)
            ++s->empty_statuses;
    } else
        s->empty_statuses = 0;
}
static inline bool sl_launch_finished(const sl_launch_watch *s) {
    return s->target && s->kind == 3 && s->played && s->running_seen && s->empty_statuses == 2;
}
