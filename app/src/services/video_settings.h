#pragma once
#include <stdbool.h>
#include <stdint.h>
#ifndef NSL_TEST_FORCE_1080
#define NSL_TEST_FORCE_1080 0
#endif

/* Application policy, independent of host-written streaming_settings.bin and
 * profile.bin. A session's effective caps must never turn Auto into fixed 720p. */
typedef enum sl_resolution {
    SL_RESOLUTION_AUTO = 0,
    SL_RESOLUTION_720 = 720,
    SL_RESOLUTION_1080 = 1080,
} sl_resolution;

static inline bool sl_resolution_valid(unsigned value) {
    return value == SL_RESOLUTION_AUTO || value == SL_RESOLUTION_720 || value == SL_RESOLUTION_1080;
}
static inline unsigned sl_resolution_height(sl_resolution mode, bool docked) {
    if (NSL_TEST_FORCE_1080)
        return 1080; /* Build-only test override; never persisted to video.conf. */
    return mode == SL_RESOLUTION_1080 || (mode == SL_RESOLUTION_AUTO && docked) ? 1080 : 720;
}
sl_resolution sl_video_settings_load(const char *directory);
bool sl_video_settings_save(const char *directory, sl_resolution);
