#pragma once
#include <stdbool.h>
/* Media thread only, after pending HID writes and before SDL teardown. */
#if defined(__SWITCH__) || defined(NSL_RUMBLE_TEST)
void sl_rumble_tick(bool session_active);
#else
static inline void sl_rumble_tick(bool session_active) {
    (void)session_active;
}
#endif
