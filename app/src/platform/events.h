#pragma once
#include <stdbool.h>
#include <stdint.h>
/* Application lifecycle facts; input payload adaptation stays platform-private. */
void sl_events_init(void);
void sl_events_shutdown(void);
bool sl_events_foreground(void);
bool sl_events_keyboard_focus(void);
bool sl_events_exit_requested(void);
/* Main owner only. Capture redirects only while allowed; false restores the
 * system screenshot notification path. Failure never arms Guide intents. */
bool sl_events_capture_guide(bool allowed);
/* At most one pending short-press intent; no physical down/up/hold semantics. */
bool sl_events_take_capture_guide(void);
#if NSL_DIAGNOSTICS && defined(__SWITCH__)
/* Offline virtual-controller probe owns notification routing temporarily. */
bool sl_events_capture_probe_begin(void);
unsigned sl_events_capture_probe_messages(void);
bool sl_events_capture_probe_end(void);
/* Explicit offline diagnostic only; driven by the existing application loop. */
bool sl_events_capture_selftest_tick(uint64_t now_ms);
#endif
