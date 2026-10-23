#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Main input owner only. A true submit result means local queue admission,
 * never a transport ACK or proof the host opened its overlay. */
typedef bool (*sl_guide_submit_fn)(void *context, bool pressed);
typedef struct sl_guide_pulse {
    bool held, admitted, releasing;
    uint64_t deadline, release_at, retry_at;
} sl_guide_pulse;
void sl_guide_pulse_tick(sl_guide_pulse *, bool allowed, bool request, uint64_t now_ms,
                         sl_guide_submit_fn, void *context);
/* Only after neutralizing/detaching the old session's canonical input state. */
void sl_guide_pulse_reset(sl_guide_pulse *);
