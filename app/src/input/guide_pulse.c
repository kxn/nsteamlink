#include "guide_pulse.h"
#include <string.h>

void sl_guide_pulse_reset(sl_guide_pulse *p) {
    memset(p, 0, sizeof(*p));
}
void sl_guide_pulse_tick(sl_guide_pulse *p, bool allowed, bool request, uint64_t now,
                         sl_guide_submit_fn submit, void *context) {
    if (p->held && (!allowed || now >= p->deadline ||
                    (p->admitted && now >= p->release_at))) {
        p->held = false;
        p->releasing = true;
        p->retry_at = 0; /* Cancel/focus loss never waits for the next retry. */
    }
    if (p->releasing) {
        if (now >= p->retry_at) {
            if (submit(context, false))
                sl_guide_pulse_reset(p);
            else
                p->retry_at = now + 20;
        }
        return; /* Coalesce notifications during a pulse; no backlog. */
    }
    if (!allowed)
        return;
    if (!p->held && request) {
        p->held = true;
        p->deadline = now + 250; /* Bounded cancellation even with zero submissions. */
        p->retry_at = 0;
    }
    if (p->held && !p->admitted && now >= p->retry_at) {
        if (submit(context, true)) {
            p->admitted = true;
            /* This is pulse duration, NOT the evidence of submission. */
            p->release_at = now + 50;
        } else
            p->retry_at = now + 20;
    }
}
