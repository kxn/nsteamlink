#pragma once
#include <stdbool.h>
#include <stdint.h>
#define SL_PACER_HISTORY 128
#define SL_PACER_WINDOW 16
/* CPU CLOCK_MONOTONIC only. Input clock and output capacity are independent. */
typedef struct sl_pacer_period {
    uint64_t last;
    double samples[SL_PACER_WINDOW], value, jitter, phase;
    unsigned count, cursor;
} sl_pacer_period;
typedef struct sl_frame_pacer {
    sl_pacer_period input, output;
    struct { uint64_t seq, us; bool presented; } history[SL_PACER_HISTORY];
    uint64_t available, settled, last_presented;
    uint64_t last_submit, last_call, last_empty;
    uint64_t wait_deadline;
    /* No diagnostic storage or updates in release; never feeds decisions. */
#if NSL_DIAGNOSTICS
    uint64_t presented, settled_presented, deferred, unobserved, holdovers;
    uint64_t diag_last, diag_ready_us, diag_wait_us, diag_first_input, diag_start_us;
    bool diag_ready, diag_wait;
#endif
    unsigned window_a, window_p, early, input_run, slow_outputs, fast_outputs;
    double late_need, extra_guard;
    bool enabled, gated, last_gated, active;
} sl_frame_pacer;
void sl_pacer_reset(sl_frame_pacer *, bool enabled);
void sl_pacer_publish(sl_frame_pacer *, uint64_t seq, uint64_t us);
bool sl_pacer_wait(sl_frame_pacer *, uint64_t now, uint64_t pending_seq);
void sl_pacer_submit(sl_frame_pacer *, uint64_t seq, uint64_t take_us,
                     uint64_t submit_us, bool success);
/* Called after the candidate's submit outcome, never during recording. */
void sl_pacer_settle(sl_frame_pacer *, bool finish);
