#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef struct sl_audio_recovery {
    uint16_t next;
    bool first;
} sl_audio_recovery;

typedef struct sl_audio_decode_step {
    uint16_t id;
    uint32_t timestamp;
    int max_samples;
    bool use_packet, fec;
} sl_audio_decode_step;

void sl_audio_recovery_reset(sl_audio_recovery *);
/* Caller serializes decoder ownership. Callback performs one actual decode and
 * submits valid PCM; errors do not prevent the remaining official steps. */
int sl_audio_recovery_run(sl_audio_recovery *, uint16_t id, uint32_t timestamp,
                          int (*decode)(void *, const sl_audio_decode_step *), void *);
