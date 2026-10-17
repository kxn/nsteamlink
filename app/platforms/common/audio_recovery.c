/* Official Android 1.3.32 CStreamDecoderOpus::DecodeFrame 7b1414..7b16fc,
 * docs/STEAMLINK_PROTOCOL_RE.md §72. This is codec recovery, not type11 FEC. */
#include "audio_recovery.h"

void sl_audio_recovery_reset(sl_audio_recovery *state) {
    *state = (sl_audio_recovery){.first = true};
}

int sl_audio_recovery_run(sl_audio_recovery *state, uint16_t id, uint32_t timestamp,
                          int (*decode)(void *, const sl_audio_decode_step *), void *context) {
    if (state->first) {
        state->next = id;
        state->first = false;
    }
    uint16_t behind = (uint16_t)(state->next - id);
    if (behind && behind < 0x8000u) /* original int16(next-current) > 0 */
        return 0;
    int result = 0;
    while (state->next != id) {
        bool last = (uint16_t)(state->next + 1u) == id;
        sl_audio_decode_step step = {.id = state->next,
                                     .timestamp = timestamp,
                                     .max_samples = 480,
                                     .use_packet = last,
                                     .fec = last};
        if (decode(context, &step))
            result = -1;
        state->next++;
    }
    state->next = (uint16_t)(id + 1u); /* advances before current-packet decode */
    sl_audio_decode_step step = {
        .id = id, .timestamp = timestamp, .max_samples = 5760, .use_packet = true};
    if (decode(context, &step))
        result = -1;
    return result;
}
