/* Observe the actual production recovery function's callbacks. This is not a
 * codec, PCM, worker, socket or device execution. Encoding has no C padding. */
#include "audio_recovery.h"
#include "crypto.h"
#include "endianness.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { MAX_STEPS = 32769, TOKEN_SIZE = 12 };
static uint8_t tokens[MAX_STEPS * TOKEN_SIZE];
static unsigned steps;
static int observe(void *unused, const sl_audio_decode_step *step) {
    (void)unused;
    assert(steps < MAX_STEPS);
    uint8_t *p = tokens + (steps++) * TOKEN_SIZE;
    IHS_WriteUInt16LE(p, step->id);
    IHS_WriteUInt32LE(p + 2, step->timestamp);
    IHS_WriteUInt32LE(p + 6, (uint32_t)step->max_samples);
    p[10] = step->use_packet;
    p[11] = step->fec;
    return 0;
}
static void hex(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i)
        printf("%02x", p[i]);
}
int main(void) {
    sl_audio_recovery state;
    sl_audio_recovery_reset(&state);
    char line[128];
    while (fgets(line, sizeof(line), stdin)) {
        steps = 0;
        if (line[0] == 'R')
            sl_audio_recovery_reset(&state);
        else {
            unsigned id, timestamp;
            assert(sscanf(line, "F %u %u", &id, &timestamp) == 2 && id <= UINT16_MAX);
            assert(sl_audio_recovery_run(&state, (uint16_t)id, timestamp, observe, NULL) == 0);
        }
        uint8_t sha[IHS_CRYPTO_SHA256_SIZE];
        assert(!IHS_CryptoSHA256(tokens, steps * TOKEN_SIZE, sha));
        printf("{\"first\":%s,\"next\":%u,\"steps\":%u,\"trace_sha256\":\"",
               state.first ? "true" : "false", state.next, steps);
        hex(sha, sizeof(sha));
        printf("\",\"first_step\":\"");
        if (steps)
            hex(tokens, TOKEN_SIZE);
        printf("\",\"last_step\":\"");
        if (steps)
            hex(tokens + (steps - 1) * TOKEN_SIZE, TOKEN_SIZE);
        puts("\"}");
    }
    return 0;
}
