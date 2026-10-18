#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Original SDL_main @75cec4..c8 uses CMP/B.PL, including its N-bit wrap.
 * Only the initial transport Connecting stage is subject to this deadline. */
static inline bool sl_connection_wait_expired(bool pending, uint32_t begin, uint32_t now) {
    return pending && (uint32_t)(now - begin - 10u * 65536u) < 0x80000000u;
}
static inline uint32_t sl_connection_wait_tick(uint64_t milliseconds) {
    return (uint32_t)(milliseconds / 1000u) * 65536u +
           (uint32_t)((milliseconds % 1000u) * 65536u / 1000u);
}
