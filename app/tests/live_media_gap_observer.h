/* Single-group diagnostic timeline. Fixed atomics only; no mutable decoder
 * reads, locks, packet retention, allocation, I/O or waits on runtime paths.
 * A key after a successful request is temporal evidence, not proof that the
 * request caused that key rather than the host's ordinary GOP schedule. */
#pragma once
#include <stdbool.h>

#include "ihslib/video.h"
#include "session/channels/video/ch_data_video.h"
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

typedef struct probe_gap_observer {
    atomic_uint_fast64_t loss, lost_ms;
    atomic_uint_fast64_t producer, producer_ms, calls, unscoped;
    atomic_bool producer_ready;
    atomic_uint_fast64_t sent_ms, sent, failed;
    atomic_uint_fast64_t key, key_ms, submit_ms, lost_submits;
    atomic_bool submitted;
} probe_gap_observer;
static probe_gap_observer probe_gap;
typedef struct probe_gap_scope {
    uint64_t input;
} probe_gap_scope;
static _Thread_local const probe_gap_scope *probe_gap_current;

static uint64_t probe_gap_header(unsigned channel, const uint8_t *bytes, size_t size) {
    if (channel < 3 || channel >= 32 || !bytes || size < 20 || bytes[0] != k_EStreamDataPacket)
        return 0;
    return (UINT64_C(1) << 48) | (uint64_t)channel << 40 | (uint64_t)bytes[15] << 32 |
           (uint64_t)(bytes[13] | (unsigned)bytes[14] << 8) << 16 |
           (bytes[1] | (unsigned)bytes[2] << 8);
}
static bool probe_gap_after_loss(uint64_t input, uint64_t loss) {
    uint16_t distance = (uint16_t)((input >> 16) - (loss >> 16));
    uint16_t ids = (uint16_t)(input - loss);
    return input && loss && (input >> 40) == (loss >> 40) && distance && distance < 0x8000 && ids &&
           ids < 0x8000;
}
static void probe_gap_loss(uint64_t identity, uint64_t now) {
    atomic_store(&probe_gap.lost_ms, now);
    atomic_store_explicit(&probe_gap.loss, identity, memory_order_release);
}
static void probe_gap_request(unsigned channel, uint64_t now) {
    uint64_t loss = atomic_load_explicit(&probe_gap.loss, memory_order_acquire);
    if (!loss || channel != ((loss >> 40) & 255))
        return;
    uint64_t input = probe_gap_current ? probe_gap_current->input : 0;
    if (!probe_gap_after_loss(input, loss) || ((input >> 32) & VideoFrameFlagKeyFrame)) {
        atomic_fetch_add(&probe_gap.unscoped, 1);
        return;
    }
    /* The actual video input worker is the sole writer of these first-input
     * fields. Publish before the production producer can expose its queue. */
    if (!atomic_fetch_add(&probe_gap.calls, 1)) {
        atomic_store(&probe_gap.producer, input);
        atomic_store(&probe_gap.producer_ms, now);
        atomic_store_explicit(&probe_gap.producer_ready, true, memory_order_release);
    }
}
static void probe_gap_socket(bool sent, uint64_t now) {
    if (!atomic_load_explicit(&probe_gap.producer_ready, memory_order_acquire))
        return;
    atomic_fetch_add(sent ? &probe_gap.sent : &probe_gap.failed, 1);
    if (sent) {
        uint_fast64_t expected = 0;
        atomic_compare_exchange_strong(&probe_gap.sent_ms, &expected, now);
    }
}
static void probe_gap_key(unsigned channel, const uint8_t *body, size_t size, uint64_t now) {
    if (!atomic_load(&probe_gap.sent_ms) || atomic_load(&probe_gap.key))
        return;
    uint64_t input = probe_gap_header(channel, body, size);
    if (!probe_gap_after_loss(input, atomic_load(&probe_gap.loss)) ||
        !probe_gap_after_loss(input, atomic_load(&probe_gap.producer)) ||
        !(body[15] & VideoFrameFlagKeyFrame) || !(body[15] & VideoFrameFlagFrameFinish) ||
        body[16] || body[17] || body[18] || body[19])
        return;
    /* Only this session's receive owner writes the candidate; the release
     * precedes the original complete-frame FIFO publication. */
    atomic_store(&probe_gap.key_ms, now);
    atomic_store_explicit(&probe_gap.key, input, memory_order_release);
}
static bool probe_gap_submit(uint16_t id, unsigned flags, int result, uint64_t now) {
    uint64_t loss = atomic_load_explicit(&probe_gap.loss, memory_order_acquire);
    if (loss && id == (uint16_t)loss)
        atomic_fetch_add(&probe_gap.lost_submits, 1);
    uint64_t key = atomic_load_explicit(&probe_gap.key, memory_order_acquire);
    if (!key || id != (uint16_t)key || !(flags & IHS_StreamVideoFrameKeyFrame) ||
        result != IHS_StreamVideoSubmitOK)
        return false;
    atomic_store(&probe_gap.submit_ms, now);
    atomic_store_explicit(&probe_gap.submitted, true, memory_order_release);
    return true;
}
