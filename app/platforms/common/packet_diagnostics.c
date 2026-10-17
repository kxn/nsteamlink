#include "packet_diagnostics.h"
#if NSL_DIAGNOSTICS
#include <stdatomic.h>
#include <string.h>
static atomic_uint_fast64_t watched_peer, raw_total;
static atomic_uint_fast64_t raw_media[32], admitted[32], recovery[32];
void sl_packet_diagnostics_begin(uint64_t peer) {
    /* Runtime joins the previous session's workers before starting a new one. */
    atomic_store_explicit(&watched_peer, 0, memory_order_relaxed);
    atomic_store_explicit(&raw_total, 0, memory_order_relaxed);
    for (unsigned i = 0; i < 32; ++i) {
        atomic_store_explicit(&raw_media[i], 0, memory_order_relaxed);
        atomic_store_explicit(&admitted[i], 0, memory_order_relaxed);
        atomic_store_explicit(&recovery[i], 0, memory_order_relaxed);
    }
    atomic_store_explicit(&watched_peer, peer, memory_order_relaxed);
}
void sl_packet_diagnostics_raw(uint64_t peer, unsigned channel, bool media) {
    if (!peer || peer != atomic_load_explicit(&watched_peer, memory_order_relaxed))
        return;
    atomic_fetch_add_explicit(&raw_total, 1, memory_order_relaxed);
    if (media && channel < 32)
        atomic_fetch_add_explicit(&raw_media[channel], 1, memory_order_relaxed);
}
void sl_packet_diagnostics_admit(unsigned channel) {
    if (channel < 32)
        atomic_fetch_add_explicit(&admitted[channel], 1, memory_order_relaxed);
}
void sl_packet_diagnostics_recovery(unsigned channel) {
    if (channel < 32)
        atomic_fetch_add_explicit(&recovery[channel], 1, memory_order_relaxed);
}
void sl_packet_diagnostics_read(sl_packet_snapshot *out) {
    memset(out, 0, sizeof(*out));
    out->active = atomic_load_explicit(&watched_peer, memory_order_relaxed) != 0;
    out->raw_total = atomic_load_explicit(&raw_total, memory_order_relaxed);
    for (unsigned i = 0; i < 32; ++i) {
        out->raw_media[i] = atomic_load_explicit(&raw_media[i], memory_order_relaxed);
        out->admitted[i] = atomic_load_explicit(&admitted[i], memory_order_relaxed);
        out->recovery[i] = atomic_load_explicit(&recovery[i], memory_order_relaxed);
    }
}
#endif
