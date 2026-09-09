#include "frame_lifetime.h"
#include <limits.h>

void sl_resource_init(sl_resource_ref *r, void (*finalize)(void *), void *context) {
    atomic_init(&r->references, 1);
    r->finalize = finalize;
    r->context = context;
}
bool sl_resource_retain(sl_resource_ref *r) {
    unsigned refs = atomic_load_explicit(&r->references, memory_order_relaxed);
    while (refs && refs != UINT_MAX) {
        if (atomic_compare_exchange_weak_explicit(&r->references, &refs, refs + 1,
                                                  memory_order_relaxed, memory_order_relaxed))
            return true;
    }
    return false;
}
bool sl_resource_release(sl_resource_ref *r) {
    unsigned refs = atomic_load_explicit(&r->references, memory_order_relaxed);
    while (refs) {
        if (atomic_compare_exchange_weak_explicit(&r->references, &refs, refs - 1,
                                                  memory_order_acq_rel, memory_order_relaxed)) {
            if (refs == 1 && r->finalize)
                r->finalize(r->context);
            /* The finalizer may have freed r. */
            return true;
        }
    }
    return false;
}
void sl_batch_init(sl_gpu_batch *b, sl_resource_ref **storage, size_t capacity) {
    *b = (sl_gpu_batch){.resources = storage, .capacity = storage ? capacity : 0};
}
bool sl_batch_begin(sl_gpu_batch *b, uint64_t serial) {
    if (b->state != SL_BATCH_FREE || !serial || serial <= b->serial)
        return false;
    b->serial = serial;
    b->state = SL_BATCH_RECORDING;
    return true;
}
bool sl_batch_pin(sl_gpu_batch *b, sl_resource_ref *r) {
    if (b->state != SL_BATCH_RECORDING || !r)
        return false;
    for (size_t i = 0; i < b->count; ++i)
        if (b->resources[i] == r)
            return true;
    if (b->count == b->capacity || !sl_resource_retain(r))
        return false;
    b->resources[b->count++] = r;
    return true;
}
static void release_resources(sl_gpu_batch *b) {
    /* Keep the batch unavailable during finalizers. */
    b->state = SL_BATCH_RELEASING;
    while (b->count) {
        sl_resource_ref *r = b->resources[--b->count];
        b->resources[b->count] = NULL;
        sl_resource_release(r);
    }
    b->state = SL_BATCH_FREE;
}
bool sl_batch_cancel(sl_gpu_batch *b) {
    if (b->state != SL_BATCH_RECORDING)
        return false;
    release_resources(b);
    return true;
}
bool sl_batch_submit(sl_gpu_batch *b) {
    if (b->state != SL_BATCH_RECORDING)
        return false;
    b->state = SL_BATCH_SUBMITTED;
    return true;
}
bool sl_batch_quarantine(sl_gpu_batch *b) {
    if (b->state != SL_BATCH_SUBMITTED)
        return false;
    b->state = SL_BATCH_QUARANTINED;
    return true;
}
bool sl_batch_complete(sl_gpu_batch *b, uint64_t serial) {
    if (b->state != SL_BATCH_SUBMITTED || b->serial != serial)
        return false;
    release_resources(b);
    return true;
}
bool sl_batch_device_stopped(sl_gpu_batch *b, uint64_t serial) {
    if ((b->state != SL_BATCH_SUBMITTED && b->state != SL_BATCH_QUARANTINED) ||
        b->serial != serial)
        return false;
    release_resources(b);
    return true;
}
