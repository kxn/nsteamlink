#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

/* CPU ownership only. Finalizers run on the thread releasing the last reference.
 * GPU objects must therefore be released exclusively by the renderer. Frame
 * finalizers may run on another thread, but must not destroy a codec/session.
 * Reinitialize only after the finalizer has returned and the owner has made the
 * storage available again. Retain requires an existing reference or owner lock. */
typedef struct sl_resource_ref {
    atomic_uint references;
    void (*finalize)(void *);
    void *context;
} sl_resource_ref;

void sl_resource_init(sl_resource_ref *, void (*finalize)(void *), void *context);
bool sl_resource_retain(sl_resource_ref *);
bool sl_resource_release(sl_resource_ref *);

typedef enum {
    SL_BATCH_FREE,
    SL_BATCH_RECORDING,
    SL_BATCH_SUBMITTED,
    SL_BATCH_QUARANTINED,
    SL_BATCH_RELEASING
} sl_batch_state;

/* Renderer-thread-only. Storage is caller-owned, reserved before acquire.
 * A pin protects a concrete immutable resource/version, not a mutable cache key.
 * Every pin must precede the first command that refers to the resource. */
typedef struct sl_gpu_batch {
    sl_batch_state state;
    uint64_t serial;
    sl_resource_ref **resources;
    size_t count, capacity;
} sl_gpu_batch;

void sl_batch_init(sl_gpu_batch *, sl_resource_ref **storage, size_t capacity);
bool sl_batch_begin(sl_gpu_batch *, uint64_t serial);
bool sl_batch_pin(sl_gpu_batch *, sl_resource_ref *);
bool sl_batch_cancel(sl_gpu_batch *); /* Recording only; no commands entered queue. */
bool sl_batch_submit(sl_gpu_batch *); /* Immediately before first queue submission. */
bool sl_batch_quarantine(sl_gpu_batch *); /* Submitted without provable completion. */
bool sl_batch_complete(sl_gpu_batch *, uint64_t serial); /* Verified matching fence. */
/* Caller must have independent SDK evidence that the device no longer accesses
 * any resource. A timeout is NOT that evidence. */
bool sl_batch_device_stopped(sl_gpu_batch *, uint64_t serial);
