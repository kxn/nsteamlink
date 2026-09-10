#include "frame_lifetime.h"
#include "app_lifecycle.h"
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>

typedef struct resource {
    sl_resource_ref ref;
    int *destroyed;
    sl_gpu_batch *batch;
} resource;
static void finalize(void *context) {
    resource *r = context;
    ++*r->destroyed;
    if (r->batch) {
        assert(r->batch->state == SL_BATCH_RELEASING);
        assert(!sl_batch_begin(r->batch, 100));
        assert(!sl_batch_cancel(r->batch));
        assert(!sl_batch_pin(r->batch, &r->ref));
    }
    free(r);
}
static resource *make_resource(int *destroyed) {
    resource *r = calloc(1, sizeof(*r));
    assert(r);
    r->destroyed = destroyed;
    sl_resource_init(&r->ref, finalize, r);
    return r;
}
static void batches(void) {
    int destroyed = 0;
    sl_resource_ref *slots[2][1];
    sl_gpu_batch a, b;
    sl_batch_init(&a, slots[0], 1);
    sl_batch_init(&b, slots[1], 1);
    resource *r = make_resource(&destroyed), *extra = make_resource(&destroyed);
    assert(sl_batch_begin(&a, 1));
    assert(sl_batch_pin(&a, &r->ref));
    assert(sl_batch_pin(&a, &r->ref)); /* dedup */
    assert(a.count == 1);
    assert(!sl_batch_pin(&a, &extra->ref));
    assert(atomic_load(&extra->ref.references) == 1);
    assert(sl_batch_begin(&b, 2));
    assert(sl_batch_pin(&b, &r->ref));
    assert(sl_resource_release(&r->ref)); /* drop current while recording */
    assert(destroyed == 0);
    assert(sl_batch_submit(&a) && sl_batch_submit(&b));
    assert(!sl_batch_cancel(&a));
    assert(!sl_batch_complete(&a, 2));
    assert(sl_batch_complete(&b, 2)); /* completion order need not be slot order */
    assert(destroyed == 0);
    assert(sl_batch_quarantine(&a));
    assert(!sl_batch_complete(&a, 1));
    assert(!sl_batch_device_stopped(&a, 2));
    assert(destroyed == 0);
    r->batch = &a;
    assert(sl_batch_device_stopped(&a, 1));
    assert(destroyed == 1);
    assert(!sl_batch_begin(&a, 1));
    assert(sl_batch_begin(&a, 3));
    assert(sl_batch_pin(&a, &extra->ref));
    extra->batch = &a;
    assert(sl_resource_release(&extra->ref));
    assert(!sl_batch_complete(&a, 1));
    assert(sl_batch_cancel(&a));
    assert(destroyed == 2);
    assert(!sl_batch_cancel(&a));
}
static void *ref_worker(void *context) {
    sl_resource_ref *r = context;
    for (int i = 0; i < 10000; ++i) {
        assert(sl_resource_retain(r));
        assert(sl_resource_release(r));
    }
    assert(sl_resource_release(r));
    return NULL;
}
static void concurrent_refs(void) {
    int destroyed = 0;
    resource *r = make_resource(&destroyed);
    pthread_t workers[4];
    for (int i = 0; i < 4; ++i) {
        assert(sl_resource_retain(&r->ref));
        assert(pthread_create(&workers[i], NULL, ref_worker, &r->ref) == 0);
    }
    assert(sl_resource_release(&r->ref));
    for (int i = 0; i < 4; ++i) assert(pthread_join(workers[i], NULL) == 0);
    assert(destroyed == 1);
}
static void policy(void) {
    sl_app_lifecycle a;
    sl_app_lifecycle_init(&a);
    assert(sl_app_request_start(&a, 1));
    assert(!sl_app_request_start(&a, 1));
    assert(!sl_app_allow_remote(&a, true));
    assert(sl_app_session_created(&a, 1, 10));
    assert(sl_app_connected(&a, 10));
    assert(sl_app_video_state(&a, 10, 1, 1, false));
    assert(sl_app_presented(&a, 10, 1));
    assert(a.phase == SL_APP_STREAMING);
    assert(sl_app_video_state(&a, 10, 2, 1, true));
    assert(sl_app_allow_remote(&a, true)); /* host pauses video, not HID */
    assert(!sl_app_video_clock_running(&a));
    sl_app_foreground(&a, false);
    assert(sl_app_video_state(&a, 10, 3, 2, false));
    assert(!sl_app_video_state(&a, 10, 2, 1, true));
    assert(!sl_app_allow_draw(&a) && !sl_app_allow_remote(&a, true));
    assert(!sl_app_video_clock_running(&a));
    sl_app_foreground(&a, true);
    assert(sl_app_video_clock_running(&a));
    assert(!sl_app_presented(&a, 10, 1));
    assert(sl_app_presented(&a, 10, 2));
    assert(sl_app_request_start(&a, 2));
    assert(sl_app_request_start(&a, 3));
    assert(!sl_app_allow_remote(&a, true) && sl_app_allow_draw(&a));
    assert(!sl_app_connected(&a, 10));
    assert(!sl_app_cleanup(&a, 2, 10, true, true, true));
    assert(!sl_app_cleanup(&a, 1, 10, true, false, true));
    assert(sl_app_cleanup(&a, 1, 10, false, true, false) == 3);
    assert(a.phase == SL_APP_STARTING && a.request_id == 3);
    assert(!sl_app_connected(&a, 10));
    sl_app_request_exit(&a);
    /* Cancellation can race successful creation: still record the resource. */
    assert(sl_app_session_created(&a, 3, 11));
    assert(!sl_app_connected(&a, 11));
    assert(!sl_app_request_start(&a, 4));
    assert(!sl_app_can_join(&a, true));
    sl_app_cleanup(&a, 3, 11, true, true, true);
    assert(!sl_app_can_join(&a, false));
    assert(sl_app_can_join(&a, true));
    assert(!sl_app_allow_draw(&a));
    sl_app_device_failed(&a);
    sl_app_request_stop(&a);
    sl_app_request_exit(&a);
    assert(a.phase == SL_APP_DEVICE_FAILED);
}
static void cleanup_orders(void) {
    static const int orders[][3] = {{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
    for (unsigned i = 0; i < sizeof(orders)/sizeof(*orders); ++i) {
        sl_app_lifecycle a;
        sl_app_lifecycle_init(&a);
        assert(sl_app_request_start(&a, 1));
        assert(sl_app_request_start(&a, 2)); /* before session creation */
        for (int j = 0; j < 3; ++j) {
            int fact = orders[i][j];
            uint64_t next = sl_app_cleanup(&a, 1, 0, fact == 0, fact == 1, fact == 2);
            assert(next == (j == 2 ? 2 : 0));
        }
        assert(a.request_id == 2 && !a.requests_closed && !a.video_clean);
        sl_app_request_stop(&a);
        assert(!sl_app_cleanup(&a, 1, 0, true, true, true));
        sl_app_cleanup(&a, 2, 0, true, true, true);
        assert(a.phase == SL_APP_IDLE);
        sl_app_request_exit(&a);
        assert(sl_app_can_join(&a, true));
    }
}
int main(void) {
    batches();
    concurrent_refs();
    policy();
    cleanup_orders();
    return 0;
}
