#include "http_route.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
static atomic_uint initializations, cleanups;
static bool fail = true;
CURLcode __real_curl_global_init(long);
void __real_curl_global_cleanup(void);
CURLcode __wrap_curl_global_init(long flags) {
    ++initializations;
    if (fail)
        return CURLE_FAILED_INIT;
    return __real_curl_global_init(flags);
}
void __wrap_curl_global_cleanup(void) {
    ++cleanups;
    __real_curl_global_cleanup();
}
static void *worker(void *unused) {
    (void)unused;
    for (unsigned i = 0; i < 1000; ++i) {
        assert(sl_http_global_acquire());
        sl_http_global_release();
    }
    return NULL;
}
int main(void) {
    assert(!sl_http_global_acquire() && initializations == 1 && cleanups == 0);
    fail = false;
    assert(sl_http_global_acquire());
    pthread_t threads[8];
    for (unsigned i = 0; i < 8; ++i)
        assert(!pthread_create(&threads[i], NULL, worker, NULL));
    for (unsigned i = 0; i < 8; ++i)
        assert(!pthread_join(threads[i], NULL));
    assert(initializations == 2 && cleanups == 0);
    sl_http_global_release();
    assert(cleanups == 1);
    assert(sl_http_global_acquire() && initializations == 3);
    sl_http_global_release();
    assert(cleanups == 2);
    puts("PASS failed init, 8000 concurrent owner cycles, last-owner cleanup, reinitialization");
}
