/* Keep the real private runtime stop path; no application injection API. */
#include "../platforms/common/runtime.c"
#include <assert.h>

void sensor_lifetime_stop_session(IHS_Session *session) {
    sl_runtime r = {0};
    assert(!pthread_mutex_init(&r.lock, NULL));
    atomic_init(&r.player_input_focus, false);
    r.session = session;
    (void)stop_session(&r);
    assert(!r.session);
    pthread_mutex_destroy(&r.lock);
}
