#include "app_lifecycle.h"

static bool running(const sl_app_lifecycle *a) {
    return a->phase == SL_APP_STARTING || a->phase == SL_APP_STREAMING;
}
static void start(sl_app_lifecycle *a, uint64_t id) {
    a->phase = SL_APP_STARTING;
    a->request_id = id;
    a->session_id = a->epoch = a->video_transition = 0;
    a->pending_request_id = 0;
    a->connected = a->host_video_paused = false;
    a->requests_closed = a->protocol_closed = a->video_clean = false;
}
void sl_app_lifecycle_init(sl_app_lifecycle *a) {
    *a = (sl_app_lifecycle){.foreground = true, .requests_closed = true,
                          .protocol_closed = true, .video_clean = true};
}
bool sl_app_request_start(sl_app_lifecycle *a, uint64_t id) {
    if (!id || id <= a->last_request_id || a->exit_requested || a->phase == SL_APP_DEVICE_FAILED)
        return false;
    a->last_request_id = id;
    if (a->phase == SL_APP_IDLE)
        start(a, id);
    else {
        a->pending_request_id = id;
        a->phase = SL_APP_STOPPING;
        a->connected = false;
    }
    return true;
}
void sl_app_request_stop(sl_app_lifecycle *a) {
    a->pending_request_id = 0;
    a->connected = false;
    if (running(a))
        a->phase = SL_APP_STOPPING;
}
void sl_app_request_exit(sl_app_lifecycle *a) {
    sl_app_request_stop(a);
    a->exit_requested = true;
    if (a->phase != SL_APP_DEVICE_FAILED)
        a->phase = SL_APP_EXITING;
}
void sl_app_device_failed(sl_app_lifecycle *a) {
    sl_app_request_exit(a);
    a->phase = SL_APP_DEVICE_FAILED;
}
bool sl_app_session_created(sl_app_lifecycle *a, uint64_t request, uint64_t session) {
    /* Creation can finish after stop/exit was requested. Record ownership even
     * then, without reopening admission. Runtime publishes creation before its
     * cleanup facts and cannot create a session after requests_closed. */
    if (a->requests_closed || a->request_id != request || !session || a->session_id)
        return false;
    a->session_id = session;
    return true;
}
bool sl_app_connected(sl_app_lifecycle *a, uint64_t session) {
    if (!running(a) || !session || a->session_id != session)
        return false;
    a->connected = true;
    return true;
}
bool sl_app_video_state(sl_app_lifecycle *a, uint64_t session, uint64_t transition,
                        uint64_t epoch, bool paused) {
    if (!running(a) || !session || a->session_id != session ||
        !transition || transition <= a->video_transition || (!paused && !epoch) || epoch < a->epoch)
        return false;
    a->video_transition = transition;
    a->epoch = epoch;
    a->host_video_paused = paused;
    return true;
}
bool sl_app_presented(sl_app_lifecycle *a, uint64_t session, uint64_t epoch) {
    if (!running(a) || !a->connected || !session || session != a->session_id ||
        !epoch || epoch != a->epoch || a->host_video_paused || !a->foreground)
        return false;
    a->phase = SL_APP_STREAMING;
    return true;
}
void sl_app_foreground(sl_app_lifecycle *a, bool foreground) {
    a->foreground = foreground;
}
bool sl_app_allow_remote(const sl_app_lifecycle *a, bool ui_wants_remote) {
    return running(a) && a->connected && a->foreground && ui_wants_remote;
}
bool sl_app_allow_draw(const sl_app_lifecycle *a) {
    return a->foreground && a->phase != SL_APP_EXITING && a->phase != SL_APP_DEVICE_FAILED;
}
bool sl_app_video_clock_running(const sl_app_lifecycle *a) {
    return running(a) && a->connected && a->foreground && !a->host_video_paused;
}
uint64_t sl_app_cleanup(sl_app_lifecycle *a, uint64_t request, uint64_t session,
                        bool requests_closed, bool protocol_closed, bool video_clean) {
    if ((a->phase != SL_APP_STOPPING && a->phase != SL_APP_EXITING &&
         a->phase != SL_APP_DEVICE_FAILED) || request != a->request_id || session != a->session_id)
        return 0;
    a->requests_closed |= requests_closed;
    a->protocol_closed |= protocol_closed;
    a->video_clean |= video_clean;
    if (!a->requests_closed || !a->protocol_closed || !a->video_clean || a->exit_requested)
        return 0;
    uint64_t next = a->pending_request_id;
    if (next)
        start(a, next);
    else {
        a->phase = SL_APP_IDLE;
        a->connected = false;
        a->request_id = a->session_id = a->epoch = 0;
    }
    return next;
}
bool sl_app_can_join(const sl_app_lifecycle *a, bool worker_finished) {
    return a->exit_requested && a->requests_closed && a->protocol_closed && a->video_clean &&
           worker_finished;
}
