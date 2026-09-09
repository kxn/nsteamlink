#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Main-thread policy. Runtime reports facts; it does not own this state machine.
 * No backend, session pointer, UI page, or blocking operation belongs here. */
typedef enum {
    SL_APP_IDLE, SL_APP_STARTING, SL_APP_STREAMING, SL_APP_STOPPING,
    SL_APP_EXITING, SL_APP_DEVICE_FAILED
} sl_app_phase;
typedef struct sl_app_lifecycle {
    sl_app_phase phase;
    uint64_t request_id, session_id, epoch, pending_request_id;
    uint64_t last_request_id, video_transition;
    bool connected, foreground, host_video_paused, exit_requested;
    bool requests_closed, protocol_closed, video_clean;
} sl_app_lifecycle;

void sl_app_lifecycle_init(sl_app_lifecycle *);
/* Returns true if accepted. STARTING with the matching request_id means the
 * caller may dispatch it now; otherwise it is the single replacement intent. */
bool sl_app_request_start(sl_app_lifecycle *, uint64_t request_id);
void sl_app_request_stop(sl_app_lifecycle *); /* Also cancels replacement intent. */
void sl_app_request_exit(sl_app_lifecycle *);
void sl_app_device_failed(sl_app_lifecycle *);
/* Runtime must publish creation before cleanup facts for that request, even if
 * stop/exit already won. requests_closed proves no later creation is possible. */
bool sl_app_session_created(sl_app_lifecycle *, uint64_t request_id, uint64_t session_id);
bool sl_app_connected(sl_app_lifecycle *, uint64_t session_id);
bool sl_app_video_state(sl_app_lifecycle *, uint64_t session_id, uint64_t transition,
                        uint64_t epoch, bool paused);
/* Paused facts carry the last epoch (0 only before any video start); transition
 * is monotonic across pause/resume in a session, independently of epoch. */
bool sl_app_presented(sl_app_lifecycle *, uint64_t session_id, uint64_t epoch);
void sl_app_foreground(sl_app_lifecycle *, bool foreground);
bool sl_app_allow_remote(const sl_app_lifecycle *, bool ui_wants_remote);
bool sl_app_allow_draw(const sl_app_lifecycle *);
bool sl_app_video_clock_running(const sl_app_lifecycle *);
/* Cleanup is scoped to the original request, including cancellation before a
 * session exists. Facts are monotonic. Returns a newly admitted request, or 0. */
uint64_t sl_app_cleanup(sl_app_lifecycle *, uint64_t request_id, uint64_t session_id,
                        bool requests_closed, bool protocol_closed, bool video_clean);
bool sl_app_can_join(const sl_app_lifecycle *, bool worker_finished);
