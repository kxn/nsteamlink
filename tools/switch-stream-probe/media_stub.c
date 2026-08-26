#include "media.h"

#include <string.h>

static probe_media_snapshot snapshot;
static probe_media_log_fn log_cb;

static void set_error(const char *message) {
    memset(&snapshot, 0, sizeof(snapshot));
    strncpy(snapshot.last_error, message, sizeof(snapshot.last_error) - 1);
    snapshot.last_error[sizeof(snapshot.last_error) - 1] = '\0';
    if (log_cb != NULL) {
        log_cb(message);
    }
}

bool probe_media_init(probe_media_log_fn log_fn) {
    log_cb = log_fn;
    set_error("media disabled in core probe");
    return false;
}

void probe_media_shutdown(void) {
    memset(&snapshot, 0, sizeof(snapshot));
}

bool probe_media_available(void) {
    return false;
}

bool probe_media_exit_requested(void) {
    return false;
}

void probe_media_present(void) {
}

void probe_media_set_hid_session(IHS_Session *session, bool enabled) {
    (void)session;
    (void)enabled;
}

void probe_media_set_ui(const probe_media_ui *ui) {
    (void)ui;
}

void probe_media_get_snapshot(probe_media_snapshot *out) {
    if (out == NULL) {
        return;
    }
    *out = snapshot;
}

int probe_media_video_start(IHS_Session *session, const IHS_StreamVideoConfig *config) {
    (void)session;
    (void)config;
    set_error("media disabled in core probe");
    return -1;
}

IHS_StreamVideoSubmitResult probe_media_video_submit(IHS_Session *session, uint16_t frame_id,
                                                     IHS_Buffer *data,
                                                     IHS_StreamVideoFrameFlag flags) {
    (void)session;
    (void)frame_id;
    (void)data;
    (void)flags;
    return IHS_StreamVideoSubmitError;
}

void probe_media_video_stop(IHS_Session *session) {
    (void)session;
}
