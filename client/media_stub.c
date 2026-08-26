#include "media.h"

#include <string.h>

static stream_media_snapshot snapshot;
static stream_media_log_fn log_cb;

static void set_error(const char *message) {
    memset(&snapshot, 0, sizeof(snapshot));
    strncpy(snapshot.last_error, message, sizeof(snapshot.last_error) - 1);
    snapshot.last_error[sizeof(snapshot.last_error) - 1] = '\0';
    if (log_cb != NULL) {
        log_cb(message);
    }
}

bool stream_media_init(stream_media_log_fn log_fn) {
    log_cb = log_fn;
    set_error("media disabled in core selftest");
    return false;
}

void stream_media_shutdown(void) {
    memset(&snapshot, 0, sizeof(snapshot));
}

bool stream_media_available(void) {
    return false;
}

bool stream_media_exit_requested(void) {
    return false;
}

void stream_media_present(void) {
}

void stream_media_set_hid_session(IHS_Session *session, bool enabled) {
    (void)session;
    (void)enabled;
}

void stream_media_set_ui(const stream_media_ui *ui) {
    (void)ui;
}

void stream_media_get_snapshot(stream_media_snapshot *out) {
    if (out == NULL) {
        return;
    }
    *out = snapshot;
}

int stream_media_video_start(IHS_Session *session, const IHS_StreamVideoConfig *config) {
    (void)session;
    (void)config;
    set_error("media disabled in core selftest");
    return -1;
}

IHS_StreamVideoSubmitResult stream_media_video_submit(IHS_Session *session, uint16_t frame_id,
                                                     IHS_Buffer *data,
                                                     IHS_StreamVideoFrameFlag flags) {
    (void)session;
    (void)frame_id;
    (void)data;
    (void)flags;
    return IHS_StreamVideoSubmitError;
}

void stream_media_video_stop(IHS_Session *session) {
    (void)session;
}
