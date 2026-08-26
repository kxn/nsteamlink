#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <ihslib/buffer.h>
#include <ihslib/session.h>
#include <ihslib/video.h>

#ifndef NSTREAMLINK_APP
#define NSTREAMLINK_APP 0
#endif

#if NSTREAMLINK_APP
#include <ihslib/hid/sdl.h>
#endif

typedef void (*probe_media_log_fn)(const char *message);

typedef struct probe_media_snapshot {
    bool available;
    bool video_active;
    bool first_frame_displayed;
    uint32_t decoded_frames;
    uint32_t displayed_frames;
    uint32_t dropped_frames;
    uint32_t decode_samples;
    uint32_t transferred_frames;
    uint32_t converted_frames;
    uint16_t last_displayed_frame;
    uint64_t decode_us_total;
    uint64_t transfer_us_total;
    uint64_t convert_us_total;
    uint64_t upload_us_total;
    uint64_t present_us_total;
    uint32_t decode_us_max;
    uint32_t transfer_us_max;
    uint32_t convert_us_max;
    uint32_t upload_us_max;
    uint32_t present_us_max;
    uint32_t hid_events;
    uint32_t hid_send_ok;
    uint32_t hid_send_fail;
    uint32_t hid_state_full;
    int hid_sdl_joystick_count;
    int hid_sdl_controller_index;
    int hid_sdl_instance_id;
    int hid_sdl_controller_type;
    int hid_last_event_type;
    int hid_last_event_which;
    int hid_last_event_code;
    int hid_last_event_value;
    int hid_provider_devices;
    char hid_sdl_guid[40];
    char hid_sdl_name[64];
    int width;
    int height;
    char decoder[64];
    char last_error[128];
} probe_media_snapshot;

#define PROBE_MEDIA_UI_LINES 8
#define PROBE_MEDIA_UI_TEXT  96

typedef struct probe_media_ui {
    bool visible;
    bool dim_background;
    char title[48];
    char lines[PROBE_MEDIA_UI_LINES][PROBE_MEDIA_UI_TEXT];
} probe_media_ui;

bool probe_media_init(probe_media_log_fn log_fn);
void probe_media_shutdown(void);
bool probe_media_available(void);
bool probe_media_exit_requested(void);
void probe_media_set_hid_session(IHS_Session *session, bool enabled);
#if NSTREAMLINK_APP
IHS_HIDProvider *probe_media_create_hid_provider(void);
void probe_media_destroy_hid_provider(IHS_HIDProvider *provider);
#endif
void probe_media_present(void);
void probe_media_get_snapshot(probe_media_snapshot *out);
void probe_media_set_ui(const probe_media_ui *ui);

int probe_media_video_start(IHS_Session *session, const IHS_StreamVideoConfig *config);
IHS_StreamVideoSubmitResult probe_media_video_submit(IHS_Session *session, uint16_t frame_id,
                                                     IHS_Buffer *data,
                                                     IHS_StreamVideoFrameFlag flags);
void probe_media_video_stop(IHS_Session *session);
