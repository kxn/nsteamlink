#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <ihslib/buffer.h>
#include <ihslib/audio.h>
#include <ihslib/session.h>
#include <ihslib/video.h>

#ifndef NSTREAMLINK_APP
#define NSTREAMLINK_APP 0
#endif

#if NSTREAMLINK_APP
#include <ihslib/hid/sdl.h>
#endif

typedef void (*stream_media_log_fn)(const char *message);

typedef struct stream_media_snapshot {
    bool available;
    bool video_active;
    bool first_frame_displayed;
    uint32_t decoded_frames;
    uint32_t displayed_frames;
    uint32_t dropped_frames;
    uint32_t decode_samples;
    uint32_t transferred_frames;
    uint32_t vic_transfer_frames;
    uint32_t transfer_fallback_frames;
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
    uint32_t frame_wait_samples;
    uint64_t frame_wait_us_total;
    uint32_t frame_wait_us_max;
    uint32_t frame_e2e_samples;
    uint64_t frame_e2e_us_total;
    uint32_t frame_e2e_us_max;
    uint32_t hid_send_samples;
    uint64_t hid_send_us_total;
    uint32_t hid_send_us_max;
    uint32_t hid_age_samples;
    uint64_t hid_age_ms_total;
    uint32_t hid_age_ms_max;
    uint32_t hid_events;
    uint32_t hid_send_ok;
    uint32_t hid_send_fail;
    uint32_t hid_state_full;
    uint32_t hid_raw_ax_total;
    uint32_t hid_raw_btn_total;
    uint32_t hid_style_flips_total;
    bool hid_marker_minus_sdl_held;
    bool hid_marker_minus_raw_held;
    uint32_t hid_marker_minus_sdl_samples_total;
    uint32_t hid_marker_minus_raw_samples_total;
    IHS_SessionReliabilityStats reliability;
    bool audio_active;
    uint32_t audio_frames;
    uint64_t audio_bytes;
    uint64_t audio_decoded_samples;
    uint32_t audio_queued_bytes;
    uint32_t audio_queue_drops;
    uint32_t audio_decode_errors;
    int audio_codec;
    int audio_channels;
    int audio_frequency;
    int hid_sdl_joystick_count;
    int hid_sdl_controller_index;
    int hid_sdl_instance_id;
    int hid_sdl_controller_type;
    int hid_last_event_type;
    int hid_last_event_which;
    int hid_last_event_code;
    int hid_last_event_value;
    int hid_provider_devices;
    char hid_style_state[12];
    char hid_sdl_guid[40];
    char hid_sdl_name[64];
    int width;
    int height;
    char decoder[64];
    char last_error[128];
} stream_media_snapshot;

#define STREAM_MEDIA_UI_LINES 8
#define STREAM_MEDIA_UI_TEXT  96

typedef struct stream_media_ui {
    bool visible;
    bool dim_background;
    char title[48];
    char lines[STREAM_MEDIA_UI_LINES][STREAM_MEDIA_UI_TEXT];
} stream_media_ui;

typedef struct stream_media_hid_history_entry {
    uint32_t seq;
    uint32_t sec;
    uint32_t events;
    uint32_t send_ok;
    uint32_t send_fail;
    uint32_t state_full;
    uint32_t pump;
    uint32_t ax;
    uint32_t btn;
    uint32_t sen;
    uint32_t oth;
    uint32_t ev_sup;
    uint32_t raw_ax;
    uint32_t raw_btn;
    uint32_t sty_fl;
    uint32_t events_total;
    uint32_t send_ok_total;
    uint32_t state_full_total;
    uint32_t raw_ax_total;
    uint32_t raw_btn_total;
    int last_type;
    int last_which;
    int last_code;
    int last_value;
    int16_t left_x;
    int16_t left_y;
    int16_t right_x;
    int16_t right_y;
    uint32_t buttons;
    uint32_t marker_minus_sdl_held;
    uint32_t marker_minus_sdl_samples;
    uint32_t marker_minus_raw_held;
    uint32_t marker_minus_raw_samples;
    char sty[12];
    /** Wire truth: axes/buttons packed into the last submitted HID report. */
    int16_t sent_lx;
    int16_t sent_ly;
    int16_t sent_rx;
    int16_t sent_ry;
    uint16_t sent_buttons;
    uint32_t sent_seq;
} stream_media_hid_history_entry;

bool stream_media_init(stream_media_log_fn log_fn);
void stream_media_shutdown(void);
bool stream_media_available(void);
bool stream_media_exit_requested(void);
void stream_media_set_hid_session(IHS_Session *session, bool enabled);
#if NSTREAMLINK_APP
IHS_HIDProvider *stream_media_create_hid_provider(void);
void stream_media_destroy_hid_provider(IHS_HIDProvider *provider);
#endif
void stream_media_present(void);
void stream_media_get_snapshot(stream_media_snapshot *out);
size_t stream_media_copy_hid_history(stream_media_hid_history_entry *out, size_t max_entries);
void stream_media_format_hid_history(char *out, size_t out_len, uint32_t max_entries);
void stream_media_set_ui(const stream_media_ui *ui);

int stream_media_video_start(IHS_Session *session, const IHS_StreamVideoConfig *config);
IHS_StreamVideoSubmitResult stream_media_video_submit(IHS_Session *session, uint16_t frame_id,
                                                     IHS_Buffer *data,
                                                     IHS_StreamVideoFrameFlag flags);
void stream_media_video_stop(IHS_Session *session);

int stream_media_audio_start(IHS_Session *session, const IHS_StreamAudioConfig *config);
int stream_media_audio_submit(IHS_Session *session, IHS_Buffer *data);
void stream_media_audio_stop(IHS_Session *session);
