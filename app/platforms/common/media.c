#include "media.h"
#include "events_backend.h"
#include "gfx_backend.h"
#include "platform/rumble.h"
#include "session/frame_tracker.h"
#include "ui_audio.h"

#include <ctype.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <SDL.h>
#include <opus.h>
#if __SWITCH__
#include <switch.h>
#endif

#include <libavcodec/avcodec.h>
#include <libavutil/buffer.h>
#include <libavutil/error.h>
#include <libavutil/frame.h>
#include <libavutil/hwcontext.h>
#include <libavutil/imgutils.h>
#include <libavutil/mem.h>
#include <libavutil/pixdesc.h>
#include <libswscale/swscale.h>

#include <ihslib/hid/sdl.h>
#include <ihslib/input.h>

#define SDL_WIDTH  1280
#define SDL_HEIGHT 720

static sl_gfx *gfx;
static SDL_AudioDeviceID audio_device;
static bool audio_shutting_down;
static bool sdl_initialized;
static bool locks_ready, mapping_installed;
static bool sdl_ready;
static bool sdl_exit_requested;
static bool logged_alignment_fallback;

static pthread_mutex_t state_lock;
static pthread_mutex_t audio_lock;

static sl_video_pipeline *video;
static sl_video_frame *current_frame;
static sl_video_key video_key;
static IHS_FrameTracker *test_tracker;
static uint64_t test_session_id;
static uint64_t presentation_serial, last_presentation_us;
static sl_video_key presentation_key, layout_key;
static OpusDecoder *audio_decoder;
static int audio_frequency;
static int audio_channels;
static IHS_StreamAudioCodec audio_codec;
static bool audio_active;
static uint32_t audio_frames_total;
static uint64_t audio_bytes_total;
static uint64_t audio_decoded_samples_total;
static uint32_t audio_queue_drops_total;
static uint32_t audio_decode_errors_total;
#define AUDIO_MAX_OPUS_FRAME_SAMPLES 5760
#define AUDIO_QUEUE_LIMIT_MS         300U
static opus_int16 audio_decode_buf[AUDIO_MAX_OPUS_FRAME_SAMPLES * 2];

static IHS_Session *hid_session;
static bool rumble_reset_pending;
static bool hid_session_enabled;
static pthread_t hid_flush_thread;
static atomic_bool hid_flush_running;
static bool hid_flush_started;
static pthread_mutex_t hid_lifecycle_lock;
static SDL_GameController *hid_controller;
static SDL_JoystickID hid_controller_id = -1;
static int hid_controller_index = -1;
#if NSL_DIAGNOSTICS
static uint32_t hid_events_since_log;
static uint32_t hid_send_ok_since_log;
static uint32_t hid_send_fail_since_log;
static uint32_t hid_events_total;
static uint32_t hid_send_ok_total;
static uint32_t hid_send_fail_total;
static uint32_t hid_state_full_since_log;
static uint32_t hid_state_full_total;
static uint32_t hid_raw_ax_total;
static uint32_t hid_raw_btn_total;
static uint32_t hid_style_flips_total;
static uint64_t hid_last_log_us;
/* Event-classification counters for locating capture halts; immediate trace budget. */
#define HID_TRACE_BUDGET_PER_SEC 12U
static uint32_t hid_pump_calls_since_log;
static uint32_t hid_axis_since_log;
static uint32_t hid_button_since_log;
static uint32_t hid_sensor_since_log;
static uint32_t hid_other_since_log;
static uint32_t hid_trace_lines_this_sec;
static uint32_t hid_trace_suppressed;
/* Raw libnx HID sampler: bypasses SDL entirely to bisect capture halts.
 * rawAx/rawBtn count OS-level stick/button motion in a second; if raw moves while
 * ax=/btn= stay zero, SDL is swallowing updates — if both are zero while the user
 * fights the stick, the HID sharedmem pipeline itself went stale. */
#define RAW_NPAD_SAMPLE_INTERVAL_MS 250
#if __SWITCH__
static void sample_raw_npad(void);
static PadState hid_raw_pad;
static bool hid_raw_pad_initialized;
static int16_t hid_raw_prev_x;
static int16_t hid_raw_prev_y;
static uint64_t hid_raw_prev_buttons;
static bool hid_raw_have_prev;
static u32 hid_prev_style;
static u32 hid_prev_attrs;
static bool hid_have_style_prev;
static uint64_t hid_raw_last_sample_us;
#endif
static uint32_t hid_raw_ax_since_log;
static uint32_t hid_raw_btn_since_log;
static bool hid_marker_minus_sdl_held;
static bool hid_marker_minus_raw_held;
static uint32_t hid_marker_minus_sdl_samples_since_log;
static uint32_t hid_marker_minus_raw_samples_since_log;
static uint32_t hid_marker_minus_sdl_samples_total;
static uint32_t hid_marker_minus_raw_samples_total;
/* Style/attribute flap odometer: SWITCH_JoystickUpdate early-returns whenever its
 * freshly read type/style differs from cached values; repeated flips skip processing
 * repeatedly. We recompute independently here to watch for storms. */
static uint32_t hid_style_flips_since_log;
static char hid_style_last[12];
#define HID_HISTORY_CAP 60U
static stream_media_hid_history_entry hid_history[HID_HISTORY_CAP];
static uint32_t hid_history_next;
static uint32_t hid_history_count;
static uint32_t hid_history_seq;
#endif
static stream_media_log_fn log_cb;
static stream_media_snapshot snapshot;
static void (*draw_hook)(void *, void *);
static void (*event_hook)(const void *, void *);
static void *hook_context;
static atomic_bool input_gate;
static atomic_bool muted;
#if NSL_DIAGNOSTICS
static IHS_HIDSDLLastSubmitted submitted_cache;
#endif
static SDL_Rect video_rect;
static struct {
    bool active;
    int64_t id;
} remote_touches[8];
static void media_logf(const char *fmt, ...);
static bool opus_rate_supported(uint32_t rate);
static uint32_t audio_queue_limit_bytes(int frequency, int channels);
static void audio_stop_locked(void);
static void update_audio_snapshot(void);

static bool open_hid_controller(void);
static void close_hid_controller(void);
#if NSL_DIAGNOSTICS
static void record_hid_event(const SDL_Event *event);
#endif
static int hid_device_list_count(void *context);
static int hid_device_list_index(SDL_JoystickID joystick_id, void *context);
static SDL_JoystickID hid_device_list_instance_id(int index, void *context);
static SDL_Gamepad *hid_device_list_controller(int index, void *context);

static const IHS_HIDProviderSDLDeviceList HID_DEVICE_LIST = {
    .count = hid_device_list_count,
    .index = hid_device_list_index,
    .instanceId = hid_device_list_instance_id,
    .controller = hid_device_list_controller,
};

static const char *SWITCH_FACE_LABEL_MAPPING =
    "000038f853776974636820436f6e7400,Switch Controller,"
    "a:b0,b:b1,back:b11,dpdown:b15,dpleft:b12,dpright:b14,dpup:b13,"
    "leftshoulder:b6,leftstick:b4,lefttrigger:b8,leftx:a0,lefty:a1,"
    "rightshoulder:b7,rightstick:b5,righttrigger:b9,rightx:a2,righty:a3,"
    "start:b10,x:b2,y:b3,";

static void install_switch_face_label_mapping(void) {
    if (mapping_installed) {
        return;
    }
    int rc = SDL_GameControllerAddMapping(SWITCH_FACE_LABEL_MAPPING);
    media_logf("hid sdl mapping override: rc=%d faceLabels=ABXY", rc);
    if (rc < 0) {
        media_logf("hid sdl mapping override failed: %s", SDL_GetError());
    }
    mapping_installed = true;
}

static uint64_t media_monotonic_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static uint32_t elapsed_us(uint64_t start_us, uint64_t end_us) {
    if (start_us == 0 || end_us < start_us) {
        return 0;
    }
    uint64_t delta = end_us - start_us;
    return delta > UINT32_MAX ? UINT32_MAX : (uint32_t)delta;
}

static void add_timing(uint64_t *total, uint32_t *max_value, uint32_t value) {
    *total += value;
    if (value > *max_value) {
        *max_value = value;
    }
}

static void media_logf(const char *fmt, ...) {
    if (log_cb == NULL) {
        return;
    }
    char msg[224];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    msg[sizeof(msg) - 1] = '\0';
    log_cb(msg);
}

static void media_set_error(const char *fmt, ...) {
    char msg[sizeof(snapshot.last_error)];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    msg[sizeof(msg) - 1] = '\0';

    pthread_mutex_lock(&state_lock);
    strncpy(snapshot.last_error, msg, sizeof(snapshot.last_error));
    snapshot.last_error[sizeof(snapshot.last_error) - 1] = '\0';
    pthread_mutex_unlock(&state_lock);
    media_logf("media error: %s", msg);
}

static void ffmpeg_log_callback(void *ptr, int level, const char *fmt, va_list vl) {
    (void)ptr;
    if (level > AV_LOG_WARNING || log_cb == NULL) {
        return;
    }
    char msg[224];
    vsnprintf(msg, sizeof(msg), fmt, vl);
    msg[sizeof(msg) - 1] = '\0';
    size_t n = strlen(msg);
    while (n > 0 && (msg[n - 1] == '\n' || msg[n - 1] == '\r')) {
        msg[--n] = '\0';
    }
    if (msg[0] != '\0') {
        if (strstr(msg, "Frame address/pitch not aligned to 256") != NULL) {
            if (logged_alignment_fallback) {
                return;
            }
            logged_alignment_fallback = true;
            media_logf("[FFmpeg] %s; suppressing repeats", msg);
            return;
        }
        media_logf("[FFmpeg] %s", msg);
    }
}

static bool opus_rate_supported(uint32_t rate) {
    return rate == 8000U || rate == 12000U || rate == 16000U || rate == 24000U || rate == 48000U;
}

static uint32_t audio_queue_limit_bytes(int frequency, int channels) {
    if (frequency <= 0 || channels <= 0) {
        return 0;
    }
    uint64_t bytes = (uint64_t)frequency * (uint64_t)channels * sizeof(opus_int16) *
                     AUDIO_QUEUE_LIMIT_MS / 1000U;
    return bytes > UINT32_MAX ? UINT32_MAX : (uint32_t)bytes;
}

static void audio_stop_locked(void) {
    if (audio_device != 0) {
        SDL_PauseAudioDevice(audio_device, 1);
        SDL_ClearQueuedAudio(audio_device);
        SDL_CloseAudioDevice(audio_device);
        audio_device = 0;
    }
    if (audio_decoder != NULL) {
        opus_decoder_destroy(audio_decoder);
        audio_decoder = NULL;
    }
    audio_active = false;
    audio_frequency = 0;
    audio_channels = 0;
    audio_codec = IHS_StreamAudioCodecNone;
}

static void update_audio_snapshot(void) {
    bool active;
    uint32_t queued;
    uint32_t frames;
    uint64_t bytes;
    uint64_t samples;
    uint32_t drops;
    uint32_t errors;
    int codec;
    int channels;
    int frequency;

    pthread_mutex_lock(&audio_lock);
    active = audio_active;
    queued = audio_device != 0 ? SDL_GetQueuedAudioSize(audio_device) : 0;
    frames = audio_frames_total;
    bytes = audio_bytes_total;
    samples = audio_decoded_samples_total;
    drops = audio_queue_drops_total;
    errors = audio_decode_errors_total;
    codec = (int)audio_codec;
    channels = audio_channels;
    frequency = audio_frequency;
    pthread_mutex_unlock(&audio_lock);

    pthread_mutex_lock(&state_lock);
    snapshot.audio_active = active;
    snapshot.audio_queued_bytes = queued;
    snapshot.audio_frames = frames;
    snapshot.audio_bytes = bytes;
    snapshot.audio_decoded_samples = samples;
    snapshot.audio_queue_drops = drops;
    snapshot.audio_decode_errors = errors;
    snapshot.audio_codec = codec;
    snapshot.audio_channels = channels;
    snapshot.audio_frequency = frequency;
    pthread_mutex_unlock(&state_lock);
}

#if NSL_DIAGNOSTICS
static void reset_hid_probe_window(void) {
    hid_events_since_log = 0;
    hid_send_ok_since_log = 0;
    hid_send_fail_since_log = 0;
    hid_state_full_since_log = 0;
    hid_pump_calls_since_log = 0;
    hid_axis_since_log = 0;
    hid_button_since_log = 0;
    hid_sensor_since_log = 0;
    hid_other_since_log = 0;
    hid_trace_suppressed = 0;
    hid_trace_lines_this_sec = 0;
    hid_raw_ax_since_log = 0;
    hid_raw_btn_since_log = 0;
    hid_marker_minus_sdl_samples_since_log = 0;
    hid_marker_minus_raw_samples_since_log = 0;
    hid_style_flips_since_log = 0;
}

static void reset_hid_probe_baseline(void) {
    reset_hid_probe_window();
    hid_marker_minus_sdl_held = false;
    hid_marker_minus_raw_held = false;
    hid_style_last[0] = '-';
    hid_style_last[1] = '\0';
    memset(hid_history, 0, sizeof(hid_history));
    hid_history_next = 0;
    hid_history_count = 0;
    hid_history_seq = 0;
#if __SWITCH__
    hid_raw_have_prev = false;
    hid_have_style_prev = false;
    hid_raw_pad_initialized = false;
    hid_raw_last_sample_us = 0;
#endif
}

static void record_hid_history(uint64_t now_us) {
    int16_t left_x = 0;
    int16_t left_y = 0;
    int16_t right_x = 0;
    int16_t right_y = 0;
    uint32_t buttons = 0;
    if (hid_controller != NULL) {
        left_x = SDL_GameControllerGetAxis(hid_controller, SDL_CONTROLLER_AXIS_LEFTX);
        left_y = SDL_GameControllerGetAxis(hid_controller, SDL_CONTROLLER_AXIS_LEFTY);
        right_x = SDL_GameControllerGetAxis(hid_controller, SDL_CONTROLLER_AXIS_RIGHTX);
        right_y = SDL_GameControllerGetAxis(hid_controller, SDL_CONTROLLER_AXIS_RIGHTY);
        for (int i = 0; i < SDL_CONTROLLER_BUTTON_MAX && i < 32; i++) {
            if (SDL_GameControllerGetButton(hid_controller, (SDL_GameControllerButton)i)) {
                buttons |= 1U << i;
            }
        }
    }
    uint32_t marker_minus_sdl_held = 0;
    if (hid_controller != NULL &&
        SDL_GameControllerGetButton(hid_controller, SDL_CONTROLLER_BUTTON_BACK)) {
        marker_minus_sdl_held = 1;
    }

    pthread_mutex_lock(&state_lock);
    IHS_HIDSDLLastSubmitted last_submitted = submitted_cache;
    bool have_sent = last_submitted.seq != 0;
    stream_media_hid_history_entry *entry = &hid_history[hid_history_next];
    memset(entry, 0, sizeof(*entry));
    entry->seq = ++hid_history_seq;
    entry->sec = (uint32_t)(now_us / 1000000ULL);
    entry->events = hid_events_since_log;
    entry->send_ok = hid_send_ok_since_log;
    entry->send_fail = hid_send_fail_since_log;
    entry->state_full = hid_state_full_since_log;
    entry->pump = hid_pump_calls_since_log;
    entry->ax = hid_axis_since_log;
    entry->btn = hid_button_since_log;
    entry->sen = hid_sensor_since_log;
    entry->oth = hid_other_since_log;
    entry->ev_sup = hid_trace_suppressed;
    entry->raw_ax = hid_raw_ax_since_log;
    entry->raw_btn = hid_raw_btn_since_log;
    entry->sty_fl = hid_style_flips_since_log;
    entry->events_total = hid_events_total;
    entry->send_ok_total = hid_send_ok_total;
    entry->state_full_total = hid_state_full_total;
    entry->raw_ax_total = hid_raw_ax_total;
    entry->raw_btn_total = hid_raw_btn_total;
    entry->last_type = snapshot.hid_last_event_type;
    entry->last_which = snapshot.hid_last_event_which;
    entry->last_code = snapshot.hid_last_event_code;
    entry->last_value = snapshot.hid_last_event_value;
    entry->left_x = left_x;
    entry->left_y = left_y;
    entry->right_x = right_x;
    entry->right_y = right_y;
    entry->buttons = buttons;
    entry->marker_minus_sdl_held = marker_minus_sdl_held;
    entry->marker_minus_sdl_samples = hid_marker_minus_sdl_samples_since_log;
    entry->marker_minus_raw_held = hid_marker_minus_raw_held ? 1U : 0U;
    entry->marker_minus_raw_samples = hid_marker_minus_raw_samples_since_log;
    snprintf(entry->sty, sizeof(entry->sty), "%s", hid_style_last);
    if (have_sent) {
        entry->sent_lx = last_submitted.axes[0];
        entry->sent_ly = last_submitted.axes[1];
        entry->sent_rx = last_submitted.axes[2];
        entry->sent_ry = last_submitted.axes[3];
        entry->sent_buttons = last_submitted.buttons;
        entry->sent_seq = (uint32_t)last_submitted.seq;
    }

    hid_history_next = (hid_history_next + 1U) % HID_HISTORY_CAP;
    if (hid_history_count < HID_HISTORY_CAP) {
        hid_history_count++;
    }
    pthread_mutex_unlock(&state_lock);
}

static void snapshot_hid_controller(int joystick_count, int controller_index,
                                    SDL_JoystickID instance_id, int controller_type,
                                    const char *guid, const char *name, int provider_devices) {
    pthread_mutex_lock(&state_lock);
    snapshot.hid_sdl_joystick_count = joystick_count;
    snapshot.hid_sdl_controller_index = controller_index;
    snapshot.hid_sdl_instance_id = (int)instance_id;
    snapshot.hid_sdl_controller_type = controller_type;
    snapshot.hid_provider_devices = provider_devices;
    if (guid != NULL) {
        strncpy(snapshot.hid_sdl_guid, guid, sizeof(snapshot.hid_sdl_guid) - 1);
        snapshot.hid_sdl_guid[sizeof(snapshot.hid_sdl_guid) - 1] = '\0';
    } else {
        snapshot.hid_sdl_guid[0] = '\0';
    }
    if (name != NULL) {
        strncpy(snapshot.hid_sdl_name, name, sizeof(snapshot.hid_sdl_name) - 1);
        snapshot.hid_sdl_name[sizeof(snapshot.hid_sdl_name) - 1] = '\0';
    } else {
        snapshot.hid_sdl_name[0] = '\0';
    }
    pthread_mutex_unlock(&state_lock);
}

static void log_hid_sdl_inventory(void) {
    int count = SDL_NumJoysticks();
    char guid[40];
    media_logf("hid sdl inventory: joysticks=%d", count);
    for (int i = 0; i < count && i < 8; ++i) {
        SDL_JoystickGUID joystick_guid = SDL_JoystickGetDeviceGUID(i);
        SDL_JoystickGetGUIDString(joystick_guid, guid, sizeof(guid));
        char *mapping = SDL_GameControllerMappingForDeviceIndex(i);
        media_logf(
            "hid sdl device[%d]: instance=%d isController=%d type=%d name=%s guid=%s mapping=%s", i,
            (int)SDL_JoystickGetDeviceInstanceID(i), (int)SDL_IsGameController(i),
            (int)SDL_GameControllerTypeForIndex(i),
            SDL_JoystickNameForIndex(i) ? SDL_JoystickNameForIndex(i) : "-", guid[0] ? guid : "-",
            mapping != NULL ? mapping : "-");
        if (mapping != NULL) {
            SDL_free(mapping);
        }
    }
}

#else
#define snapshot_hid_controller(...) ((void)0)
#define log_hid_sdl_inventory()      ((void)0)
#endif
static bool open_hid_controller(void) {
    if (hid_controller != NULL) {
        return true;
    }

    SDL_JoystickEventState(SDL_ENABLE);
    SDL_GameControllerEventState(SDL_ENABLE);
    install_switch_face_label_mapping();
    log_hid_sdl_inventory();

    int count = SDL_NumJoysticks();
    int index = -1;
    if (count > 0 && SDL_IsGameController(0)) {
        index = 0;
    } else {
        for (int i = 0; i < count; ++i) {
            if (SDL_IsGameController(i)) {
                index = i;
                break;
            }
        }
    }
    if (index < 0) {
        snapshot_hid_controller(count, -1, -1, 0, NULL, NULL, 0);
        /* Keyboard/touch remain usable without a controller. */
        return false;
    }

    hid_controller = SDL_GameControllerOpen(index);
    if (hid_controller == NULL) {
        snapshot_hid_controller(count, index, -1, 0, NULL, NULL, 0);
        media_set_error("SDL_GameControllerOpen(%d): %s", index, SDL_GetError());
        return false;
    }

    SDL_Joystick *joystick = SDL_GameControllerGetJoystick(hid_controller);
    if (joystick == NULL) {
        SDL_GameControllerClose(hid_controller);
        hid_controller = NULL;
        snapshot_hid_controller(count, index, -1, 0, NULL, NULL, 0);
        media_set_error("SDL_GameControllerGetJoystick(%d) failed", index);
        return false;
    }

    hid_controller_index = index;
    hid_controller_id = SDL_JoystickInstanceID(joystick);
#if NSL_DIAGNOSTICS
    SDL_JoystickGUID joystick_guid = SDL_JoystickGetGUID(joystick);
    char guid[40];
    SDL_JoystickGetGUIDString(joystick_guid, guid, sizeof(guid));
    const char *name = SDL_GameControllerName(hid_controller);
    if (name == NULL) {
        name = SDL_JoystickName(joystick);
    }
    int type = (int)SDL_GameControllerGetType(hid_controller);
    snapshot_hid_controller(count, hid_controller_index, hid_controller_id, type, guid, name, 1);

    char *mapping = SDL_GameControllerMapping(hid_controller);
    media_logf("hid controller selected: index=%d instance=%d type=%d name=%s guid=%s mapping=%s",
               hid_controller_index, (int)hid_controller_id, type, name ? name : "-",
               guid[0] ? guid : "-", mapping != NULL ? mapping : "-");
    if (mapping != NULL) {
        SDL_free(mapping);
    }
#endif
    return true;
}

static void close_hid_controller(void) {
    if (hid_controller != NULL) {
        media_logf("hid controller close: index=%d instance=%d", hid_controller_index,
                   (int)hid_controller_id);
        SDL_GameControllerClose(hid_controller);
        hid_controller = NULL;
    }
    hid_controller_id = -1;
    hid_controller_index = -1;
    snapshot_hid_controller(0, -1, -1, 0, NULL, NULL, 0);
}

#if NSL_DIAGNOSTICS
static void record_hid_event(const SDL_Event *event) {
    int type = 0;
    int which = -1;
    int code = -1;
    int value = 0;

    switch (event->type) {
    case SDL_CONTROLLERDEVICEADDED:
    case SDL_CONTROLLERDEVICEREMOVED:
    case SDL_CONTROLLERDEVICEREMAPPED:
        type = (int)event->type;
        which = (int)event->cdevice.which;
        break;
    case SDL_CONTROLLERBUTTONDOWN:
    case SDL_CONTROLLERBUTTONUP:
        type = (int)event->type;
        which = (int)event->cbutton.which;
        code = (int)event->cbutton.button;
        value = (int)event->cbutton.state;
        break;
    case SDL_CONTROLLERAXISMOTION:
        type = (int)event->type;
        which = (int)event->caxis.which;
        code = (int)event->caxis.axis;
        value = (int)event->caxis.value;
        break;
    case SDL_CONTROLLERSENSORUPDATE:
        type = (int)event->type;
        which = (int)event->csensor.which;
        code = (int)event->csensor.sensor;
        break;
    default:
        return;
    }

    pthread_mutex_lock(&state_lock);
    snapshot.hid_last_event_type = type;
    snapshot.hid_last_event_which = which;
    snapshot.hid_last_event_code = code;
    snapshot.hid_last_event_value = value;
    pthread_mutex_unlock(&state_lock);
}

#endif
static int hid_device_list_count(void *context) {
    (void)context;
    return hid_controller != NULL ? 1 : 0;
}

static int hid_device_list_index(SDL_JoystickID joystick_id, void *context) {
    (void)context;
    return (hid_controller != NULL && joystick_id == hid_controller_id) ? 0 : -1;
}

static SDL_JoystickID hid_device_list_instance_id(int index, void *context) {
    (void)context;
    return (hid_controller != NULL && index == 0) ? hid_controller_id : -1;
}

static SDL_Gamepad *hid_device_list_controller(int index, void *context) {
    (void)context;
    return (hid_controller != NULL && index == 0) ? hid_controller : NULL;
}

#if NSL_DIAGNOSTICS
static void sample_sdl_marker_minus(void) {
    bool held = hid_controller != NULL &&
                SDL_GameControllerGetButton(hid_controller, SDL_CONTROLLER_BUTTON_BACK) != 0;
    hid_marker_minus_sdl_held = held;
    if (held) {
        hid_marker_minus_sdl_samples_since_log++;
        hid_marker_minus_sdl_samples_total++;
    }
}

#if __SWITCH__
/* Sample the libnx PadState path every 250ms, independent of SDL. */
static void sample_raw_npad(void) {
    uint64_t now_us = media_monotonic_us();
    if (hid_raw_last_sample_us != 0 &&
        now_us - hid_raw_last_sample_us < RAW_NPAD_SAMPLE_INTERVAL_MS * 1000ULL) {
        return;
    }
    hid_raw_last_sample_us = now_us;

    if (!hid_raw_pad_initialized) {
        padInitializeDefault(&hid_raw_pad);
        hid_raw_pad_initialized = true;
    }
    padUpdate(&hid_raw_pad);

    u32 style = padGetStyleSet(&hid_raw_pad);
    u32 attrs = padGetAttributes(&hid_raw_pad);
    snprintf(hid_style_last, sizeof(hid_style_last), "%x/%x", style, attrs);
    if (hid_have_style_prev && (style != hid_prev_style || attrs != hid_prev_attrs)) {
        hid_style_flips_since_log++;
        hid_style_flips_total++;
    }
    hid_prev_style = style;
    hid_prev_attrs = attrs;
    hid_have_style_prev = true;

    HidAnalogStickState left = padGetStickPos(&hid_raw_pad, 0);
    uint64_t buttons = padGetButtons(&hid_raw_pad);
    bool raw_minus = (buttons & HidNpadButton_Minus) != 0;
    hid_marker_minus_raw_held = raw_minus;
    if (raw_minus) {
        hid_marker_minus_raw_samples_since_log++;
        hid_marker_minus_raw_samples_total++;
    }
    if (hid_raw_have_prev && (left.x != hid_raw_prev_x || left.y != hid_raw_prev_y)) {
        hid_raw_ax_since_log++;
        hid_raw_ax_total++;
    }
    if (hid_raw_have_prev && buttons != hid_raw_prev_buttons) {
        hid_raw_btn_since_log++;
        hid_raw_btn_total++;
    }
    hid_raw_prev_x = (int16_t)left.x;
    hid_raw_prev_y = (int16_t)left.y;
    hid_raw_prev_buttons = buttons;
    hid_raw_have_prev = true;
}
#endif

#endif
static void pump_sdl_events(void) {
    SDL_Event event;
    bool devices_changed = false;
    for (unsigned budget = 0; budget < 128 && sl_events_next(&event); ++budget) {
#if NSL_DIAGNOSTICS
        record_hid_event(&event);
#endif
        if (event.type == SDL_CONTROLLERDEVICEADDED) {
            open_hid_controller();
            devices_changed = true;
        }
        if (event.type == SDL_CONTROLLERDEVICEREMOVED && event.cdevice.which == hid_controller_id) {
            close_hid_controller();
            devices_changed = true;
        }
        if (event.type == SDL_QUIT)
            sdl_exit_requested = true;
        if (event_hook)
            event_hook(&event, hook_context);
    }
#if NSL_DIAGNOSTICS
    uint64_t now = media_monotonic_us();
    if (now - hid_last_log_us >= 1000000) {
        sample_sdl_marker_minus();
#if __SWITCH__
        sample_raw_npad();
#endif
        record_hid_history(now);
        reset_hid_probe_window();
        hid_last_log_us = now;
    }
#endif
    pthread_mutex_lock(&state_lock);
    if (rumble_reset_pending) {
        sl_rumble_tick(false);
        rumble_reset_pending = false;
    }
    if (hid_session) {
        IHS_HIDSDLApplyPendingWrites(hid_session);
        if (devices_changed)
            IHS_SessionHIDNotifyDeviceChange(hid_session);
    }
    sl_rumble_tick(hid_session != NULL);
    pthread_mutex_unlock(&state_lock);
}

bool stream_media_init(stream_media_log_fn log_fn) {
    if (sdl_ready) {
        return true;
    }
    if (!locks_ready) {
        pthread_mutex_init(&state_lock, NULL);
        pthread_mutex_init(&audio_lock, NULL);
        pthread_mutex_init(&hid_lifecycle_lock, NULL);
        locks_ready = true;
    }
    atomic_store(&input_gate, false);
    log_cb = NSL_DIAGNOSTICS ? log_fn : NULL;
    memset(&snapshot, 0, sizeof(snapshot));
    sdl_exit_requested = false;

    av_log_set_level(NSL_DIAGNOSTICS ? AV_LOG_WARNING : AV_LOG_QUIET);
    av_log_set_callback(ffmpeg_log_callback);

    video = sl_video_create();
    if (!video) {
        stream_media_shutdown();
        return false;
    }
    Uint32 init_flags = NSL_GFX_DEKO ? 0 : SDL_INIT_VIDEO;
    init_flags |= SDL_INIT_GAMECONTROLLER | SDL_INIT_AUDIO;
    if (SDL_Init(init_flags) < 0) {
        media_set_error("SDL_Init: %s", SDL_GetError());
        stream_media_shutdown();
        return false;
    }
    sdl_initialized = true;
    sl_events_init();

    sl_gfx_config graphics = {.width = SDL_WIDTH, .height = SDL_HEIGHT, .title = "nsteamlink"};
    gfx = sl_gfx_create(&graphics);
    if (!gfx) {
        media_set_error("graphics initialization failed");
        stream_media_shutdown();
        return false;
    }

    open_hid_controller();

    audio_shutting_down = false;
    sl_audio_init();
    sdl_ready = true;

    pthread_mutex_lock(&state_lock);
    snapshot.available = true;
    pthread_mutex_unlock(&state_lock);
    media_logf("media init: graphics backend ready");
    return true;
}

void stream_media_shutdown(void) {
    if (!locks_ready)
        return;
    media_logf("media shutdown: begin");
    stream_media_set_hid_session(NULL, false);
    stream_media_video_stop(NULL);
    audio_shutting_down = true;
    stream_media_audio_stop(NULL);
    sl_audio_shutdown();

    pthread_mutex_lock(&state_lock);
    snapshot.available = false;
    snapshot.video_active = false;
    hid_session = NULL;
    hid_session_enabled = false;
    snapshot.hid_provider_devices = 0;
#if NSL_DIAGNOSTICS
    hid_events_total = 0;
    hid_send_ok_total = 0;
    hid_send_fail_total = 0;
    hid_state_full_total = 0;
    hid_raw_ax_total = 0;
    hid_raw_btn_total = 0;
    hid_style_flips_total = 0;
    hid_marker_minus_sdl_samples_total = 0;
    hid_marker_minus_raw_samples_total = 0;
    reset_hid_probe_baseline();
    hid_last_log_us = 0;
#endif
    pthread_mutex_unlock(&state_lock);

    close_hid_controller();

    if (current_frame) {
        sl_resource_release(&current_frame->ref);
        current_frame = NULL;
    }
    if (video)
        sl_video_reap(video);
    sl_gfx_destroy(gfx);
    gfx = NULL;
    if (video)
        sl_video_reap(video);
    if (sdl_initialized) {
        sl_rumble_tick(false);
        media_logf("media shutdown: SDL_Quit");
        SDL_Quit();
        sdl_initialized = false;
        sdl_ready = false;
        media_logf("media shutdown: SDL_Quit done");
    }

    if (video && !sl_video_destroy(video))
        abort();
    video = NULL;
    mapping_installed = false;
    pthread_mutex_destroy(&state_lock);
    pthread_mutex_destroy(&audio_lock);
    pthread_mutex_destroy(&hid_lifecycle_lock);
    locks_ready = false;
    media_logf("media shutdown: done");
}

bool stream_media_available(void) {
    return sdl_ready;
}

bool stream_media_exit_requested(void) {
    return sdl_exit_requested;
}

/* Dedicated input flush thread: 8ms interval, matching the official client's
 * CHIDDeviceReportThread. Sends delta reports (previous→current masked diff)
 * independently of the present loop. Thread safety: calls the same
 * IHS_HIDFlushSDLGameControllers which locks each device under its own lock;
 * no new lock ordering. */
static void *hid_flush_thread_fn(void *arg) {
    (void)arg;
    while (atomic_load(&hid_flush_running)) {
        pthread_mutex_lock(&state_lock);
        IHS_Session *sess = hid_session;
        bool enabled = hid_session_enabled;
        if (enabled && sess != NULL && input_gate) {
            IHS_HIDFlushSDLGameControllers(sess);
        }
        pthread_mutex_unlock(&state_lock);
        usleep(8000); /* 8ms = 125Hz */
    }
    return NULL;
}

static void hid_flush_thread_start(void) {
    atomic_store(&hid_flush_running, true);
    int err = pthread_create(&hid_flush_thread, NULL, hid_flush_thread_fn, NULL);
    hid_flush_started = err == 0;
    if (err != 0) {
        atomic_store(&hid_flush_running, false);
        media_logf("HID flush thread creation failed: %d", err);
    }
}

static void hid_flush_thread_stop(void) {
    atomic_store(&hid_flush_running, false);
    if (hid_flush_started) {
        pthread_join(hid_flush_thread, NULL);
        hid_flush_started = false;
    }
}

void stream_media_set_hid_session(IHS_Session *session, bool enabled) {
    /* The lifecycle lock is never acquired by the worker. Join before
     * replacing its session pointer, outside the worker's state_lock. */
    pthread_mutex_lock(&hid_lifecycle_lock);
    hid_flush_thread_stop();
    pthread_mutex_lock(&state_lock);
    if (hid_session != session)
        rumble_reset_pending = true;
    hid_session = session;
    memset(remote_touches, 0, sizeof(remote_touches));
    hid_session_enabled = enabled;
#if NSL_DIAGNOSTICS
    if (session != NULL && enabled) {
        hid_events_total = 0;
        hid_send_ok_total = 0;
        hid_send_fail_total = 0;
        hid_state_full_total = 0;
        hid_raw_ax_total = 0;
        hid_raw_btn_total = 0;
        hid_style_flips_total = 0;
        hid_marker_minus_sdl_samples_total = 0;
        hid_marker_minus_raw_samples_total = 0;
        reset_hid_probe_baseline();
        hid_last_log_us = 0;
        snapshot.hid_events = 0;
        snapshot.hid_send_ok = 0;
        snapshot.hid_send_fail = 0;
        snapshot.hid_state_full = 0;
        snapshot.hid_raw_ax_total = 0;
        snapshot.hid_raw_btn_total = 0;
        snapshot.hid_style_flips_total = 0;
        snapshot.hid_marker_minus_sdl_held = false;
        snapshot.hid_marker_minus_raw_held = false;
        snapshot.hid_marker_minus_sdl_samples_total = 0;
        snapshot.hid_marker_minus_raw_samples_total = 0;
        strncpy(snapshot.hid_style_state, hid_style_last, sizeof(snapshot.hid_style_state) - 1);
        snapshot.hid_style_state[sizeof(snapshot.hid_style_state) - 1] = '\0';
        snapshot.hid_last_event_type = 0;
        snapshot.hid_last_event_which = -1;
        snapshot.hid_last_event_code = -1;
        snapshot.hid_last_event_value = 0;
    } else {
        reset_hid_probe_window();
        hid_last_log_us = 0;
    }
#endif
    pthread_mutex_unlock(&state_lock);
    if (session != NULL && enabled)
        hid_flush_thread_start();
    pthread_mutex_unlock(&hid_lifecycle_lock);
}

IHS_HIDProvider *stream_media_create_hid_provider(void) {
    open_hid_controller();
    IHS_HIDProvider *provider = IHS_HIDProviderSDLCreateUnmanaged(&HID_DEVICE_LIST, NULL);
    pthread_mutex_lock(&state_lock);
    snapshot.hid_provider_devices = provider != NULL ? hid_device_list_count(NULL) : 0;
    pthread_mutex_unlock(&state_lock);
    media_logf("hid provider created: SDL unmanaged devices=%d",
               provider != NULL ? hid_device_list_count(NULL) : 0);
    return provider;
}

void stream_media_destroy_hid_provider(IHS_HIDProvider *provider) {
    if (provider == NULL) {
        return;
    }
    IHS_HIDProviderSDLDestroy(provider);
    pthread_mutex_lock(&state_lock);
    snapshot.hid_provider_devices = 0;
    pthread_mutex_unlock(&state_lock);
}

int sl_media_video_start_tracked(IHS_Session *session, const IHS_VideoEpochInfo *epoch,
                                 const IHS_StreamVideoConfig *config) {
    (void)session;
    if (!video || config->codec != IHS_StreamVideoCodecH264)
        return -1;
    sl_video_reap(video);
    sl_video_config decoder = {.width = config->width,
                               .height = config->height,
                               .extradata = config->codecData,
                               .extradata_size = config->codecDataLen,
#if __SWITCH__
                               .hardware = true
#endif
    };
    sl_video_key key = {epoch->session_id, epoch->video_epoch};
    pthread_mutex_lock(&state_lock);
    video_key = key;
    snapshot.session_id = key.session;
    snapshot.video_epoch = key.epoch;
    snapshot.video_active = false;
    snapshot.first_frame_displayed = false;
    snapshot.render_failed = false;
    snapshot.decoded_frames = snapshot.displayed_frames = snapshot.dropped_frames = 0;
    snapshot.width = config->width;
    snapshot.height = config->height;
    pthread_mutex_unlock(&state_lock);
    if (!sl_video_open(video, key, &decoder)) {
        media_set_error("video domain unavailable or decoder initialization failed");
        return -1;
    }
    pthread_mutex_lock(&state_lock);
    snapshot.video_active = true;
    snprintf(snapshot.decoder, sizeof(snapshot.decoder), "h264 %s",
             decoder.hardware ? "nvtegra" : "software");
    snapshot.last_error[0] = 0;
    pthread_mutex_unlock(&state_lock);
    return 0;
}
IHS_StreamVideoSubmitResult
sl_media_video_submit_tracked(IHS_Session *session, const IHS_VideoEpochInfo *epoch, uint16_t id,
                              IHS_FrameTicket *ticket, IHS_Buffer *data,
                              IHS_StreamVideoFrameFlag flags, bool *taken) {
    (void)session;
    (void)id;
    (void)flags;
    if (!video) {
        *taken = false;
        return IHS_StreamVideoSubmitError;
    }
    bool ok = sl_video_submit(video, (sl_video_key){epoch->session_id, epoch->video_epoch},
                              IHS_BufferPointer(data), data->size, ticket, taken);
    if (!ok)
        media_set_error("video packet ownership or decode failure");
    return ok ? IHS_StreamVideoSubmitOK : IHS_StreamVideoSubmitError;
}
void sl_media_video_stop_tracked(IHS_Session *session, const IHS_VideoEpochInfo *epoch) {
    (void)session;
    if (!video)
        return;
    sl_video_key key = {epoch->session_id, epoch->video_epoch};
    sl_video_stop(video, key);
    pthread_mutex_lock(&state_lock);
    if (video_key.session == key.session && video_key.epoch == key.epoch)
        snapshot.video_active = false;
    pthread_mutex_unlock(&state_lock);
    sl_video_reap(video);
}
void sl_media_close_video(void) {
    if (video)
        sl_video_freeze(video);
}
void sl_media_allow_video(void) {
    if (video)
        sl_video_thaw(video);
}
bool sl_media_video_clean(void) {
    if (!video)
        return true;
    sl_video_reap(video);
    return sl_video_clean(video);
}

int stream_media_audio_start(IHS_Session *session, const IHS_StreamAudioConfig *config) {
    (void)session;
    if (config == NULL) {
        media_set_error("audio start missing config");
        return -1;
    }
    if (!sdl_ready) {
        media_set_error("audio start before SDL media init");
        return -1;
    }
    if (config->codec != IHS_StreamAudioCodecOpus) {
        media_set_error("unsupported audio codec=%d", (int)config->codec);
        return -1;
    }
    if (config->channels == 0 || config->channels > 2) {
        media_set_error("unsupported audio channels=%u", config->channels);
        return -1;
    }
    if (!opus_rate_supported(config->frequency)) {
        media_set_error("unsupported Opus audio frequency=%u", config->frequency);
        return -1;
    }

    int opus_err = OPUS_OK;
    OpusDecoder *decoder =
        opus_decoder_create((opus_int32)config->frequency, (int)config->channels, &opus_err);
    if (decoder == NULL || opus_err != OPUS_OK) {
        media_set_error("opus_decoder_create: %s", opus_strerror(opus_err));
        return -1;
    }

    SDL_AudioSpec want;
    SDL_AudioSpec have;
    SDL_zero(want);
    SDL_zero(have);
    want.freq = (int)config->frequency;
    want.format = AUDIO_S16LSB;
    want.channels = (Uint8)config->channels;
#if __SWITCH__
    want.samples = 960; /* Restore the device-tested pre-feedback Switch request. */
#else
    want.samples = 1024; /* Portable SDL/dummy requires power-of-two blocks. */
#endif
    want.callback = NULL;

    pthread_mutex_lock(&audio_lock);
    sl_audio_suspend(); /* Close the UI device before opening the stream device. */
    audio_stop_locked();
    SDL_AudioDeviceID device =
        SDL_OpenAudioDevice(NULL, 0, &want, &have, SDL_AUDIO_ALLOW_SAMPLES_CHANGE);
    if (device == 0) {
        sl_audio_init();
        pthread_mutex_unlock(&audio_lock);
        media_set_error("SDL_OpenAudioDevice: %s", SDL_GetError());
        opus_decoder_destroy(decoder);
        return -1;
    }
    if (have.freq != want.freq || have.format != want.format || have.channels != want.channels) {
        media_set_error("SDL audio format mismatch: got %dHz fmt=0x%x ch=%u", have.freq,
                        (unsigned)have.format, (unsigned)have.channels);
        SDL_CloseAudioDevice(device);
        sl_audio_init();
        pthread_mutex_unlock(&audio_lock);
        opus_decoder_destroy(decoder);
        return -1;
    }

    audio_decoder = decoder;
    audio_device = device;
    audio_frequency = have.freq;
    audio_channels = have.channels;
    audio_codec = config->codec;
    audio_active = true;
    audio_frames_total = 0;
    audio_bytes_total = 0;
    audio_decoded_samples_total = 0;
    audio_queue_drops_total = 0;
    audio_decode_errors_total = 0;
    SDL_PauseAudioDevice(audio_device, 0);
    pthread_mutex_unlock(&audio_lock);

    update_audio_snapshot();
    media_logf("audio start: codec=Opus freq=%d channels=%d samples=%u codecData=%zu", have.freq,
               have.channels, have.samples, config->codecDataLen);
    return 0;
}

int stream_media_audio_submit(IHS_Session *session, IHS_Buffer *data) {
    (void)session;
    if (data == NULL) {
        return -1;
    }

    char error[128] = "";
    int ret = 0;
    pthread_mutex_lock(&audio_lock);
    if (!audio_active || audio_decoder == NULL || audio_device == 0) {
        pthread_mutex_unlock(&audio_lock);
        return 0;
    }

    uint32_t queue_limit = audio_queue_limit_bytes(audio_frequency, audio_channels);
    uint32_t queued = SDL_GetQueuedAudioSize(audio_device);
    if (queue_limit > 0 && queued > queue_limit) {
        SDL_ClearQueuedAudio(audio_device);
        audio_queue_drops_total++;
    }

    const unsigned char *payload =
        data->size > 0 ? (const unsigned char *)IHS_BufferPointer(data) : NULL;
    int samples = opus_decode(audio_decoder, payload, (opus_int32)data->size, audio_decode_buf,
                              AUDIO_MAX_OPUS_FRAME_SAMPLES, 0);
    if (samples < 0) {
        audio_decode_errors_total++;
        ret = -1;
        if (audio_decode_errors_total <= 3 || (audio_decode_errors_total % 60U) == 0U) {
            snprintf(error, sizeof(error), "opus_decode: %s", opus_strerror(samples));
        }
    } else {
        uint32_t pcm_bytes =
            (uint32_t)samples * (uint32_t)audio_channels * (uint32_t)sizeof(opus_int16);
        if (atomic_load(&muted))
            memset(audio_decode_buf, 0, pcm_bytes);
        sl_audio_mix(audio_decode_buf, samples, audio_frequency, audio_channels);
        if (pcm_bytes > 0 && SDL_QueueAudio(audio_device, audio_decode_buf, pcm_bytes) != 0) {
            audio_decode_errors_total++;
            ret = -1;
            if (audio_decode_errors_total <= 3 || (audio_decode_errors_total % 60U) == 0U) {
                snprintf(error, sizeof(error), "SDL_QueueAudio: %s", SDL_GetError());
            }
        } else {
            audio_frames_total++;
            audio_bytes_total += pcm_bytes;
            audio_decoded_samples_total += (uint32_t)samples;
        }
    }
    pthread_mutex_unlock(&audio_lock);

    if (error[0] != '\0') {
        media_set_error("%s", error);
    }
    update_audio_snapshot();
    return ret;
}

void stream_media_audio_stop(IHS_Session *session) {
    (void)session;
    pthread_mutex_lock(&audio_lock);
    bool had_audio = audio_active || audio_device != 0 || audio_decoder != NULL;
    audio_stop_locked();
    if (!audio_shutting_down && sdl_ready)
        sl_audio_init();
    pthread_mutex_unlock(&audio_lock);

    update_audio_snapshot();
    if (had_audio) {
        media_logf("audio stopped");
    }
}

void sl_media_collect(void) {
    if (!sdl_ready)
        return;
    pump_sdl_events();
    sl_gfx_collect(gfx);
    if (!sl_events_foreground())
        sl_media_gate(false);
    if (current_frame && !sl_video_is_current(video, current_frame->key)) {
        sl_resource_release(&current_frame->ref);
        current_frame = NULL;
        sl_media_neutral(NULL);
        pthread_mutex_lock(&state_lock);
        layout_key = (sl_video_key){0};
        pthread_mutex_unlock(&state_lock);
    }
    pthread_mutex_lock(&state_lock);
    sl_video_key key = video_key;
    pthread_mutex_unlock(&state_lock);
    if (!sl_video_is_current(video, key))
        sl_gfx_forget_video(gfx);
}
void stream_media_present(void) {
    if (!sdl_ready)
        return;
    sl_media_collect();
    if (!sl_events_foreground() || sl_gfx_begin(gfx) != SL_GFX_READY)
        return;
    sl_video_frame *candidate = sl_video_take(video);
    if (candidate && !sl_video_is_current(video, candidate->key)) {
        sl_resource_release(&candidate->ref);
        candidate = NULL;
    }
    sl_video_frame *frame = candidate ? candidate : current_frame;
    sl_gfx_draw_color(gfx, 0, 0, 0, 255);
    sl_gfx_clear(gfx);
    uint64_t upload_begin = media_monotonic_us();
    bool drawn = frame && sl_gfx_video(gfx, frame);
    uint64_t upload_end = media_monotonic_us();
    if (candidate && !drawn) {
        media_set_error("video layout, import, or renderer capacity rejected");
        pthread_mutex_lock(&state_lock);
        if (snapshot.session_id == candidate->key.session &&
            snapshot.video_epoch == candidate->key.epoch)
            snapshot.render_failed = true;
        pthread_mutex_unlock(&state_lock);
        sl_video_close(video, candidate->key);
        if (current_frame)
            sl_gfx_video(gfx, current_frame);
    }
    if (draw_hook)
        draw_hook(gfx, hook_context);
    sl_gfx_present_result result = sl_gfx_present(gfx);
    uint64_t present_us = media_monotonic_us();
    if (candidate) {
        bool displayed = drawn && result.result == SL_GFX_READY && result.output_returned;
        if (presentation_key.session != candidate->key.session ||
            presentation_key.epoch != candidate->key.epoch) {
            presentation_key = candidate->key;
            presentation_serial = last_presentation_us = 0;
        }
        IHS_FrameOutcome outcome = {.result = displayed ? IHS_VideoFrameResultDisplayed
                                                        : IHS_VideoFrameResultDroppedLate,
                                    .completionUs = present_us};
        if (displayed) {
            outcome.presentationSerial = ++presentation_serial;
            outcome.hasPresentationInterval = last_presentation_us != 0;
            outcome.presentationIntervalUs =
                last_presentation_us ? present_us - last_presentation_us : 0;
            last_presentation_us = present_us;
            outcome.hasUpload = !NSL_GFX_DEKO || candidate->pixels->hw_frames_ctx == NULL;
            outcome.uploadBeginUs = upload_begin;
            outcome.uploadEndUs = upload_end;
        }
        sl_video_frame_complete(candidate, &outcome);
        bool active = sl_video_is_current(video, candidate->key);
        pthread_mutex_lock(&state_lock);
        if (video_key.session == candidate->key.session &&
            video_key.epoch == candidate->key.epoch) {
            if (!NSL_GFX_DEKO && candidate->pixels->hw_frames_ctx && drawn)
                snapshot.transferred_frames++;
            if (displayed && active) {
                int w = 1280, h = candidate->pixels->height * 1280 / candidate->pixels->width;
                if (h > 720) {
                    h = 720;
                    w = candidate->pixels->width * 720 / candidate->pixels->height;
                }
                video_rect = (SDL_Rect){(1280 - w) / 2, (720 - h) / 2, w, h};
                layout_key = candidate->key;
                snapshot.first_frame_displayed = true;
                snapshot.displayed_frames++;
                snapshot.last_displayed_frame = IHS_FrameTicketIdentity(candidate->ticket).frameId;
                snapshot.width = candidate->pixels->width;
                snapshot.height = candidate->pixels->height;
                if (outcome.hasUpload) {
                    snapshot.upload_samples++;
                    add_timing(&snapshot.upload_us_total, &snapshot.upload_us_max,
                               elapsed_us(upload_begin, upload_end));
                }
                add_timing(&snapshot.present_us_total, &snapshot.present_us_max,
                           elapsed_us(upload_end, present_us));
            } else
                snapshot.dropped_frames++;
        }
        pthread_mutex_unlock(&state_lock);
        if (displayed && active) {
            if (current_frame)
                sl_resource_release(&current_frame->ref);
            current_frame = candidate;
        } else
            sl_resource_release(&candidate->ref);
    }
}

void stream_media_get_snapshot(stream_media_snapshot *out) {
    if (out == NULL) {
        return;
    }
    bool audio_snap_active;
    uint32_t audio_snap_queued;
    uint32_t audio_snap_frames;
    uint64_t audio_snap_bytes;
    uint64_t audio_snap_samples;
    uint32_t audio_snap_drops;
    uint32_t audio_snap_errors;
    int audio_snap_codec;
    int audio_snap_channels;
    int audio_snap_frequency;

    pthread_mutex_lock(&audio_lock);
    audio_snap_active = audio_active;
    audio_snap_queued = audio_device != 0 ? SDL_GetQueuedAudioSize(audio_device) : 0;
    audio_snap_frames = audio_frames_total;
    audio_snap_bytes = audio_bytes_total;
    audio_snap_samples = audio_decoded_samples_total;
    audio_snap_drops = audio_queue_drops_total;
    audio_snap_errors = audio_decode_errors_total;
    audio_snap_codec = (int)audio_codec;
    audio_snap_channels = audio_channels;
    audio_snap_frequency = audio_frequency;
    pthread_mutex_unlock(&audio_lock);

    pthread_mutex_lock(&state_lock);
    sl_video_counters counters;
    if (video && sl_video_read_counters(video, video_key, &counters)) {
        snapshot.decoded_frames = snapshot.decode_samples = counters.decoded;
        snapshot.decode_us_total = counters.decode_total_us;
        snapshot.decode_us_max = counters.decode_max_us;
    }
    snapshot.audio_active = audio_snap_active;
    snapshot.audio_queued_bytes = audio_snap_queued;
    snapshot.audio_frames = audio_snap_frames;
    snapshot.audio_bytes = audio_snap_bytes;
    snapshot.audio_decoded_samples = audio_snap_samples;
    snapshot.audio_queue_drops = audio_snap_drops;
    snapshot.audio_decode_errors = audio_snap_errors;
    snapshot.audio_codec = audio_snap_codec;
    snapshot.audio_channels = audio_snap_channels;
    snapshot.audio_frequency = audio_snap_frequency;
#if NSL_DIAGNOSTICS
    snapshot.hid_events = hid_events_total;
    snapshot.hid_send_ok = hid_send_ok_total;
    snapshot.hid_send_fail = hid_send_fail_total;
    snapshot.hid_state_full = hid_state_full_total;
    snapshot.hid_raw_ax_total = hid_raw_ax_total;
    snapshot.hid_raw_btn_total = hid_raw_btn_total;
    snapshot.hid_style_flips_total = hid_style_flips_total;
    snapshot.hid_marker_minus_sdl_held = hid_marker_minus_sdl_held;
    snapshot.hid_marker_minus_raw_held = hid_marker_minus_raw_held;
    snapshot.hid_marker_minus_sdl_samples_total = hid_marker_minus_sdl_samples_total;
    snapshot.hid_marker_minus_raw_samples_total = hid_marker_minus_raw_samples_total;
    /* Protocol statistics are sampled by runtime owner, never while holding this UI lock. */
    strncpy(snapshot.hid_style_state, hid_style_last, sizeof(snapshot.hid_style_state) - 1);
    snapshot.hid_style_state[sizeof(snapshot.hid_style_state) - 1] = '\0';
#endif
    *out = snapshot;
    pthread_mutex_unlock(&state_lock);
}

size_t stream_media_copy_hid_history(stream_media_hid_history_entry *out, size_t max_entries) {
#if NSL_DIAGNOSTICS

    if (out == NULL || max_entries == 0) {
        return 0;
    }
    if (max_entries > HID_HISTORY_CAP) {
        max_entries = HID_HISTORY_CAP;
    }
    pthread_mutex_lock(&state_lock);
    uint32_t count = hid_history_count < max_entries ? hid_history_count : (uint32_t)max_entries;
    uint32_t start = (hid_history_next + HID_HISTORY_CAP - count) % HID_HISTORY_CAP;
    for (uint32_t i = 0; i < count; i++) {
        out[i] = hid_history[(start + i) % HID_HISTORY_CAP];
    }
    pthread_mutex_unlock(&state_lock);
    return count;

#else
    (void)out;
    (void)max_entries;
    return 0;
#endif
}

void stream_media_format_hid_history(char *out, size_t out_len, uint32_t max_entries) {
#if NSL_DIAGNOSTICS

    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (max_entries == 0 || max_entries > HID_HISTORY_CAP) {
        max_entries = HID_HISTORY_CAP;
    }
    stream_media_hid_history_entry entries[HID_HISTORY_CAP];
    uint32_t total_count;
    pthread_mutex_lock(&state_lock);
    uint32_t count = hid_history_count < max_entries ? hid_history_count : max_entries;
    uint32_t start = (hid_history_next + HID_HISTORY_CAP - count) % HID_HISTORY_CAP;
    for (uint32_t i = 0; i < count; i++) {
        entries[i] = hid_history[(start + i) % HID_HISTORY_CAP];
    }
    total_count = hid_history_count;
    pthread_mutex_unlock(&state_lock);

    size_t used = (size_t)snprintf(out, out_len, "count=%u total=%u", count, total_count);
    if (used >= out_len) {
        out[out_len - 1] = '\0';
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        const stream_media_hid_history_entry *e = &entries[i];
        int written =
            snprintf(out + used, out_len - used,
                     " | #%u t=%u e=%u ok=%u f=%u h=%u p=%u ax=%u btn=%u sen=%u oth=%u sup=%u "
                     "raw=%u/%u sty=%u:%s sticks=%d/%d/%d/%d b=0x%x minus=%u/%u/%u/%u "
                     "tot=%u/%u/%u/%u/%u last=%d/%d/%d/%d",
                     e->seq, e->sec, e->events, e->send_ok, e->send_fail, e->state_full, e->pump,
                     e->ax, e->btn, e->sen, e->oth, e->ev_sup, e->raw_ax, e->raw_btn, e->sty_fl,
                     e->sty[0] ? e->sty : "-", e->left_x, e->left_y, e->right_x, e->right_y,
                     e->buttons, e->marker_minus_sdl_held, e->marker_minus_sdl_samples,
                     e->marker_minus_raw_held, e->marker_minus_raw_samples, e->events_total,
                     e->send_ok_total, e->state_full_total, e->raw_ax_total, e->raw_btn_total,
                     e->last_type, e->last_which, e->last_code, e->last_value);
        if (written < 0) {
            break;
        }
        if ((size_t)written >= out_len - used) {
            out[out_len - 1] = '\0';
            break;
        }
        used += (size_t)written;
    }

#else
    (void)max_entries;
    if (out && out_len)
        out[0] = 0;
#endif
}

/* Compatibility entry points for local media fixtures. Production registers
 * the tracked IHS callbacks and never routes a renderer through a session. */
int stream_media_video_start(IHS_Session *session, const IHS_StreamVideoConfig *config) {
    stream_media_video_stop(session);
    sl_media_allow_video();
    test_tracker = IHS_FrameTrackerCreate(++test_session_id);
    if (!test_tracker || !IHS_FrameTrackerOpenEpoch(test_tracker, 1))
        return -1;
    IHS_VideoEpochInfo epoch = {test_session_id, 1};
    return sl_media_video_start_tracked(session, &epoch, config);
}
IHS_StreamVideoSubmitResult stream_media_video_submit(IHS_Session *session, uint16_t id,
                                                      IHS_Buffer *data,
                                                      IHS_StreamVideoFrameFlag flags) {
    if (!test_tracker)
        return IHS_StreamVideoSubmitError;
    uint64_t now = media_monotonic_us();
    IHS_TrackedFrame settled[16];
    while (IHS_FrameTrackerSettle(test_tracker, now, 2000000, settled, 16) == 16) {
    }
    IHS_FrameReceive received = {.firstReceiveUs = now, .lastReceiveUs = now};
    IHS_FrameTicket *ticket;
    if (IHS_FrameTrackerBegin(test_tracker, 1, id, &received, &ticket) != IHS_FrameBeginOK)
        return IHS_StreamVideoSubmitError;
    IHS_VideoEpochInfo epoch = {test_session_id, 1};
    bool taken = false;
    IHS_StreamVideoSubmitResult result =
        sl_media_video_submit_tracked(session, &epoch, id, ticket, data, flags, &taken);
    IHS_FrameTicketRelease(ticket);
    return result;
}
void stream_media_video_stop(IHS_Session *session) {
    if (!video)
        return;
    pthread_mutex_lock(&state_lock);
    IHS_VideoEpochInfo epoch = {video_key.session, video_key.epoch};
    pthread_mutex_unlock(&state_lock);
    sl_media_video_stop_tracked(session, &epoch);
    if (test_tracker) {
        IHS_FrameTrackerClose(test_tracker);
        test_tracker = NULL;
    }
}

void sl_media_hooks(void (*draw)(void *, void *), void (*event)(const void *, void *),
                    void *context) {
    draw_hook = draw;
    event_hook = event;
    hook_context = context;
}
sl_gfx *sl_media_gfx(void) {
    return gfx;
}
void sl_media_mute(bool mute) {
    atomic_store(&muted, mute);
}
static void neutral_locked(void) {
    if (hid_session) {
        IHS_HIDResetSDLGameControllers(hid_session);
        for (unsigned i = 0; i < 8; ++i)
            if (remote_touches[i].active)
                IHS_SessionSendTouchUp(hid_session, remote_touches[i].id, 0, 0);
    }
    memset(remote_touches, 0, sizeof(remote_touches));
}
void sl_media_gate(bool enabled) {
    if (atomic_load(&input_gate) == enabled)
        return;
    pthread_mutex_lock(&state_lock);
    if (input_gate && !enabled)
        neutral_locked();
    input_gate = enabled;
    pthread_mutex_unlock(&state_lock);
}
void sl_media_neutral(void *context) {
    (void)context;
    pthread_mutex_lock(&state_lock);
    neutral_locked();
    pthread_mutex_unlock(&state_lock);
}
void sl_media_input(const sl_input_event *e, void *context) {
    (void)context;
    pthread_mutex_lock(&state_lock);
    IHS_Session *session = hid_session;
    if (!session) {
        pthread_mutex_unlock(&state_lock);
        return;
    }
    if (e->type == SL_TOUCH_DOWN || e->type == SL_TOUCH_MOVE || e->type == SL_TOUCH_UP) {
        if (e->type != SL_TOUCH_UP &&
            (!layout_key.session || layout_key.session != snapshot.session_id ||
             layout_key.epoch != snapshot.video_epoch)) {
            pthread_mutex_unlock(&state_lock);
            return;
        }
        float x = (e->x * 1280 - video_rect.x) / (video_rect.w ? video_rect.w : 1280);
        float y = (e->y * 720 - video_rect.y) / (video_rect.h ? video_rect.h : 720);
        int slot = -1;
        for (int i = 0; i < 8; ++i)
            if (remote_touches[i].active && remote_touches[i].id == e->finger)
                slot = i;
        if (e->type == SL_TOUCH_DOWN) {
            if (x < 0 || x > 1 || y < 0 || y > 1 || !input_gate) {
                pthread_mutex_unlock(&state_lock);
                return;
            }
            for (int i = 0; i < 8; ++i)
                if (!remote_touches[i].active) {
                    slot = i;
                    break;
                }
            if (slot >= 0 && IHS_SessionSendTouchDown(session, e->finger, x, y)) {
                remote_touches[slot].active = true;
                remote_touches[slot].id = e->finger;
            }
        } else if (slot >= 0) {
            x = x < 0 ? 0 : x > 1 ? 1 : x;
            y = y < 0 ? 0 : y > 1 ? 1 : y;
            if (e->type == SL_TOUCH_MOVE && input_gate)
                IHS_SessionSendTouchMotion(session, e->finger, x, y);
            if (e->type == SL_TOUCH_UP) {
                IHS_SessionSendTouchUp(session, e->finger, x, y);
                remote_touches[slot].active = false;
            }
        }
    } else if (input_gate) {
        SDL_Event event = {0};
        if (e->type == SL_BUTTON) {
            event.type = e->value ? SDL_CONTROLLERBUTTONDOWN : SDL_CONTROLLERBUTTONUP;
            event.cbutton.which = hid_controller_id;
            event.cbutton.button = e->code;
            event.cbutton.state = e->value ? SDL_PRESSED : SDL_RELEASED;
        }
        if (e->type == SL_AXIS) {
            event.type = SDL_CONTROLLERAXISMOTION;
            event.caxis.which = hid_controller_id;
            event.caxis.axis = e->code;
            event.caxis.value = e->value;
        }
        if (event.type) {
#if NSL_DIAGNOSTICS
            if (IHS_HIDHandleSDLEvent(session, &event))
                hid_events_total++;
#else
            IHS_HIDHandleSDLEvent(session, &event);
#endif
            if (e->immediate)
                IHS_HIDFlushSDLGameControllers(session);
        }
    }
    pthread_mutex_unlock(&state_lock);
}

void sl_media_submitted(const IHS_HIDSDLLastSubmitted *value) {
#if NSL_DIAGNOSTICS

    pthread_mutex_lock(&state_lock);
    submitted_cache = *value;
    pthread_mutex_unlock(&state_lock);

#else
    (void)value;
#endif
}
