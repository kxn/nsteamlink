#include "media.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

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

#ifndef NSTREAMLINK_APP
#define NSTREAMLINK_APP 0
#endif

#if NSTREAMLINK_APP
#include <ihslib/hid/sdl.h>
#endif

#define SDL_WIDTH  1920
#define SDL_HEIGHT 1080

static SDL_Window *sdl_window;
static SDL_Renderer *sdl_renderer;
static SDL_Texture *video_texture;
static SDL_AudioDeviceID audio_device;
static SDL_Joystick *joysticks[2];
static bool sdl_initialized;
static bool sdl_ready;
static bool sdl_exit_requested;
static int texture_width;
static int texture_height;
static Uint32 texture_format;
static bool nv12_texture_failed;

static pthread_mutex_t frame_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t audio_lock = PTHREAD_MUTEX_INITIALIZER;

static AVCodecContext *decoder_ctx;
static AVBufferRef *hw_device_ctx;
static enum AVPixelFormat hw_pix_fmt = AV_PIX_FMT_NONE;
static AVPacket *packet;
static AVFrame *decode_frame;
static AVFrame *latched_frame;
static AVFrame *present_frame;
static struct SwsContext *sws;
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
#define AUDIO_QUEUE_LIMIT_MS 300U
static opus_int16 audio_decode_buf[AUDIO_MAX_OPUS_FRAME_SAMPLES * 2];

static IHS_Session *stats_session;
#if NSTREAMLINK_APP
static IHS_Session *hid_session;
static bool hid_session_enabled;
static bool hid_frame_dirty;
static SDL_GameController *hid_controller;
static SDL_JoystickID hid_controller_id = -1;
static int hid_controller_index = -1;
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
static uint64_t hid_last_full_us;
static uint64_t hid_last_log_us;
/* 100ms forced full-state heartbeat; bounded input staleness after packet loss. */
#define HID_FULL_REFRESH_US 100000ULL
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
static stream_media_ui ui_state;
static bool frame_dirty;
static uint16_t pending_frame_id;
static uint64_t pending_submit_us;
static uint64_t pending_latch_us;
static bool need_flush;
static bool have_last_frame;
static uint16_t last_frame_id;
static bool logged_alignment_fallback;
static bool logged_vic_transfer;
static bool logged_vic_prepare_fallback;
static bool logged_vic_transfer_retry;
static enum AVPixelFormat logged_convert_format = AV_PIX_FMT_NONE;

static void media_logf(const char *fmt, ...);
static bool opus_rate_supported(uint32_t rate);
static uint32_t audio_queue_limit_bytes(int frequency, int channels);
static void audio_stop_locked(void);
static void update_audio_snapshot(void);

#if NSTREAMLINK_APP
static bool open_hid_controller(void);
static void close_hid_controller(void);
static void record_hid_event(const SDL_Event *event);
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
    static bool installed;
    if (installed) {
        return;
    }
    int rc = SDL_GameControllerAddMapping(SWITCH_FACE_LABEL_MAPPING);
    media_logf("hid sdl mapping override: rc=%d faceLabels=ABXY", rc);
    if (rc < 0) {
        media_logf("hid sdl mapping override failed: %s", SDL_GetError());
    }
    installed = true;
}
#endif

static const uint8_t *font_rows(char c) {
    static const uint8_t blank[7] = {0, 0, 0, 0, 0, 0, 0};
    static const uint8_t unknown[7] = {0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04};
    static const uint8_t glyphs[][7] = {
        {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E}, /* 0 */
        {0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E}, /* 1 */
        {0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F}, /* 2 */
        {0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E}, /* 3 */
        {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02}, /* 4 */
        {0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E}, /* 5 */
        {0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E}, /* 6 */
        {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08}, /* 7 */
        {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E}, /* 8 */
        {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C}, /* 9 */
        {0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11}, /* A */
        {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E}, /* B */
        {0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E}, /* C */
        {0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E}, /* D */
        {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F}, /* E */
        {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10}, /* F */
        {0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F}, /* G */
        {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11}, /* H */
        {0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E}, /* I */
        {0x07, 0x02, 0x02, 0x02, 0x12, 0x12, 0x0C}, /* J */
        {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11}, /* K */
        {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F}, /* L */
        {0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11}, /* M */
        {0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11}, /* N */
        {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E}, /* O */
        {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10}, /* P */
        {0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D}, /* Q */
        {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11}, /* R */
        {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E}, /* S */
        {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04}, /* T */
        {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E}, /* U */
        {0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04}, /* V */
        {0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0A}, /* W */
        {0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11}, /* X */
        {0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04}, /* Y */
        {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F}, /* Z */
    };
    static const uint8_t colon[7] = {0, 0x04, 0x04, 0, 0x04, 0x04, 0};
    static const uint8_t dot[7] = {0, 0, 0, 0, 0, 0x0C, 0x0C};
    static const uint8_t dash[7] = {0, 0, 0, 0x1F, 0, 0, 0};
    static const uint8_t slash[7] = {0x01, 0x01, 0x02, 0x04, 0x08, 0x10, 0x10};
    static const uint8_t plus[7] = {0, 0x04, 0x04, 0x1F, 0x04, 0x04, 0};
    static const uint8_t eq[7] = {0, 0, 0x1F, 0, 0x1F, 0, 0};
    static const uint8_t lt[7] = {0x02, 0x04, 0x08, 0x10, 0x08, 0x04, 0x02};
    static const uint8_t gt[7] = {0x08, 0x04, 0x02, 0x01, 0x02, 0x04, 0x08};
    static const uint8_t lbr[7] = {0x0E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x0E};
    static const uint8_t rbr[7] = {0x0E, 0x02, 0x02, 0x02, 0x02, 0x02, 0x0E};
    static const uint8_t excl[7] = {0x04, 0x04, 0x04, 0x04, 0x04, 0, 0x04};

    if (c >= 'a' && c <= 'z') {
        c = (char)toupper((unsigned char)c);
    }
    if (c == ' ') {
        return blank;
    }
    if (c >= '0' && c <= '9') {
        return glyphs[c - '0'];
    }
    if (c >= 'A' && c <= 'Z') {
        return glyphs[10 + c - 'A'];
    }
    switch (c) {
    case ':':
        return colon;
    case '.':
        return dot;
    case '-':
    case '_':
        return dash;
    case '/':
        return slash;
    case '+':
        return plus;
    case '=':
        return eq;
    case '<':
    case '(':
        return lt;
    case '>':
    case ')':
        return gt;
    case '[':
        return lbr;
    case ']':
        return rbr;
    case '!':
        return excl;
    case '?':
        return unknown;
    default:
        return unknown;
    }
}

static void draw_text(const char *text, int x, int y, int scale, SDL_Color color) {
    if (text == NULL || scale <= 0) {
        return;
    }
    SDL_SetRenderDrawColor(sdl_renderer, color.r, color.g, color.b, color.a);
    int cursor = x;
    for (const char *p = text; *p != '\0'; p++) {
        const uint8_t *rows = font_rows(*p);
        for (int row = 0; row < 7; row++) {
            for (int col = 0; col < 5; col++) {
                if ((rows[row] & (1U << (4 - col))) == 0) {
                    continue;
                }
                SDL_Rect px = {cursor + col * scale, y + row * scale, scale, scale};
                SDL_RenderFillRect(sdl_renderer, &px);
            }
        }
        cursor += 6 * scale;
    }
}

static void draw_ui_overlay(void) {
    stream_media_ui ui;
    pthread_mutex_lock(&state_lock);
    ui = ui_state;
    pthread_mutex_unlock(&state_lock);
    if (!ui.visible || sdl_renderer == NULL) {
        return;
    }

    int w = SDL_WIDTH;
    int h = SDL_HEIGHT;
    SDL_GetWindowSize(sdl_window, &w, &h);

    SDL_SetRenderDrawBlendMode(sdl_renderer, SDL_BLENDMODE_BLEND);
    if (ui.dim_background) {
        SDL_SetRenderDrawColor(sdl_renderer, 0, 0, 0, 150);
        SDL_Rect dim = {0, 0, w, h};
        SDL_RenderFillRect(sdl_renderer, &dim);
    }

    SDL_Color title = {240, 246, 255, 255};
    SDL_Color body = {210, 224, 238, 255};
    SDL_Color muted = {134, 155, 176, 255};
    if (ui.dim_background) {
        SDL_SetRenderDrawColor(sdl_renderer, 10, 12, 16, 220);
        SDL_Rect panel = {48, 48, w - 96, h - 96};
        SDL_RenderFillRect(sdl_renderer, &panel);
        SDL_SetRenderDrawColor(sdl_renderer, 66, 153, 225, 255);
        SDL_Rect top = {48, 48, w - 96, 6};
        SDL_RenderFillRect(sdl_renderer, &top);

        if (ui.title[0] != '\0') {
            draw_text(ui.title, 78, 82, 5, title);
        }

        int y = 184;
        for (int i = 0; i < STREAM_MEDIA_UI_LINES; i++) {
            if (ui.lines[i][0] == '\0') {
                continue;
            }
            SDL_Color color = i >= STREAM_MEDIA_UI_LINES - 2 ? muted : body;
            draw_text(ui.lines[i], 82, y, 3, color);
            y += 44;
        }
    } else {
        int line_count = 0;
        for (int i = 0; i < STREAM_MEDIA_UI_LINES; i++) {
            if (ui.lines[i][0] != '\0') {
                line_count++;
            }
        }
        int panel_h = 58 + line_count * 28;
        if (panel_h < 96) {
            panel_h = 96;
        }
        SDL_SetRenderDrawColor(sdl_renderer, 10, 12, 16, 165);
        SDL_Rect panel = {28, 28, 980, panel_h};
        SDL_RenderFillRect(sdl_renderer, &panel);
        SDL_SetRenderDrawColor(sdl_renderer, 66, 153, 225, 230);
        SDL_Rect top = {28, 28, 980, 4};
        SDL_RenderFillRect(sdl_renderer, &top);

        if (ui.title[0] != '\0') {
            draw_text(ui.title, 50, 48, 3, title);
        }
        int y = 88;
        for (int i = 0; i < STREAM_MEDIA_UI_LINES; i++) {
            if (ui.lines[i][0] == '\0') {
                continue;
            }
            SDL_Color color = i >= STREAM_MEDIA_UI_LINES - 2 ? muted : body;
            draw_text(ui.lines[i], 50, y, 2, color);
            y += 28;
        }
    }

    SDL_SetRenderDrawBlendMode(sdl_renderer, SDL_BLENDMODE_NONE);
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

static void media_log_av_error(const char *prefix, int err) {
    char errbuf[AV_ERROR_MAX_STRING_SIZE];
    av_strerror(err, errbuf, sizeof(errbuf));
    media_set_error("%s: %s (%d)", prefix, errbuf, err);
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
    return rate == 8000U || rate == 12000U || rate == 16000U ||
           rate == 24000U || rate == 48000U;
}

static uint32_t audio_queue_limit_bytes(int frequency, int channels) {
    if (frequency <= 0 || channels <= 0) {
        return 0;
    }
    uint64_t bytes = (uint64_t)frequency * (uint64_t)channels *
                     sizeof(opus_int16) * AUDIO_QUEUE_LIMIT_MS / 1000U;
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

#if NSTREAMLINK_APP
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

    IHS_HIDSDLLastSubmitted last_submitted;
    memset(&last_submitted, 0, sizeof(last_submitted));
    pthread_mutex_lock(&state_lock);
    IHS_Session *report_session = hid_session;
    pthread_mutex_unlock(&state_lock);
    bool have_sent = report_session != NULL &&
                     IHS_HIDSDLGetLastSubmittedReport(report_session, &last_submitted);

    pthread_mutex_lock(&state_lock);
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
    strncpy(entry->sty, hid_style_last, sizeof(entry->sty) - 1);
    if (have_sent) {
        entry->sent_lx = last_submitted.axes[0];
        entry->sent_ly = last_submitted.axes[1];
        entry->sent_rx = last_submitted.axes[2];
        entry->sent_ry = last_submitted.axes[3];
        entry->sent_buttons = last_submitted.buttons;
        entry->sent_seq = (uint32_t) last_submitted.seq;
    }

    hid_history_next = (hid_history_next + 1U) % HID_HISTORY_CAP;
    if (hid_history_count < HID_HISTORY_CAP) {
        hid_history_count++;
    }
    pthread_mutex_unlock(&state_lock);
}

static void snapshot_hid_controller(int joystick_count, int controller_index,
                                    SDL_JoystickID instance_id,
                                    int controller_type, const char *guid,
                                    const char *name, int provider_devices) {
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
        media_logf("hid sdl device[%d]: instance=%d isController=%d type=%d name=%s guid=%s mapping=%s",
                   i, (int)SDL_JoystickGetDeviceInstanceID(i),
                   (int)SDL_IsGameController(i),
                   (int)SDL_GameControllerTypeForIndex(i),
                   SDL_JoystickNameForIndex(i) ? SDL_JoystickNameForIndex(i) : "-",
                   guid[0] ? guid : "-",
                   mapping != NULL ? mapping : "-");
        if (mapping != NULL) {
            SDL_free(mapping);
        }
    }
}

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
        media_set_error("No SDL game controller available for HID");
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
    SDL_JoystickGUID joystick_guid = SDL_JoystickGetGUID(joystick);
    char guid[40];
    SDL_JoystickGetGUIDString(joystick_guid, guid, sizeof(guid));
    const char *name = SDL_GameControllerName(hid_controller);
    if (name == NULL) {
        name = SDL_JoystickName(joystick);
    }
    int type = (int)SDL_GameControllerGetType(hid_controller);
    snapshot_hid_controller(count, hid_controller_index, hid_controller_id,
                            type, guid, name, 1);

    char *mapping = SDL_GameControllerMapping(hid_controller);
    media_logf("hid controller selected: index=%d instance=%d type=%d name=%s guid=%s mapping=%s",
               hid_controller_index, (int)hid_controller_id, type,
               name ? name : "-", guid[0] ? guid : "-",
               mapping != NULL ? mapping : "-");
    if (mapping != NULL) {
        SDL_free(mapping);
    }
    return true;
}

static void close_hid_controller(void) {
    if (hid_controller != NULL) {
        media_logf("hid controller close: index=%d instance=%d",
                   hid_controller_index, (int)hid_controller_id);
        SDL_GameControllerClose(hid_controller);
        hid_controller = NULL;
    }
    hid_controller_id = -1;
    hid_controller_index = -1;
    snapshot_hid_controller(0, -1, -1, 0, NULL, NULL, 0);
}

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

static void sample_sdl_marker_minus(void) {
    bool held = hid_controller != NULL &&
                SDL_GameControllerGetButton(hid_controller, SDL_CONTROLLER_BUTTON_BACK) != 0;
    hid_marker_minus_sdl_held = held;
    if (held) {
        hid_marker_minus_sdl_samples_since_log++;
        hid_marker_minus_sdl_samples_total++;
    }
}
#endif

#if NSTREAMLINK_APP && __SWITCH__
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
    if (hid_raw_have_prev &&
        (left.x != hid_raw_prev_x || left.y != hid_raw_prev_y)) {
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

static void pump_sdl_events(void) {
    SDL_Event event;
#if NSTREAMLINK_APP
    IHS_Session *event_hid_session = NULL;
    bool hid_enabled = false;
    bool hid_changed = false;
    uint64_t pump_age_ms_total = 0;
    uint32_t pump_age_samples = 0;
    uint32_t pump_age_ms_max = 0;

    pthread_mutex_lock(&state_lock);
    event_hid_session = hid_session;
    hid_enabled = hid_session_enabled;
    pthread_mutex_unlock(&state_lock);
    hid_pump_calls_since_log++;
#if __SWITCH__
    sample_raw_npad();
#endif
#endif

    while (SDL_PollEvent(&event)) {
#if NSTREAMLINK_APP
        record_hid_event(&event);
        if (hid_enabled && event_hid_session != NULL &&
            IHS_HIDHandleSDLEvent(event_hid_session, &event)) {
            hid_changed = true;
            hid_events_since_log++;
            hid_events_total++;
            uint32_t ev_age_ms =
                (uint32_t)(SDL_GetTicks() > event.common.timestamp
                               ? SDL_GetTicks() - event.common.timestamp
                               : 0);
            pump_age_ms_total += ev_age_ms;
            pump_age_samples++;
            if (ev_age_ms > pump_age_ms_max) {
                pump_age_ms_max = ev_age_ms;
            }
            switch (event.type) {
                case SDL_CONTROLLERAXISMOTION:
                    hid_axis_since_log++;
                    break;
                case SDL_CONTROLLERBUTTONDOWN:
                case SDL_CONTROLLERBUTTONUP:
                    hid_button_since_log++;
                    break;
                case SDL_CONTROLLERSENSORUPDATE:
                    hid_sensor_since_log++;
                    break;
                default:
                    hid_other_since_log++;
                    break;
            }
        }
        if (event.type == SDL_CONTROLLERBUTTONDOWN ||
            event.type == SDL_CONTROLLERBUTTONUP ||
            event.type == SDL_CONTROLLERAXISMOTION ||
            event.type == SDL_CONTROLLERSENSORUPDATE) {
            if (hid_trace_lines_this_sec < HID_TRACE_BUDGET_PER_SEC) {
                const char *kind = event.type == SDL_CONTROLLERAXISMOTION ? "axis" :
                                   (event.type == SDL_CONTROLLERBUTTONDOWN ? "btn-down" :
                                   (event.type == SDL_CONTROLLERBUTTONUP ? "btn-up" : "sensor"));
                int code = event.type == SDL_CONTROLLERAXISMOTION ? (int) event.caxis.axis :
                           (int) event.cbutton.button;
                int value = event.type == SDL_CONTROLLERAXISMOTION ? (int) event.caxis.value :
                            (event.type == SDL_CONTROLLERSENSORUPDATE ? -1 :
                             (int) event.cbutton.state);
                media_logf("hid ev %s which=%d code=%d value=%d", kind,
                           event.type == SDL_CONTROLLERAXISMOTION ? (int) event.caxis.which :
                           (int) event.cbutton.which, code, value);
                hid_trace_lines_this_sec++;
            } else {
                hid_trace_suppressed++;
            }
        }
#endif
        switch (event.type) {
            case SDL_QUIT:
                media_logf("SDL_QUIT received");
                sdl_exit_requested = true;
                break;
#if !NSTREAMLINK_APP
            case SDL_JOYBUTTONDOWN:
                media_logf("SDL joystick %d button %d down",
                           (int)event.jbutton.which, (int)event.jbutton.button);
                if (event.jbutton.which == 0 && event.jbutton.button == 10) {
                    sdl_exit_requested = true;
                }
                break;
#endif
            default:
                break;
        }
    }
#if NSTREAMLINK_APP
    sample_sdl_marker_minus();
    if (hid_changed && event_hid_session != NULL) {
        /* Plume semantics: one HID packet per frame at most, carrying the
         * coalesced state - present() flushes the flag once per vsync frame.
         * Per-event sends burst dozens of reliable packets per second and are
         * the input-path divergence from every working client. */
        hid_frame_dirty = true;
    }
    if (hid_enabled && event_hid_session != NULL && pump_age_samples > 0) {
        pthread_mutex_lock(&state_lock);
        snapshot.hid_age_samples += pump_age_samples;
        snapshot.hid_age_ms_total += pump_age_ms_total;
        if (pump_age_ms_max > snapshot.hid_age_ms_max) {
            snapshot.hid_age_ms_max = pump_age_ms_max;
        }
        pthread_mutex_unlock(&state_lock);
    }
    if (hid_enabled && event_hid_session != NULL) {
        uint64_t now_us = media_monotonic_us();
        if (hid_last_log_us == 0) {
            hid_last_log_us = now_us;
            hid_last_full_us = 0;
        }
        /* Keep a low-rate complete-state heartbeat even when SDL emits no event. */
        if (now_us - hid_last_full_us >= HID_FULL_REFRESH_US) {
            bool refreshed = IHS_HIDRefreshSDLGameControllers(event_hid_session);
            if (refreshed) {
                hid_state_full_since_log++;
                hid_state_full_total++;
            }
            hid_last_full_us = now_us;
        }
        if (elapsed_us(hid_last_log_us, now_us) >= 1000000U) {
            record_hid_history(now_us);
            media_logf("hid summary: events=%u send_ok=%u send_fail=%u stateFull=%u"
                       " pump=%u ax=%u btn=%u sen=%u oth=%u evSup=%u rawAx=%u rawBtn=%u styFl=%u(%s)",
                       hid_events_since_log, hid_send_ok_since_log,
                       hid_send_fail_since_log, hid_state_full_since_log,
                       hid_pump_calls_since_log, hid_axis_since_log,
                       hid_button_since_log, hid_sensor_since_log,
                       hid_other_since_log, hid_trace_suppressed,
                       hid_raw_ax_since_log, hid_raw_btn_since_log,
                       hid_style_flips_since_log, hid_style_last);
            reset_hid_probe_window();
            hid_last_log_us = now_us;
        }
    } else {
        reset_hid_probe_window();
        hid_last_log_us = 0;
        hid_last_full_us = 0;
    }
#endif
}

static void draw_idle_indicator(void) {
    if (!sdl_ready || sdl_renderer == NULL) {
        return;
    }

    static int tick;
    tick = (tick + 1) % 180;

    int w = SDL_WIDTH;
    int h = SDL_HEIGHT;
    SDL_GetWindowSize(sdl_window, &w, &h);

    SDL_SetRenderDrawColor(sdl_renderer, 14, 15, 18, 255);
    SDL_RenderClear(sdl_renderer);

    SDL_SetRenderDrawColor(sdl_renderer, 46, 51, 58, 255);
    SDL_Rect rail = {32, h - 72, w - 64, 12};
    SDL_RenderFillRect(sdl_renderer, &rail);

    int span = w - 64 - 144;
    if (span < 1) {
        span = 1;
    }
    int pos = (tick * span) / 179;
    SDL_SetRenderDrawColor(sdl_renderer, 39, 174, 96, 255);
    SDL_Rect bar = {32 + pos, h - 88, 144, 42};
    SDL_RenderFillRect(sdl_renderer, &bar);

    SDL_SetRenderDrawColor(sdl_renderer, 245, 166, 35, 255);
    SDL_Rect marker = {24, 24, 42, 42};
    SDL_RenderFillRect(sdl_renderer, &marker);

    draw_ui_overlay();
    SDL_RenderPresent(sdl_renderer);
}

bool stream_media_init(stream_media_log_fn log_fn) {
    if (sdl_ready) {
        return true;
    }
    log_cb = log_fn;
    memset(&snapshot, 0, sizeof(snapshot));
    sdl_exit_requested = false;

    av_log_set_level(AV_LOG_WARNING);
    av_log_set_callback(ffmpeg_log_callback);

    latched_frame = av_frame_alloc();
    present_frame = av_frame_alloc();
    if (latched_frame == NULL || present_frame == NULL) {
        media_set_error("media frame allocation failed");
        stream_media_shutdown();
        return false;
    }

    Uint32 init_flags = SDL_INIT_VIDEO;
#if NSTREAMLINK_APP
    init_flags |= SDL_INIT_GAMECONTROLLER | SDL_INIT_AUDIO;
#else
    init_flags |= SDL_INIT_JOYSTICK;
#endif
    if (SDL_Init(init_flags) < 0) {
        media_set_error("SDL_Init: %s", SDL_GetError());
        stream_media_shutdown();
        return false;
    }
    sdl_initialized = true;

    sdl_window = SDL_CreateWindow("nsteamlink", 0, 0, SDL_WIDTH, SDL_HEIGHT, 0);
    if (sdl_window == NULL) {
        media_set_error("SDL_CreateWindow: %s", SDL_GetError());
        stream_media_shutdown();
        return false;
    }

    sdl_renderer = SDL_CreateRenderer(sdl_window, 0,
                                      SDL_RENDERER_ACCELERATED |
                                          SDL_RENDERER_PRESENTVSYNC);
    if (sdl_renderer == NULL) {
        media_set_error("SDL_CreateRenderer: %s", SDL_GetError());
        stream_media_shutdown();
        return false;
    }

#if NSTREAMLINK_APP
    if (!open_hid_controller()) {
        stream_media_shutdown();
        return false;
    }
#endif

#if !NSTREAMLINK_APP
    for (int i = 0; i < 2; i++) {
        joysticks[i] = SDL_JoystickOpen(i);
        if (joysticks[i] == NULL) {
            media_set_error("SDL_JoystickOpen(%d): %s", i, SDL_GetError());
            stream_media_shutdown();
            return false;
        }
    }
#endif

    sdl_ready = true;
    draw_idle_indicator();

    pthread_mutex_lock(&state_lock);
    snapshot.available = true;
    pthread_mutex_unlock(&state_lock);
    media_logf("media init: SDL2 renderer ready");
    return true;
}

void stream_media_shutdown(void) {
    media_logf("media shutdown: begin");
    stream_media_video_stop(NULL);
    stream_media_audio_stop(NULL);

    pthread_mutex_lock(&state_lock);
    snapshot.available = false;
    snapshot.video_active = false;
#if NSTREAMLINK_APP
    hid_session = NULL;
    hid_session_enabled = false;
    snapshot.hid_provider_devices = 0;
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
    hid_last_full_us = 0;
#endif
    pthread_mutex_unlock(&state_lock);

#if NSTREAMLINK_APP
    close_hid_controller();
#endif

    for (int i = 0; i < 2; i++) {
        if (joysticks[i] != NULL) {
            media_logf("media shutdown: close joystick %d", i);
            SDL_JoystickClose(joysticks[i]);
            joysticks[i] = NULL;
        }
    }
    if (sdl_renderer != NULL) {
        media_logf("media shutdown: destroy renderer");
        SDL_DestroyRenderer(sdl_renderer);
        sdl_renderer = NULL;
    }
    if (sdl_window != NULL) {
        media_logf("media shutdown: destroy window");
        SDL_DestroyWindow(sdl_window);
        sdl_window = NULL;
    }
    if (sdl_initialized) {
        media_logf("media shutdown: SDL_Quit");
        SDL_Quit();
        sdl_initialized = false;
        sdl_ready = false;
        media_logf("media shutdown: SDL_Quit done");
    }

    pthread_mutex_lock(&frame_lock);
    frame_dirty = false;
    av_frame_free(&latched_frame);
    av_frame_free(&present_frame);
    pthread_mutex_unlock(&frame_lock);
    media_logf("media shutdown: done");
}

bool stream_media_available(void) {
    return sdl_ready;
}

bool stream_media_exit_requested(void) {
    return sdl_exit_requested;
}

void stream_media_set_hid_session(IHS_Session *session, bool enabled) {
#if NSTREAMLINK_APP
    pthread_mutex_lock(&state_lock);
    hid_session = session;
    hid_session_enabled = enabled;
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
        hid_last_full_us = 0;
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
        hid_last_full_us = 0;
    }
    pthread_mutex_unlock(&state_lock);
#else
    (void)session;
    (void)enabled;
#endif
}

#if NSTREAMLINK_APP
IHS_HIDProvider *stream_media_create_hid_provider(void) {
    if (!open_hid_controller()) {
        return NULL;
    }
    IHS_HIDProvider *provider =
        IHS_HIDProviderSDLCreateUnmanaged(&HID_DEVICE_LIST, NULL);
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
#endif

static enum AVPixelFormat get_hw_format(AVCodecContext *ctx, const enum AVPixelFormat *fmts) {
    (void)ctx;
    for (const enum AVPixelFormat *p = fmts; *p != AV_PIX_FMT_NONE; p++) {
        if (*p == hw_pix_fmt) {
            return *p;
        }
    }
    media_logf("NVTEGRA pixel format unavailable; falling back to software output");
    for (const enum AVPixelFormat *p = fmts; *p != AV_PIX_FMT_NONE; p++) {
        const AVPixFmtDescriptor *desc = av_pix_fmt_desc_get(*p);
        if (desc != NULL && !(desc->flags & AV_PIX_FMT_FLAG_HWACCEL)) {
            return *p;
        }
    }
    return fmts[0];
}

static bool find_nvtegra_config(const AVCodec *codec) {
    hw_pix_fmt = AV_PIX_FMT_NONE;
    for (int i = 0;; i++) {
        const AVCodecHWConfig *cfg = avcodec_get_hw_config(codec, i);
        if (cfg == NULL) {
            return false;
        }
        if ((cfg->methods & AV_CODEC_HW_CONFIG_METHOD_HW_DEVICE_CTX) &&
            cfg->device_type == AV_HWDEVICE_TYPE_NVTEGRA) {
            hw_pix_fmt = cfg->pix_fmt;
            return true;
        }
    }
}

static int open_decoder(const IHS_StreamVideoConfig *config, bool use_hw) {
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (codec == NULL) {
        media_set_error("avcodec_find_decoder(H264) failed");
        return -1;
    }

    decoder_ctx = avcodec_alloc_context3(codec);
    if (decoder_ctx == NULL) {
        media_set_error("avcodec_alloc_context3 failed");
        return -1;
    }
    decoder_ctx->width = (int)config->width;
    decoder_ctx->height = (int)config->height;
    decoder_ctx->thread_count = 1;
    decoder_ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;

    if (use_hw) {
        int rc = av_hwdevice_ctx_create(&hw_device_ctx, AV_HWDEVICE_TYPE_NVTEGRA, NULL, NULL, 0);
        if (rc != 0) {
            avcodec_free_context(&decoder_ctx);
            media_log_av_error("av_hwdevice_ctx_create(NVTEGRA) failed", rc);
            return -1;
        }
        decoder_ctx->hw_device_ctx = av_buffer_ref(hw_device_ctx);
        decoder_ctx->get_format = get_hw_format;
        decoder_ctx->extra_hw_frames = 3;
    } else {
        decoder_ctx->thread_type = FF_THREAD_FRAME | FF_THREAD_SLICE;
        decoder_ctx->thread_count = 0;
    }

    int rc = avcodec_open2(decoder_ctx, codec, NULL);
    if (rc != 0) {
        avcodec_free_context(&decoder_ctx);
        if (hw_device_ctx != NULL) {
            av_buffer_unref(&hw_device_ctx);
        }
        media_log_av_error(use_hw ? "avcodec_open2 H264 NVTEGRA failed" :
                                    "avcodec_open2 H264 software failed",
                           rc);
        return -1;
    }

    pthread_mutex_lock(&state_lock);
    snprintf(snapshot.decoder, sizeof(snapshot.decoder), "%s %s", codec->name,
             use_hw ? "nvtegra" : "software");
    snapshot.decoder[sizeof(snapshot.decoder) - 1] = '\0';
    snapshot.last_error[0] = '\0';
    pthread_mutex_unlock(&state_lock);

    media_logf("video decoder opened: %s (%s)", codec->name, use_hw ? "nvtegra" : "software");
    return 0;
}

int stream_media_video_start(IHS_Session *session, const IHS_StreamVideoConfig *config) {
    (void)session;
    if (!sdl_ready) {
        media_set_error("media unavailable at video start");
        return -1;
    }
    if (config->codec != IHS_StreamVideoCodecH264) {
        media_set_error("unsupported video codec for M3.3: %d", (int)config->codec);
        return -1;
    }

    stream_media_video_stop(NULL);

    packet = av_packet_alloc();
    decode_frame = av_frame_alloc();
    if (packet == NULL || decode_frame == NULL) {
        media_set_error("FFmpeg packet/frame allocation failed");
        stream_media_video_stop(NULL);
        return -1;
    }

    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    bool can_try_hw = codec != NULL && find_nvtegra_config(codec);
    if (can_try_hw) {
        media_logf("H264 NVTEGRA hw config found: pix_fmt=%d", (int)hw_pix_fmt);
    } else {
        media_logf("H264 NVTEGRA hw config not advertised; trying software decoder");
    }

    if ((!can_try_hw || open_decoder(config, true) != 0) && open_decoder(config, false) != 0) {
        stream_media_video_stop(NULL);
        return -1;
    }

    pthread_mutex_lock(&frame_lock);
    av_frame_unref(latched_frame);
    av_frame_unref(present_frame);
    frame_dirty = false;
    pending_frame_id = 0;
    pending_submit_us = 0;
    pending_latch_us = 0;
    pthread_mutex_unlock(&frame_lock);

    stats_session = session;
    need_flush = false;
    have_last_frame = false;
    last_frame_id = 0;
    logged_alignment_fallback = false;
    logged_vic_transfer = false;
    logged_vic_prepare_fallback = false;
    logged_vic_transfer_retry = false;
    logged_convert_format = AV_PIX_FMT_NONE;
    nv12_texture_failed = false;

    pthread_mutex_lock(&state_lock);
    snapshot.video_active = true;
    snapshot.first_frame_displayed = false;
    snapshot.decoded_frames = 0;
    snapshot.displayed_frames = 0;
    snapshot.dropped_frames = 0;
    snapshot.decode_samples = 0;
    snapshot.transferred_frames = 0;
    snapshot.vic_transfer_frames = 0;
    snapshot.transfer_fallback_frames = 0;
    snapshot.converted_frames = 0;
    snapshot.last_displayed_frame = 0;
    snapshot.decode_us_total = 0;
    snapshot.transfer_us_total = 0;
    snapshot.convert_us_total = 0;
    snapshot.upload_us_total = 0;
    snapshot.present_us_total = 0;
    snapshot.decode_us_max = 0;
    snapshot.transfer_us_max = 0;
    snapshot.convert_us_max = 0;
    snapshot.upload_us_max = 0;
    snapshot.present_us_max = 0;
    snapshot.frame_wait_samples = 0;
    snapshot.frame_wait_us_total = 0;
    snapshot.frame_wait_us_max = 0;
    snapshot.frame_e2e_samples = 0;
    snapshot.frame_e2e_us_total = 0;
    snapshot.frame_e2e_us_max = 0;
    snapshot.hid_send_samples = 0;
    snapshot.hid_send_us_total = 0;
    snapshot.hid_send_us_max = 0;
    snapshot.hid_events = 0;
    snapshot.hid_send_ok = 0;
    snapshot.hid_send_fail = 0;
    snapshot.hid_last_event_type = 0;
    snapshot.hid_last_event_which = -1;
    snapshot.hid_last_event_code = -1;
    snapshot.hid_last_event_value = 0;
    snapshot.width = (int)config->width;
    snapshot.height = (int)config->height;
    snapshot.last_error[0] = '\0';
    pthread_mutex_unlock(&state_lock);
    return 0;
}

static void stash_frame(AVFrame *src, uint16_t frame_id, uint64_t submit_us) {
    bool had_pending;
    uint16_t dropped_id;

    pthread_mutex_lock(&frame_lock);
    had_pending = frame_dirty;
    dropped_id = pending_frame_id;
    av_frame_unref(latched_frame);
    av_frame_move_ref(latched_frame, src);
    pending_frame_id = frame_id;
    pending_submit_us = submit_us;
    pending_latch_us = media_monotonic_us();
    frame_dirty = true;
    pthread_mutex_unlock(&frame_lock);

    pthread_mutex_lock(&state_lock);
    snapshot.decoded_frames++;
    pthread_mutex_unlock(&state_lock);

    if (had_pending) {
        pthread_mutex_lock(&state_lock);
        snapshot.dropped_frames++;
        pthread_mutex_unlock(&state_lock);
        if (stats_session != NULL) {
            IHS_SessionReportVideoFrameComplete(stats_session, dropped_id,
                                                IHS_VideoFrameResultDroppedLate);
        }
    }
}

static void stash_converted_frame(const AVFrame *src, uint16_t frame_id, uint64_t submit_us) {
    AVFrame *out = av_frame_alloc();
    if (out == NULL) {
        return;
    }
    out->format = AV_PIX_FMT_YUV420P;
    out->width = src->width;
    out->height = src->height;
    if (av_frame_get_buffer(out, 32) != 0) {
        av_frame_free(&out);
        return;
    }
    sws = sws_getCachedContext(sws, src->width, src->height, src->format,
                               src->width, src->height, AV_PIX_FMT_YUV420P,
                               SWS_BILINEAR, NULL, NULL, NULL);
    if (sws == NULL) {
        av_frame_free(&out);
        return;
    }
    uint64_t convert_start = media_monotonic_us();
    sws_scale(sws, (const uint8_t *const *)src->data, src->linesize, 0, src->height,
              out->data, out->linesize);
    uint32_t convert_us = elapsed_us(convert_start, media_monotonic_us());
    pthread_mutex_lock(&state_lock);
    snapshot.converted_frames++;
    add_timing(&snapshot.convert_us_total, &snapshot.convert_us_max, convert_us);
    pthread_mutex_unlock(&state_lock);
    stash_frame(out, frame_id, submit_us);
    av_frame_free(&out);
}

#define NVTEGRA_VIC_ALIGNMENT 256
#define NVTEGRA_MAP_ALIGNMENT 4096

static void free_aligned_frame_buffer(void *opaque, uint8_t *data) {
    (void)data;
    av_free(opaque);
}

static bool frame_planes_aligned(const AVFrame *frame) {
    int planes = av_pix_fmt_count_planes((enum AVPixelFormat)frame->format);
    if (planes <= 0) {
        return false;
    }
    for (int i = 0; i < planes; i++) {
        if (frame->data[i] == NULL ||
            ((uintptr_t)frame->data[i] & (NVTEGRA_VIC_ALIGNMENT - 1)) != 0 ||
            (frame->linesize[i] & (NVTEGRA_VIC_ALIGNMENT - 1)) != 0) {
            return false;
        }
    }
    return true;
}

static int prepare_vic_transfer_frame(AVFrame *dst, const AVFrame *src) {
    if (src->hw_frames_ctx == NULL) {
        return AVERROR(EINVAL);
    }

    const AVHWFramesContext *frames_ctx =
        (const AVHWFramesContext *)src->hw_frames_ctx->data;
    dst->format = frames_ctx->sw_format;
    dst->width = src->width;
    dst->height = src->height;

    int image_size = av_image_get_buffer_size((enum AVPixelFormat)dst->format,
                                              dst->width, dst->height,
                                              NVTEGRA_VIC_ALIGNMENT);
    if (image_size < 0) {
        return image_size;
    }

    size_t map_size = ((size_t)image_size + NVTEGRA_MAP_ALIGNMENT - 1) &
                      ~(size_t)(NVTEGRA_MAP_ALIGNMENT - 1);
    if (map_size > SIZE_MAX - (NVTEGRA_MAP_ALIGNMENT - 1)) {
        return AVERROR(ENOMEM);
    }

    uint8_t *allocation = av_malloc(map_size + NVTEGRA_MAP_ALIGNMENT - 1);
    if (allocation == NULL) {
        return AVERROR(ENOMEM);
    }
    uint8_t *aligned = (uint8_t *)(((uintptr_t)allocation + NVTEGRA_MAP_ALIGNMENT - 1) &
                                   ~(uintptr_t)(NVTEGRA_MAP_ALIGNMENT - 1));
    dst->buf[0] = av_buffer_create(aligned, map_size, free_aligned_frame_buffer,
                                   allocation, 0);
    if (dst->buf[0] == NULL) {
        av_free(allocation);
        return AVERROR(ENOMEM);
    }

    int rc = av_image_fill_arrays(dst->data, dst->linesize, aligned,
                                  (enum AVPixelFormat)dst->format,
                                  dst->width, dst->height,
                                  NVTEGRA_VIC_ALIGNMENT);
    if (rc < 0) {
        av_frame_unref(dst);
        return rc;
    }
    dst->extended_data = dst->data;
    return 0;
}

static int transfer_nvtegra_frame(AVFrame *dst, const AVFrame *src, bool *used_vic) {
    *used_vic = false;

    int prepare_rc = prepare_vic_transfer_frame(dst, src);
    bool vic_eligible = prepare_rc == 0 && frame_planes_aligned(dst);
    if (!vic_eligible) {
        if (!logged_vic_prepare_fallback) {
            logged_vic_prepare_fallback = true;
            if (prepare_rc < 0) {
                char errbuf[AV_ERROR_MAX_STRING_SIZE];
                av_strerror(prepare_rc, errbuf, sizeof(errbuf));
                media_logf("NVTEGRA VIC buffer preparation failed: %s (%d); using default transfer",
                           errbuf, prepare_rc);
            } else {
                media_logf("NVTEGRA VIC buffer failed runtime alignment check; using default transfer");
            }
        }
        av_frame_unref(dst);
    }

    int transfer_rc = av_hwframe_transfer_data(dst, src, 0);
    if (transfer_rc < 0 && vic_eligible) {
        if (!logged_vic_transfer_retry) {
            logged_vic_transfer_retry = true;
            char errbuf[AV_ERROR_MAX_STRING_SIZE];
            av_strerror(transfer_rc, errbuf, sizeof(errbuf));
            media_logf("NVTEGRA VIC transfer failed: %s (%d); retrying default transfer",
                       errbuf, transfer_rc);
        }
        av_frame_unref(dst);
        transfer_rc = av_hwframe_transfer_data(dst, src, 0);
        vic_eligible = false;
    }
    if (transfer_rc < 0) {
        return transfer_rc;
    }

    if (vic_eligible) {
        int props_rc = av_frame_copy_props(dst, src);
        if (props_rc < 0) {
            return props_rc;
        }
    }
    *used_vic = vic_eligible;
    if (vic_eligible && !logged_vic_transfer) {
        logged_vic_transfer = true;
        media_logf("NVTEGRA transfer path: VIC 256B-aligned format=%d pitch=%d/%d",
                   dst->format, dst->linesize[0], dst->linesize[1]);
    }
    return 0;
}

static void receive_frames(uint16_t frame_id, uint64_t submit_us) {
    while (avcodec_receive_frame(decoder_ctx, decode_frame) == 0) {
        AVFrame *frame = decode_frame;
        AVFrame *downloaded = NULL;
        if (decode_frame->hw_frames_ctx != NULL || decode_frame->format == AV_PIX_FMT_NVTEGRA) {
            downloaded = av_frame_alloc();
            bool used_vic = false;
            uint64_t transfer_start = media_monotonic_us();
            int transfer_rc = downloaded != NULL ?
                                  transfer_nvtegra_frame(downloaded, decode_frame, &used_vic) :
                                  AVERROR(ENOMEM);
            uint32_t transfer_us = elapsed_us(transfer_start, media_monotonic_us());
            if (downloaded != NULL && transfer_rc == 0) {
                pthread_mutex_lock(&state_lock);
                snapshot.transferred_frames++;
                if (used_vic) {
                    snapshot.vic_transfer_frames++;
                } else {
                    snapshot.transfer_fallback_frames++;
                }
                add_timing(&snapshot.transfer_us_total, &snapshot.transfer_us_max, transfer_us);
                pthread_mutex_unlock(&state_lock);
                frame = downloaded;
            } else {
                media_set_error("av_hwframe_transfer_data failed for frame %u", frame_id);
                av_frame_free(&downloaded);
                av_frame_unref(decode_frame);
                continue;
            }
        }

        if (frame->format == AV_PIX_FMT_YUV420P || frame->format == AV_PIX_FMT_NV12) {
            stash_frame(frame, frame_id, submit_us);
        } else {
            if (logged_convert_format != frame->format) {
                logged_convert_format = frame->format;
                media_logf("converting decoded frame format %d to YUV420P; suppressing repeats",
                           frame->format);
            }
            stash_converted_frame(frame, frame_id, submit_us);
        }

        av_frame_free(&downloaded);
        av_frame_unref(decode_frame);
    }
}

IHS_StreamVideoSubmitResult stream_media_video_submit(IHS_Session *session, uint16_t frame_id,
                                                     IHS_Buffer *data,
                                                     IHS_StreamVideoFrameFlag flags) {
    if (decoder_ctx == NULL || packet == NULL) {
        return IHS_StreamVideoSubmitError;
    }
    uint64_t submit_us = media_monotonic_us();

    stats_session = session;
    if (have_last_frame && frame_id != (uint16_t)(last_frame_id + 1)) {
        need_flush = true;
    }
    have_last_frame = true;
    last_frame_id = frame_id;
    if ((flags & IHS_StreamVideoFrameKeyFrame) && need_flush) {
        avcodec_flush_buffers(decoder_ctx);
        need_flush = false;
    }

    if (av_new_packet(packet, (int)data->size) < 0) {
        need_flush = true;
        if (session != NULL) {
            IHS_SessionReportVideoFrameComplete(session, frame_id,
                                                IHS_VideoFrameResultDroppedNetworkLost);
        }
        return IHS_StreamVideoSubmitReportLost;
    }
    memcpy(packet->data, IHS_BufferPointer(data), data->size);

    if (session != NULL) {
        IHS_SessionReportVideoFrameStage(session, frame_id, IHS_VideoFrameStageDecodeBegin, 0);
    }
    uint64_t decode_start = media_monotonic_us();
    int rc = avcodec_send_packet(decoder_ctx, packet);
    if (rc == AVERROR(EAGAIN)) {
        receive_frames(frame_id, submit_us);
        rc = avcodec_send_packet(decoder_ctx, packet);
    }
    if (rc == 0) {
        receive_frames(frame_id, submit_us);
        uint32_t decode_us = elapsed_us(decode_start, media_monotonic_us());
        pthread_mutex_lock(&state_lock);
        snapshot.decode_samples++;
        add_timing(&snapshot.decode_us_total, &snapshot.decode_us_max, decode_us);
        pthread_mutex_unlock(&state_lock);
        if (session != NULL) {
            IHS_SessionReportVideoFrameStage(session, frame_id, IHS_VideoFrameStageDecodeEnd, 0);
        }
        av_packet_unref(packet);
        return IHS_StreamVideoSubmitOK;
    }

    if (session != NULL) {
        IHS_SessionReportVideoFrameStage(session, frame_id, IHS_VideoFrameStageDecodeEnd, 0);
        IHS_SessionReportVideoFrameComplete(session, frame_id,
                                            IHS_VideoFrameResultDroppedDecodeCorrupt);
    }
    media_log_av_error("avcodec_send_packet failed", rc);
    need_flush = true;
    av_packet_unref(packet);
    return IHS_StreamVideoSubmitReportLost;
}

void stream_media_video_stop(IHS_Session *session) {
    (void)session;
    uint16_t dropped_id = 0;
    bool had_pending = false;

    pthread_mutex_lock(&frame_lock);
    had_pending = frame_dirty;
    dropped_id = pending_frame_id;
    frame_dirty = false;
    if (latched_frame != NULL) {
        av_frame_unref(latched_frame);
    }
    if (present_frame != NULL) {
        av_frame_unref(present_frame);
    }
    pthread_mutex_unlock(&frame_lock);

    if (had_pending && stats_session != NULL) {
        IHS_SessionReportVideoFrameComplete(stats_session, dropped_id,
                                            IHS_VideoFrameResultDroppedReset);
    }
    stats_session = NULL;

    if (video_texture != NULL) {
        SDL_DestroyTexture(video_texture);
        video_texture = NULL;
        texture_width = 0;
        texture_height = 0;
        texture_format = 0;
    }
    if (sws != NULL) {
        sws_freeContext(sws);
        sws = NULL;
    }
    if (decoder_ctx != NULL) {
        avcodec_free_context(&decoder_ctx);
    }
    if (hw_device_ctx != NULL) {
        av_buffer_unref(&hw_device_ctx);
    }
    av_packet_free(&packet);
    av_frame_free(&decode_frame);

    pthread_mutex_lock(&state_lock);
    snapshot.video_active = false;
    pthread_mutex_unlock(&state_lock);
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
    want.samples = 960;
    want.callback = NULL;

    SDL_AudioDeviceID device =
        SDL_OpenAudioDevice(NULL, 0, &want, &have, SDL_AUDIO_ALLOW_SAMPLES_CHANGE);
    if (device == 0) {
        media_set_error("SDL_OpenAudioDevice: %s", SDL_GetError());
        opus_decoder_destroy(decoder);
        return -1;
    }
    if (have.freq != want.freq || have.format != want.format ||
        have.channels != want.channels) {
        media_set_error("SDL audio format mismatch: got %dHz fmt=0x%x ch=%u",
                        have.freq, (unsigned)have.format, (unsigned)have.channels);
        SDL_CloseAudioDevice(device);
        opus_decoder_destroy(decoder);
        return -1;
    }

    pthread_mutex_lock(&audio_lock);
    audio_stop_locked();
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
    media_logf("audio start: codec=Opus freq=%d channels=%d samples=%u codecData=%zu",
               have.freq, have.channels, have.samples, config->codecDataLen);
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
    int samples = opus_decode(audio_decoder, payload, (opus_int32)data->size,
                              audio_decode_buf, AUDIO_MAX_OPUS_FRAME_SAMPLES, 0);
    if (samples < 0) {
        audio_decode_errors_total++;
        ret = -1;
        if (audio_decode_errors_total <= 3 || (audio_decode_errors_total % 60U) == 0U) {
            snprintf(error, sizeof(error), "opus_decode: %s", opus_strerror(samples));
        }
    } else {
        uint32_t pcm_bytes =
            (uint32_t)samples * (uint32_t)audio_channels * (uint32_t)sizeof(opus_int16);
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
    pthread_mutex_unlock(&audio_lock);

    update_audio_snapshot();
    if (had_audio) {
        media_logf("audio stopped");
    }
}

static AVFrame *take_frame(uint16_t *frame_id, uint64_t *submit_us, uint64_t *latch_us) {
    pthread_mutex_lock(&frame_lock);
    if (!frame_dirty || latched_frame == NULL || latched_frame->width <= 0) {
        pthread_mutex_unlock(&frame_lock);
        return NULL;
    }
    av_frame_unref(present_frame);
    av_frame_move_ref(present_frame, latched_frame);
    *frame_id = pending_frame_id;
    *submit_us = pending_submit_us;
    *latch_us = pending_latch_us;
    pending_submit_us = 0;
    pending_latch_us = 0;
    frame_dirty = false;
    pthread_mutex_unlock(&frame_lock);
    return present_frame;
}

static bool ensure_video_texture(int width, int height, Uint32 format) {
    if (video_texture != NULL && texture_width == width && texture_height == height &&
        texture_format == format) {
        return true;
    }
    if (video_texture != NULL) {
        SDL_DestroyTexture(video_texture);
        video_texture = NULL;
        texture_width = 0;
        texture_height = 0;
        texture_format = 0;
    }
    video_texture = SDL_CreateTexture(sdl_renderer, format, SDL_TEXTUREACCESS_STREAMING, width,
                                      height);
    if (video_texture == NULL) {
        media_set_error("SDL_CreateTexture(%s %dx%d): %s",
                        format == SDL_PIXELFORMAT_NV12 ? "NV12" : "IYUV", width, height,
                        SDL_GetError());
        return false;
    }
    texture_width = width;
    texture_height = height;
    texture_format = format;
    media_logf("SDL video texture ready: %s %dx%d",
               format == SDL_PIXELFORMAT_NV12 ? "NV12" : "IYUV", width, height);
    return true;
}

static bool draw_frame_to_sdl(const AVFrame *frame) {
    if (!sdl_ready || sdl_renderer == NULL || frame == NULL ||
        frame->width <= 0 || frame->height <= 0) {
        return false;
    }
    if (frame->format != AV_PIX_FMT_YUV420P && frame->format != AV_PIX_FMT_NV12) {
        media_set_error("unsupported present format: %d", frame->format);
        return false;
    }
    Uint32 wanted_format = frame->format == AV_PIX_FMT_NV12 && !nv12_texture_failed ?
                               SDL_PIXELFORMAT_NV12 :
                               SDL_PIXELFORMAT_IYUV;
    if (!ensure_video_texture(frame->width, frame->height, wanted_format)) {
        if (wanted_format == SDL_PIXELFORMAT_NV12) {
            nv12_texture_failed = true;
            media_logf("SDL NV12 texture unavailable; falling back to IYUV conversion");
            if (!ensure_video_texture(frame->width, frame->height, SDL_PIXELFORMAT_IYUV)) {
                return false;
            }
            pthread_mutex_lock(&state_lock);
            snapshot.last_error[0] = '\0';
            pthread_mutex_unlock(&state_lock);
        } else {
            return false;
        }
    }

    const AVFrame *upload_frame = frame;
    AVFrame *converted = NULL;
    if (frame->format == AV_PIX_FMT_NV12 && texture_format == SDL_PIXELFORMAT_IYUV) {
        converted = av_frame_alloc();
        if (converted == NULL) {
            return false;
        }
        converted->format = AV_PIX_FMT_YUV420P;
        converted->width = frame->width;
        converted->height = frame->height;
        if (av_frame_get_buffer(converted, 32) != 0) {
            av_frame_free(&converted);
            return false;
        }
        sws = sws_getCachedContext(sws, frame->width, frame->height, frame->format,
                                   frame->width, frame->height, AV_PIX_FMT_YUV420P,
                                   SWS_BILINEAR, NULL, NULL, NULL);
        if (sws == NULL) {
            av_frame_free(&converted);
            return false;
        }
        uint64_t convert_start = media_monotonic_us();
        sws_scale(sws, (const uint8_t *const *)frame->data, frame->linesize, 0,
                  frame->height, converted->data, converted->linesize);
        uint32_t convert_us = elapsed_us(convert_start, media_monotonic_us());
        pthread_mutex_lock(&state_lock);
        snapshot.converted_frames++;
        add_timing(&snapshot.convert_us_total, &snapshot.convert_us_max, convert_us);
        pthread_mutex_unlock(&state_lock);
        upload_frame = converted;
    } else if (frame->format == AV_PIX_FMT_YUV420P && texture_format != SDL_PIXELFORMAT_IYUV) {
        return false;
    }

    uint64_t upload_start = media_monotonic_us();
    int update_rc = 0;
    if (texture_format == SDL_PIXELFORMAT_NV12) {
        update_rc = SDL_UpdateNVTexture(video_texture, NULL, upload_frame->data[0],
                                        upload_frame->linesize[0], upload_frame->data[1],
                                        upload_frame->linesize[1]);
    } else {
        update_rc = SDL_UpdateYUVTexture(video_texture, NULL, upload_frame->data[0],
                                         upload_frame->linesize[0], upload_frame->data[1],
                                         upload_frame->linesize[1], upload_frame->data[2],
                                         upload_frame->linesize[2]);
    }
    if (update_rc != 0) {
        if (texture_format == SDL_PIXELFORMAT_NV12) {
            media_logf("SDL_UpdateNVTexture failed: %s; falling back to IYUV conversion",
                       SDL_GetError());
            nv12_texture_failed = true;
            if (video_texture != NULL) {
                SDL_DestroyTexture(video_texture);
                video_texture = NULL;
                texture_width = 0;
                texture_height = 0;
                texture_format = 0;
            }
            av_frame_free(&converted);
            return draw_frame_to_sdl(frame);
        }
        media_set_error("SDL_UpdateYUVTexture: %s", SDL_GetError());
        av_frame_free(&converted);
        return false;
    }
    uint32_t upload_us = elapsed_us(upload_start, media_monotonic_us());
    pthread_mutex_lock(&state_lock);
    add_timing(&snapshot.upload_us_total, &snapshot.upload_us_max, upload_us);
    pthread_mutex_unlock(&state_lock);

    int w = SDL_WIDTH;
    int h = SDL_HEIGHT;
    SDL_GetWindowSize(sdl_window, &w, &h);

    SDL_SetRenderDrawColor(sdl_renderer, 0, 0, 0, 255);
    SDL_RenderClear(sdl_renderer);

    int dst_w = w;
    int dst_h = (frame->height * w) / frame->width;
    if (dst_h > h) {
        dst_h = h;
        dst_w = (frame->width * h) / frame->height;
    }
    if (dst_w <= 0 || dst_h <= 0) {
        av_frame_free(&converted);
        return false;
    }

    SDL_Rect dst = {(w - dst_w) / 2, (h - dst_h) / 2, dst_w, dst_h};
    uint64_t present_start = media_monotonic_us();
    if (SDL_RenderCopy(sdl_renderer, video_texture, NULL, &dst) != 0) {
        media_set_error("SDL_RenderCopy: %s", SDL_GetError());
        av_frame_free(&converted);
        return false;
    }
    draw_ui_overlay();
    SDL_RenderPresent(sdl_renderer);
    uint32_t present_us = elapsed_us(present_start, media_monotonic_us());
    pthread_mutex_lock(&state_lock);
    add_timing(&snapshot.present_us_total, &snapshot.present_us_max, present_us);
    pthread_mutex_unlock(&state_lock);
    av_frame_free(&converted);
    return true;
}

static bool should_draw_idle(void) {
    pthread_mutex_lock(&state_lock);
    bool idle = !snapshot.video_active && !snapshot.first_frame_displayed;
    pthread_mutex_unlock(&state_lock);
    return idle;
}

void stream_media_present(void) {
    if (!sdl_ready) {
        return;
    }

    pump_sdl_events();

#if NSTREAMLINK_APP
    /* Plume semantics: at most one HID packet per frame, carrying the state
     * coalesced across all pumps since the previous frame. */
    if (hid_frame_dirty) {
        pthread_mutex_lock(&state_lock);
        IHS_Session *hid_sess = hid_session;
        bool hid_enabled = hid_session_enabled;
        pthread_mutex_unlock(&state_lock);
        if (hid_enabled && hid_sess != NULL) {
            uint64_t send_start = media_monotonic_us();
            bool hid_sent = IHS_HIDFlushSDLGameControllers(hid_sess);
            uint32_t send_us = (uint32_t)elapsed_us(send_start, media_monotonic_us());
            pthread_mutex_lock(&state_lock);
            snapshot.hid_send_samples++;
            add_timing(&snapshot.hid_send_us_total, &snapshot.hid_send_us_max, send_us);
            pthread_mutex_unlock(&state_lock);
            if (hid_sent) {
                hid_send_ok_since_log++;
                hid_send_ok_total++;
            } else {
                hid_send_fail_since_log++;
                hid_send_fail_total++;
            }
        }
        hid_frame_dirty = false;
    }
#endif

    uint16_t frame_id = 0;
    uint64_t frame_submit_us = 0;
    uint64_t frame_latch_us = 0;
    uint64_t take_us = media_monotonic_us();
    AVFrame *frame = take_frame(&frame_id, &frame_submit_us, &frame_latch_us);
    bool displayed = false;
    if (frame != NULL && stats_session != NULL) {
        IHS_SessionReportVideoFrameStage(stats_session, frame_id,
                                         IHS_VideoFrameStageUploadBegin, 0);
    }

    if (frame == NULL && should_draw_idle()) {
        draw_idle_indicator();
    } else {
        displayed = draw_frame_to_sdl(frame);
    }

    if (frame != NULL && stats_session != NULL) {
        IHS_SessionReportVideoFrameStage(stats_session, frame_id,
                                         IHS_VideoFrameStageUploadEnd, 0);
        IHS_SessionReportVideoFrameComplete(
            stats_session, frame_id,
            displayed ? IHS_VideoFrameResultDisplayed : IHS_VideoFrameResultDroppedLate);
    }

    if (displayed) {
        uint64_t displayed_us = media_monotonic_us();
        uint32_t wait_us =
            frame_latch_us != 0 && take_us > frame_latch_us
                ? (uint32_t)elapsed_us(frame_latch_us, take_us)
                : 0;
        uint32_t e2e_us =
            frame_submit_us != 0 && displayed_us > frame_submit_us
                ? (uint32_t)elapsed_us(frame_submit_us, displayed_us)
                : 0;
        pthread_mutex_lock(&state_lock);
        bool first = !snapshot.first_frame_displayed;
        snapshot.first_frame_displayed = true;
        snapshot.displayed_frames++;
        snapshot.last_displayed_frame = frame_id;
        snapshot.width = frame->width;
        snapshot.height = frame->height;
        snapshot.frame_wait_samples++;
        add_timing(&snapshot.frame_wait_us_total, &snapshot.frame_wait_us_max, wait_us);
        snapshot.frame_e2e_samples++;
        add_timing(&snapshot.frame_e2e_us_total, &snapshot.frame_e2e_us_max, e2e_us);
        pthread_mutex_unlock(&state_lock);
        if (first) {
            media_logf("first frame displayed: id=%u size=%dx%d fmt=%d", frame_id,
                       frame->width, frame->height, frame->format);
        }
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
#if NSTREAMLINK_APP
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
    IHS_SessionGetReliabilityStats(hid_session, &snapshot.reliability);
    strncpy(snapshot.hid_style_state, hid_style_last, sizeof(snapshot.hid_style_state) - 1);
    snapshot.hid_style_state[sizeof(snapshot.hid_style_state) - 1] = '\0';
#endif
    *out = snapshot;
    pthread_mutex_unlock(&state_lock);
}

size_t stream_media_copy_hid_history(stream_media_hid_history_entry *out, size_t max_entries) {
    if (out == NULL || max_entries == 0) {
        return 0;
    }
#if NSTREAMLINK_APP
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
    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';
#if NSTREAMLINK_APP
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
        int written = snprintf(out + used, out_len - used,
                               " | #%u t=%u e=%u ok=%u f=%u h=%u p=%u ax=%u btn=%u sen=%u oth=%u sup=%u raw=%u/%u sty=%u:%s sticks=%d/%d/%d/%d b=0x%x minus=%u/%u/%u/%u tot=%u/%u/%u/%u/%u last=%d/%d/%d/%d",
                               e->seq, e->sec, e->events, e->send_ok,
                               e->send_fail, e->state_full, e->pump, e->ax,
                               e->btn, e->sen, e->oth, e->ev_sup,
                               e->raw_ax, e->raw_btn, e->sty_fl,
                               e->sty[0] ? e->sty : "-", e->left_x, e->left_y,
                               e->right_x, e->right_y, e->buttons,
                               e->marker_minus_sdl_held,
                               e->marker_minus_sdl_samples,
                               e->marker_minus_raw_held,
                               e->marker_minus_raw_samples, e->events_total,
                               e->send_ok_total, e->state_full_total,
                               e->raw_ax_total, e->raw_btn_total,
                               e->last_type, e->last_which, e->last_code,
                               e->last_value);
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
    snprintf(out, out_len, "hidlog disabled");
#endif
}

void stream_media_set_ui(const stream_media_ui *ui) {
    pthread_mutex_lock(&state_lock);
    if (ui != NULL) {
        ui_state = *ui;
    } else {
        memset(&ui_state, 0, sizeof(ui_state));
    }
    pthread_mutex_unlock(&state_lock);
}
