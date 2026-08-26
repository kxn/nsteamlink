#include "media.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <SDL.h>

#include <libavcodec/avcodec.h>
#include <libavutil/error.h>
#include <libavutil/frame.h>
#include <libavutil/hwcontext.h>
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

static AVCodecContext *decoder_ctx;
static AVBufferRef *hw_device_ctx;
static enum AVPixelFormat hw_pix_fmt = AV_PIX_FMT_NONE;
static AVPacket *packet;
static AVFrame *decode_frame;
static AVFrame *latched_frame;
static AVFrame *present_frame;
static struct SwsContext *sws;

static IHS_Session *stats_session;
#if NSTREAMLINK_APP
static IHS_Session *hid_session;
static bool hid_session_enabled;
static SDL_GameController *hid_controller;
static SDL_JoystickID hid_controller_id = -1;
static int hid_controller_index = -1;
static uint32_t hid_events_since_log;
static uint32_t hid_send_ok_since_log;
static uint32_t hid_send_fail_since_log;
static uint32_t hid_events_total;
static uint32_t hid_send_ok_total;
static uint32_t hid_send_fail_total;
static uint64_t hid_last_log_us;
#endif
static probe_media_log_fn log_cb;
static probe_media_snapshot snapshot;
static probe_media_ui ui_state;
static bool frame_dirty;
static uint16_t pending_frame_id;
static bool need_flush;
static bool have_last_frame;
static uint16_t last_frame_id;
static bool logged_alignment_fallback;
static enum AVPixelFormat logged_convert_format = AV_PIX_FMT_NONE;

static void media_logf(const char *fmt, ...);

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
    probe_media_ui ui;
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
        for (int i = 0; i < PROBE_MEDIA_UI_LINES; i++) {
            if (ui.lines[i][0] == '\0') {
                continue;
            }
            SDL_Color color = i >= PROBE_MEDIA_UI_LINES - 2 ? muted : body;
            draw_text(ui.lines[i], 82, y, 3, color);
            y += 44;
        }
    } else {
        int line_count = 0;
        for (int i = 0; i < PROBE_MEDIA_UI_LINES; i++) {
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
        for (int i = 0; i < PROBE_MEDIA_UI_LINES; i++) {
            if (ui.lines[i][0] == '\0') {
                continue;
            }
            SDL_Color color = i >= PROBE_MEDIA_UI_LINES - 2 ? muted : body;
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

#if NSTREAMLINK_APP
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
#endif

static void pump_sdl_events(void) {
    SDL_Event event;
#if NSTREAMLINK_APP
    IHS_Session *event_hid_session = NULL;
    bool hid_enabled = false;
    bool hid_changed = false;

    pthread_mutex_lock(&state_lock);
    event_hid_session = hid_session;
    hid_enabled = hid_session_enabled;
    pthread_mutex_unlock(&state_lock);
#endif

    while (SDL_PollEvent(&event)) {
#if NSTREAMLINK_APP
        record_hid_event(&event);
        if (hid_enabled && event_hid_session != NULL &&
            IHS_HIDHandleSDLEvent(event_hid_session, &event)) {
            hid_changed = true;
            hid_events_since_log++;
            hid_events_total++;
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
    if (hid_changed && event_hid_session != NULL) {
        bool hid_sent = IHS_SessionHIDSendReport(event_hid_session);
        if (hid_sent) {
            hid_send_ok_since_log++;
            hid_send_ok_total++;
        } else {
            hid_send_fail_since_log++;
            hid_send_fail_total++;
        }
    }
    if (hid_enabled && event_hid_session != NULL) {
        uint64_t now_us = media_monotonic_us();
        if (hid_last_log_us == 0) {
            hid_last_log_us = now_us;
        }
        if (elapsed_us(hid_last_log_us, now_us) >= 1000000U) {
            media_logf("hid summary: events=%u send_ok=%u send_fail=%u",
                       hid_events_since_log, hid_send_ok_since_log,
                       hid_send_fail_since_log);
            hid_events_since_log = 0;
            hid_send_ok_since_log = 0;
            hid_send_fail_since_log = 0;
            hid_last_log_us = now_us;
        }
    } else {
        hid_events_since_log = 0;
        hid_send_ok_since_log = 0;
        hid_send_fail_since_log = 0;
        hid_last_log_us = 0;
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

bool probe_media_init(probe_media_log_fn log_fn) {
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
        probe_media_shutdown();
        return false;
    }

    Uint32 init_flags = SDL_INIT_VIDEO;
#if NSTREAMLINK_APP
    init_flags |= SDL_INIT_GAMECONTROLLER;
#else
    init_flags |= SDL_INIT_JOYSTICK;
#endif
    if (SDL_Init(init_flags) < 0) {
        media_set_error("SDL_Init: %s", SDL_GetError());
        probe_media_shutdown();
        return false;
    }
    sdl_initialized = true;

    sdl_window = SDL_CreateWindow("nsteamlink", 0, 0, SDL_WIDTH, SDL_HEIGHT, 0);
    if (sdl_window == NULL) {
        media_set_error("SDL_CreateWindow: %s", SDL_GetError());
        probe_media_shutdown();
        return false;
    }

    sdl_renderer = SDL_CreateRenderer(sdl_window, 0,
                                      SDL_RENDERER_ACCELERATED |
                                          SDL_RENDERER_PRESENTVSYNC);
    if (sdl_renderer == NULL) {
        media_set_error("SDL_CreateRenderer: %s", SDL_GetError());
        probe_media_shutdown();
        return false;
    }

#if NSTREAMLINK_APP
    if (!open_hid_controller()) {
        probe_media_shutdown();
        return false;
    }
#endif

#if !NSTREAMLINK_APP
    for (int i = 0; i < 2; i++) {
        joysticks[i] = SDL_JoystickOpen(i);
        if (joysticks[i] == NULL) {
            media_set_error("SDL_JoystickOpen(%d): %s", i, SDL_GetError());
            probe_media_shutdown();
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

void probe_media_shutdown(void) {
    media_logf("media shutdown: begin");
    probe_media_video_stop(NULL);

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
    hid_events_since_log = 0;
    hid_send_ok_since_log = 0;
    hid_send_fail_since_log = 0;
    hid_last_log_us = 0;
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

bool probe_media_available(void) {
    return sdl_ready;
}

bool probe_media_exit_requested(void) {
    return sdl_exit_requested;
}

void probe_media_set_hid_session(IHS_Session *session, bool enabled) {
#if NSTREAMLINK_APP
    pthread_mutex_lock(&state_lock);
    hid_session = session;
    hid_session_enabled = enabled;
    if (session != NULL && enabled) {
        hid_events_total = 0;
        hid_send_ok_total = 0;
        hid_send_fail_total = 0;
        hid_events_since_log = 0;
        hid_send_ok_since_log = 0;
        hid_send_fail_since_log = 0;
        hid_last_log_us = 0;
        snapshot.hid_events = 0;
        snapshot.hid_send_ok = 0;
        snapshot.hid_send_fail = 0;
        snapshot.hid_last_event_type = 0;
        snapshot.hid_last_event_which = -1;
        snapshot.hid_last_event_code = -1;
        snapshot.hid_last_event_value = 0;
    }
    pthread_mutex_unlock(&state_lock);
#else
    (void)session;
    (void)enabled;
#endif
}

#if NSTREAMLINK_APP
IHS_HIDProvider *probe_media_create_hid_provider(void) {
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

void probe_media_destroy_hid_provider(IHS_HIDProvider *provider) {
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

int probe_media_video_start(IHS_Session *session, const IHS_StreamVideoConfig *config) {
    (void)session;
    if (!sdl_ready) {
        media_set_error("media unavailable at video start");
        return -1;
    }
    if (config->codec != IHS_StreamVideoCodecH264) {
        media_set_error("unsupported video codec for M3.3: %d", (int)config->codec);
        return -1;
    }

    probe_media_video_stop(NULL);

    packet = av_packet_alloc();
    decode_frame = av_frame_alloc();
    if (packet == NULL || decode_frame == NULL) {
        media_set_error("FFmpeg packet/frame allocation failed");
        probe_media_video_stop(NULL);
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
        probe_media_video_stop(NULL);
        return -1;
    }

    pthread_mutex_lock(&frame_lock);
    av_frame_unref(latched_frame);
    av_frame_unref(present_frame);
    frame_dirty = false;
    pending_frame_id = 0;
    pthread_mutex_unlock(&frame_lock);

    stats_session = session;
    need_flush = false;
    have_last_frame = false;
    last_frame_id = 0;
    logged_alignment_fallback = false;
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

static void stash_frame(AVFrame *src, uint16_t frame_id) {
    bool had_pending;
    uint16_t dropped_id;

    pthread_mutex_lock(&frame_lock);
    had_pending = frame_dirty;
    dropped_id = pending_frame_id;
    av_frame_unref(latched_frame);
    av_frame_move_ref(latched_frame, src);
    pending_frame_id = frame_id;
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

static void stash_converted_frame(const AVFrame *src, uint16_t frame_id) {
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
    stash_frame(out, frame_id);
    av_frame_free(&out);
}

static void receive_frames(uint16_t frame_id) {
    while (avcodec_receive_frame(decoder_ctx, decode_frame) == 0) {
        AVFrame *frame = decode_frame;
        AVFrame *downloaded = NULL;
        if (decode_frame->hw_frames_ctx != NULL || decode_frame->format == AV_PIX_FMT_NVTEGRA) {
            downloaded = av_frame_alloc();
            uint64_t transfer_start = media_monotonic_us();
            int transfer_rc = downloaded != NULL ?
                                  av_hwframe_transfer_data(downloaded, decode_frame, 0) :
                                  AVERROR(ENOMEM);
            uint32_t transfer_us = elapsed_us(transfer_start, media_monotonic_us());
            if (downloaded != NULL && transfer_rc == 0) {
                pthread_mutex_lock(&state_lock);
                snapshot.transferred_frames++;
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
            stash_frame(frame, frame_id);
        } else {
            if (logged_convert_format != frame->format) {
                logged_convert_format = frame->format;
                media_logf("converting decoded frame format %d to YUV420P; suppressing repeats",
                           frame->format);
            }
            stash_converted_frame(frame, frame_id);
        }

        av_frame_free(&downloaded);
        av_frame_unref(decode_frame);
    }
}

IHS_StreamVideoSubmitResult probe_media_video_submit(IHS_Session *session, uint16_t frame_id,
                                                     IHS_Buffer *data,
                                                     IHS_StreamVideoFrameFlag flags) {
    if (decoder_ctx == NULL || packet == NULL) {
        return IHS_StreamVideoSubmitError;
    }

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
        receive_frames(frame_id);
        rc = avcodec_send_packet(decoder_ctx, packet);
    }
    if (rc == 0) {
        receive_frames(frame_id);
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

void probe_media_video_stop(IHS_Session *session) {
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

static AVFrame *take_frame(uint16_t *frame_id) {
    pthread_mutex_lock(&frame_lock);
    if (!frame_dirty || latched_frame == NULL || latched_frame->width <= 0) {
        pthread_mutex_unlock(&frame_lock);
        return NULL;
    }
    av_frame_unref(present_frame);
    av_frame_move_ref(present_frame, latched_frame);
    *frame_id = pending_frame_id;
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

void probe_media_present(void) {
    if (!sdl_ready) {
        return;
    }

    pump_sdl_events();

    uint16_t frame_id = 0;
    AVFrame *frame = take_frame(&frame_id);
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
        pthread_mutex_lock(&state_lock);
        bool first = !snapshot.first_frame_displayed;
        snapshot.first_frame_displayed = true;
        snapshot.displayed_frames++;
        snapshot.last_displayed_frame = frame_id;
        snapshot.width = frame->width;
        snapshot.height = frame->height;
        pthread_mutex_unlock(&state_lock);
        if (first) {
            media_logf("first frame displayed: id=%u size=%dx%d fmt=%d", frame_id,
                       frame->width, frame->height, frame->format);
        }
    }
}

void probe_media_get_snapshot(probe_media_snapshot *out) {
    if (out == NULL) {
        return;
    }
    pthread_mutex_lock(&state_lock);
#if NSTREAMLINK_APP
    snapshot.hid_events = hid_events_total;
    snapshot.hid_send_ok = hid_send_ok_total;
    snapshot.hid_send_fail = hid_send_fail_total;
#endif
    *out = snapshot;
    pthread_mutex_unlock(&state_lock);
}

void probe_media_set_ui(const probe_media_ui *ui) {
    pthread_mutex_lock(&state_lock);
    if (ui != NULL) {
        ui_state = *ui;
    } else {
        memset(&ui_state, 0, sizeof(ui_state));
    }
    pthread_mutex_unlock(&state_lock);
}
