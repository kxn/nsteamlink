// M3 tool: request a Steam stream and verify the session/video path.
// M3.3 adds FFmpeg/NVTEGRA + SDL2 rendering; the app target also forwards gamepad input.
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <switch.h>

#include <ihslib/buffer.h>
#include <ihslib/audio.h>
#include <ihslib/client.h>
#include <ihslib/common.h>
#include <ihslib/net.h>
#include <ihslib/session.h>
#include <ihslib/video.h>

#include "client_pri.h"
#include "discovery.pb-c.h"
#include "media.h"
#include "pb_utils.h"

#define AUTH_DIR             "sdmc:/switch/nsteamlink"
#define AUTH_PATH            AUTH_DIR "/auth.bin"
#define BOOT_STAGE_PATH      AUTH_DIR "/stream_boot_stage.txt"
#define EXCEPTION_PATH       AUTH_DIR "/stream_exception_dump.txt"
#define EXIT_STAGE_PATH      AUTH_DIR "/stream_exit_stage.txt"
#define WATCHDOG_PATH        AUTH_DIR "/stream_watchdog.txt"
#define DIAG_PATH            AUTH_DIR "/stream_diag.log"
#define DIAG_PREV_PATH       AUTH_DIR "/stream_diag_prev.log"
#define DIAG_OLDER_PATH      AUTH_DIR "/stream_diag_older.log"
#define DIAG_MARKER_PATH     AUTH_DIR "/stream_diag_markers.log"
#define DIAG_MARKER_PREV_PATH AUTH_DIR "/stream_diag_markers_prev.log"
#define DIAG_MARKER_OLDER_PATH AUTH_DIR "/stream_diag_markers_older.log"
#define DIAG_EVENT_PATH      AUTH_DIR "/stream_diag_events.log"
#define DIAG_EVENT_PREV_PATH AUTH_DIR "/stream_diag_events_prev.log"
#define DIAG_TAIL_BYTES      3500U
#define DIAG_CHUNK_BYTES     3000U
#define AUTH_MAGIC           "NSLAUTH"
#define AUTH_VERSION         1U
#define FALLBACK_HOST        "10.10.10.166"
#define DEBUG_PORT           28772
#define DEBUG_RX             256
#define DEBUG_TX             4096
#define LOGQ_LEN             256
#define LOGQ_MSG             224
#define LOGQ_DRAIN_LIMIT     8
#define MAX_HOSTS            8
#define PROBE_WIDTH          1280U
#define PROBE_HEIGHT         720U
#define PROBE_FPS            60U
#define PROBE_BITRATE_KBPS   6000U
#define PROBE_SHORT_STOP_FRAMES 120U
#define PROBE_LONG_STOP_FRAMES 3600U
#define PROBE_AUTO_STOP_FRAMES PROBE_LONG_STOP_FRAMES
#ifndef NSTREAMLINK_APP
#define NSTREAMLINK_APP 0
#endif
#define PROBE_AUTO_STREAM_ON_BOOT (!NSTREAMLINK_APP)
#define WATCHDOG_MAIN_STALL_MS 8000U
#define WATCHDOG_STREAM_NO_FRAME_MS 45000U
#define WATCHDOG_POLL_MS 250U
#define VIDEO_STALL_NOTICE_MS 2500U
#define VIDEO_STALL_AUTO_STOP_MS 10000U
#define LOCAL_HOTKEY_MASK     (HidNpadButton_StickL | HidNpadButton_StickR)
#define LOCAL_VOLUME_POLL_MS  80U


/* internal ihslib API (session/channels/ch_control.h) */
void IHS_SessionChannelControlGetRecentHIDReports(uint64_t *out_ms, uint16_t *out_len,
                                                  uint8_t *out_data, size_t *out_off);
size_t IHS_SessionChannelControlDrainPendingHIDReports(char *out, size_t cap);

#if NSTREAMLINK_APP
#include <ihslib/hid/sdl.h>
#endif

typedef struct __attribute__((packed)) sl_auth_file {
    char magic[8];
    uint32_t version;
    uint32_t size;
    uint64_t device_id;
    uint8_t secret_key[32];
    char device_name[64];
    uint64_t steam_id;
    char last_hostname[64];
    uint8_t last_host_ipv4[4];
    uint16_t last_host_port;
    uint8_t reserved[30];
} sl_auth_file;

typedef enum stream_mode {
    PROBE_DISCOVERING,
    PROBE_READY,
    PROBE_STREAM_REQUESTING,
    PROBE_STREAM_READY,
    PROBE_SESSION_CONNECTING,
    PROBE_SESSION_ACTIVE,
    PROBE_SESSION_STOPPING,
    PROBE_ERROR,
} stream_mode;

typedef struct app_state {
    pthread_mutex_t lock;
    sl_auth_file auth;
    bool auth_loaded;

    IHS_HostInfo hosts[MAX_HOSTS];
    int host_count;
    int selected_host;
    int discovery_frame;
    uint32_t fallback_seq;

    stream_mode mode;
    IHS_StreamingResult stream_result;
    bool stream_desktop;
    bool stream_hold;
    char stream_pin[16];
    IHS_SessionInfo session_info;

    IHS_Session *session;
#if NSTREAMLINK_APP
    IHS_HIDProvider *hid_provider;
#endif
    bool session_connected;
    bool session_finished;
    bool stop_requested;
    bool exit_requested;
    char exit_reason[96];
    bool local_hotkeys_ready;
    bool local_volume_ready;
    int local_volume_target;
    int local_volume_value;
    bool auto_stop_requested;
    bool exit_after_auto_stop;

    bool video_started;
    bool video_stalled;
    uint64_t video_stall_report_ms;
    uint32_t video_width;
    uint32_t video_height;
    IHS_StreamVideoCodec video_codec;
    size_t video_codec_data_len;
    uint32_t frame_count;
    uint32_t keyframe_count;
    uint16_t last_frame_id;
    size_t last_frame_size;
    uint64_t encoded_bytes;
    uint64_t stream_start_ms;
    uint64_t first_frame_ms;
    uint64_t last_frame_ms;
    uint32_t frame_gap_count;
    uint32_t max_frame_gap;
    bool have_expected_frame_id;
    uint16_t expected_frame_id;
    uint32_t auto_stop_after_frames;
    bool media_available;
    bool first_frame_displayed;
    uint32_t decoded_frames;
    uint32_t displayed_frames;
    uint32_t media_dropped_frames;
    bool ihs_initialized;
    bool ihs_client_ready;
    bool stream_worker_active;
    uint16_t last_displayed_frame;
    char media_decoder[64];
    char media_error[128];

    bool ui_desktop;
    bool ui_pin_mode;
    int ui_pin_cursor;
    char ui_pin[5];
    char ui_notice[160];

    char status[160];
} app_state;

typedef struct debug_server {
    int fd;
    struct in_addr allowed_host;
} debug_server;

static int cons_fd = -1;
static int nxlink_fd = -1;
static bool nxlink_active = false;
/* Live UDP log stream: every logline datagram is fire-and-forget to the
 * operator's listener (MSG_DONTWAIT — drops, never blocks, never deadlocks).
 * Destination is learned from the nxlink host or the first debugctl peer. */
static int log_udp_fd = -1;
static struct sockaddr_in log_udp_dst;
static volatile bool log_udp_ready;
static char socket_summary[LOGQ_MSG];
static atomic_uint_fast64_t watchdog_last_main_ms;
static atomic_uint_fast64_t watchdog_stream_start_ms;
static atomic_uint_fast32_t watchdog_displayed_frames;
static atomic_bool watchdog_stop;
static atomic_uint_fast32_t diag_hid_open_ok;
static atomic_uint_fast32_t diag_hid_open_fail;
static atomic_uint_fast32_t diag_hid_start_reports;
static atomic_uint_fast32_t diag_hid_start_report_len;
static atomic_uint_fast32_t diag_hid_full_reports;
static atomic_uint_fast32_t diag_hid_get_feature;
static atomic_uint_fast32_t diag_hid_get_strings;
static atomic_uint_fast32_t diag_hid_no_device;
static atomic_uint_fast32_t diag_control_warn;
static atomic_uint_fast32_t diag_control_unhandled;
static atomic_bool diag_disk_stop;
static pthread_t diag_disk_thread;
static bool diag_disk_started;
static atomic_bool diag_disk_thread_alive;
static atomic_uint_fast32_t diag_disk_start_error;
static atomic_uint_fast32_t diag_disk_thread_error;
static atomic_uint_fast32_t diag_disk_marker_error;
static atomic_uint_fast32_t diag_disk_event_error;
static atomic_uint_fast32_t diag_disk_ticks;
static pthread_mutex_t diag_recent_lock = PTHREAD_MUTEX_INITIALIZER;
static char diag_recent[DIAG_TAIL_BYTES + 1U];
static size_t diag_recent_len;
static pthread_mutex_t diag_marker_recent_lock = PTHREAD_MUTEX_INITIALIZER;
static char diag_marker_recent[DIAG_TAIL_BYTES + 1U];
static size_t diag_marker_recent_len;
static pthread_mutex_t diag_event_recent_lock = PTHREAD_MUTEX_INITIALIZER;
static char diag_event_recent[DIAG_TAIL_BYTES + 1U];
static size_t diag_event_recent_len;

__attribute__((aligned(16))) u8 __nx_exception_stack[0x1000];
u64 __nx_exception_stack_size = sizeof(__nx_exception_stack);

void __libnx_exception_handler(ThreadExceptionDump *ctx) {
    mkdir(AUTH_DIR, 0777);
    FILE *fp = fopen(EXCEPTION_PATH, "w");
    if (fp == NULL) {
        return;
    }
    fprintf(fp, "nsteamlink switch-stream-selftest exception dump\n");
    fprintf(fp, "error_desc: 0x%x\n", ctx->error_desc);
    for (int i = 0; i < 29; i++) {
        fprintf(fp, "x%d: 0x%016" PRIx64 "\n", i, (uint64_t)ctx->cpu_gprs[i].x);
    }
    fprintf(fp, "fp: 0x%016" PRIx64 "\n", (uint64_t)ctx->fp.x);
    fprintf(fp, "lr: 0x%016" PRIx64 "\n", (uint64_t)ctx->lr.x);
    fprintf(fp, "sp: 0x%016" PRIx64 "\n", (uint64_t)ctx->sp.x);
    fprintf(fp, "pc: 0x%016" PRIx64 "\n", (uint64_t)ctx->pc.x);
    fprintf(fp, "pstate: 0x%x\n", ctx->pstate);
    fprintf(fp, "afsr0: 0x%x\n", ctx->afsr0);
    fprintf(fp, "afsr1: 0x%x\n", ctx->afsr1);
    fprintf(fp, "esr: 0x%x\n", ctx->esr);
    fprintf(fp, "far: 0x%016" PRIx64 "\n", (uint64_t)ctx->far.x);
    fclose(fp);
}

static char logq[LOGQ_LEN][LOGQ_MSG];
static uint64_t logq_ms[LOGQ_LEN];
static int logq_head = 0;
static int logq_tail = 0;
static pthread_mutex_t logq_lock = PTHREAD_MUTEX_INITIALIZER;

static void log_udp_open(const struct in_addr *dst);
static void log_udp_send(const char *buf);

static void logline(const char *fmt, ...) {
    char buf[LOGQ_MSG];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (cons_fd >= 0) {
        dprintf(cons_fd, "%s\n", buf);
    }
    if (nxlink_active && nxlink_fd >= 0) {
        if (dprintf(nxlink_fd, "%s\n", buf) < 0) {
            nxlink_active = false;
        }
    }
    log_udp_send(buf);
}

static void set_nonblocking_log_fd(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

static uint64_t monotonic_ms(void);

static void logline_net(const char *fmt, ...) {
    pthread_mutex_lock(&logq_lock);
    char *slot = logq[logq_head];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(slot, LOGQ_MSG, fmt, ap);
    va_end(ap);
    logq_ms[logq_head] = monotonic_ms();
    logq_head = (logq_head + 1) % LOGQ_LEN;
    if (logq_head == logq_tail) {
        logq_tail = (logq_tail + 1) % LOGQ_LEN;
    }
    pthread_mutex_unlock(&logq_lock);
}

static void log_udp_open(const struct in_addr *dst) {
    if (log_udp_fd >= 0) {
        return;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return;
    }
    int sndbuf = 65536;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    memset(&log_udp_dst, 0, sizeof(log_udp_dst));
    log_udp_dst.sin_family = AF_INET;
    log_udp_dst.sin_addr = *dst;
    log_udp_dst.sin_port = htons(28773);
    log_udp_fd = fd;
    log_udp_ready = true;
    logline_net("udp log stream active: %s:28773", inet_ntoa(log_udp_dst.sin_addr));
}

static void log_udp_send(const char *buf) {
    if (!log_udp_ready || log_udp_fd < 0) {
        return;
    }
    /* fire-and-forget: MSG_DONTWAIT, connectionless — drops instead of
     * blocking, and touches no SDL/session locks. */
    sendto(log_udp_fd, buf, strlen(buf), MSG_DONTWAIT,
           (struct sockaddr *) &log_udp_dst, sizeof(log_udp_dst));
}

static void media_log(const char *message) {
    logline_net("%s", message);
}

static void nxlink_log_close(void) {
    if (nxlink_fd < 0) {
        nxlink_active = false;
        return;
    }
    int fd = nxlink_fd;
    nxlink_fd = -1;
    nxlink_active = false;
    close(fd);
}

static bool ensure_auth_dir(void) {
    return mkdir(AUTH_DIR, 0777) == 0 || errno == EEXIST;
}

static void write_exit_stage(const char *stage) {
    int saved_errno = errno;
    if (ensure_auth_dir()) {
        FILE *fp = fopen(EXIT_STAGE_PATH, "w");
        if (fp != NULL) {
            fprintf(fp, "%s\n", stage);
            fclose(fp);
        }
    }
    errno = saved_errno;
}

static void write_boot_stage(const char *stage) {
    int saved_errno = errno;
    if (ensure_auth_dir()) {
        FILE *fp = fopen(BOOT_STAGE_PATH, "w");
        if (fp != NULL) {
            fprintf(fp, "%s\n", stage);
            fclose(fp);
        }
    }
    errno = saved_errno;
}

static void sanitize_text_for_log(char *text) {
    if (text == NULL) {
        return;
    }
    for (char *p = text; *p != '\0'; p++) {
        unsigned char ch = (unsigned char)*p;
        if (ch == '\r' || ch == '\n' || ch == '\t') {
            *p = ' ';
        } else if (!isprint(ch)) {
            *p = '?';
        }
    }
}

static bool read_text_tail(const char *path, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return false;
    }
    out[0] = '\0';
    size_t capacity = out_len - 1;
    if (capacity == 0) {
        return false;
    }
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return false;
    }
    size_t n = 0;
    if (fseek(fp, 0, SEEK_END) == 0) {
        long end = ftell(fp);
        if (end >= 0) {
            long keep = (long)capacity;
            if (keep > (long)DIAG_TAIL_BYTES) {
                keep = (long)DIAG_TAIL_BYTES;
            }
            long start = end > keep ? end - keep : 0;
            if (fseek(fp, start, SEEK_SET) == 0) {
                n = fread(out, 1, capacity, fp);
            }
        }
    }
    if (n == 0 && ferror(fp)) {
        clearerr(fp);
    }
    if (n == 0) {
        rewind(fp);
        char chunk[256];
        while (true) {
            size_t got = fread(chunk, 1, sizeof(chunk), fp);
            if (got == 0) {
                break;
            }
            if (capacity <= sizeof(chunk) && got >= capacity) {
                memcpy(out, chunk + got - capacity, capacity);
                n = capacity;
            } else if (n + got <= capacity) {
                memcpy(out + n, chunk, got);
                n += got;
            } else {
                size_t drop = n + got - capacity;
                memmove(out, out + drop, n - drop);
                n -= drop;
                memcpy(out + n, chunk, got);
                n += got;
            }
        }
    }
    fclose(fp);
    out[n] = '\0';
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)out[i];
        if (ch == '\r') {
            out[i] = '\n';
        } else if (ch != '\n' && ch != '\t' && !isprint(ch)) {
            out[i] = '?';
        }
    }
    return n > 0;
}

static bool read_text_chunk(const char *path, uint32_t offset, uint32_t requested_len,
                            char *out, size_t out_len, uint32_t *file_size_out,
                            uint32_t *next_offset_out, bool *eof_out) {
    if (out == NULL || out_len == 0) {
        return false;
    }
    out[0] = '\0';
    if (file_size_out != NULL) {
        *file_size_out = 0;
    }
    if (next_offset_out != NULL) {
        *next_offset_out = offset;
    }
    if (eof_out != NULL) {
        *eof_out = true;
    }

    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return false;
    }
    uint32_t file_size = 0;
    if (fseek(fp, 0, SEEK_END) == 0) {
        long end = ftell(fp);
        if (end > 0) {
            file_size = end > UINT32_MAX ? UINT32_MAX : (uint32_t)end;
        }
    }
    if (file_size_out != NULL) {
        *file_size_out = file_size;
    }
    if (offset > file_size || fseek(fp, (long)offset, SEEK_SET) != 0) {
        fclose(fp);
        return false;
    }

    size_t capacity = out_len - 1;
    if (requested_len == 0 || requested_len > DIAG_CHUNK_BYTES) {
        requested_len = DIAG_CHUNK_BYTES;
    }
    if (requested_len > capacity) {
        requested_len = (uint32_t)capacity;
    }
    size_t n = fread(out, 1, requested_len, fp);
    fclose(fp);

    out[n] = '\0';
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)out[i];
        if (ch == '\r') {
            out[i] = '\n';
        } else if (ch != '\n' && ch != '\t' && !isprint(ch)) {
            out[i] = '?';
        }
    }

    uint32_t next = offset + (uint32_t)n;
    if (next_offset_out != NULL) {
        *next_offset_out = next;
    }
    if (eof_out != NULL) {
        *eof_out = next >= file_size;
    }
    return n > 0 || offset == file_size;
}

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void watchdog_beat(void) {
    atomic_store_explicit(&watchdog_last_main_ms, monotonic_ms(), memory_order_relaxed);
}

static void write_watchdog_report(const char *reason, uint64_t now_ms, uint64_t last_main_ms,
                                  uint64_t stream_start_ms, uint32_t displayed) {
    int saved_errno = errno;
    if (ensure_auth_dir()) {
        FILE *fp = fopen(WATCHDOG_PATH, "w");
        if (fp != NULL) {
            fprintf(fp, "reason=%s\n", reason);
            fprintf(fp, "now_ms=%" PRIu64 "\n", now_ms);
            fprintf(fp, "last_main_ms=%" PRIu64 "\n", last_main_ms);
            fprintf(fp, "main_stall_ms=%" PRIu64 "\n",
                    last_main_ms > 0 && now_ms >= last_main_ms ? now_ms - last_main_ms : 0);
            fprintf(fp, "stream_start_ms=%" PRIu64 "\n", stream_start_ms);
            fprintf(fp, "stream_age_ms=%" PRIu64 "\n",
                    stream_start_ms > 0 && now_ms >= stream_start_ms ? now_ms - stream_start_ms : 0);
            fprintf(fp, "displayed_frames=%u\n", displayed);
            fclose(fp);
        }
    }
    errno = saved_errno;
}

static void watchdog_request_exit(const char *reason) {
    write_exit_stage(reason);
    if (nxlink_active && nxlink_fd >= 0) {
        dprintf(nxlink_fd, "watchdog request exit: %s\n", reason);
    }
    appletRequestExitToSelf();
}

static void *watchdog_thread_main(void *arg) {
    (void)arg;
    while (!atomic_load_explicit(&watchdog_stop, memory_order_relaxed)) {
        svcSleepThread(WATCHDOG_POLL_MS * 1000ULL * 1000ULL);
        uint64_t now = monotonic_ms();
        uint64_t last_main = atomic_load_explicit(&watchdog_last_main_ms, memory_order_relaxed);
        uint64_t stream_start = atomic_load_explicit(&watchdog_stream_start_ms,
                                                     memory_order_relaxed);
        uint32_t displayed = atomic_load_explicit(&watchdog_displayed_frames,
                                                  memory_order_relaxed);
        if (last_main > 0 && now >= last_main &&
            now - last_main > WATCHDOG_MAIN_STALL_MS) {
            write_watchdog_report("main_stall", now, last_main, stream_start, displayed);
            watchdog_request_exit("watchdog:main_stall");
            atomic_store_explicit(&watchdog_stop, true, memory_order_relaxed);
        }
        if (stream_start > 0 && displayed == 0 && now >= stream_start &&
            now - stream_start > WATCHDOG_STREAM_NO_FRAME_MS) {
            write_watchdog_report("stream_no_first_frame", now, last_main, stream_start,
                                  displayed);
            watchdog_request_exit("watchdog:stream_no_first_frame");
            atomic_store_explicit(&watchdog_stop, true, memory_order_relaxed);
        }
    }
    return NULL;
}

static void set_status(app_state *state, const char *fmt, ...) {
    pthread_mutex_lock(&state->lock);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(state->status, sizeof(state->status), fmt, ap);
    va_end(ap);
    pthread_mutex_unlock(&state->lock);
}

static void request_app_exit(app_state *state, const char *source) {
    const char *reason = source != NULL && source[0] != '\0' ? source : "unknown";
    bool first = false;

    pthread_mutex_lock(&state->lock);
    first = !state->exit_requested;
    state->stop_requested = true;
    state->exit_requested = true;
    if (state->exit_reason[0] == '\0') {
        snprintf(state->exit_reason, sizeof(state->exit_reason), "%s", reason);
    }
    snprintf(state->ui_notice, sizeof(state->ui_notice), "Exiting");
    pthread_mutex_unlock(&state->lock);

    if (first) {
        char stage[128];
        snprintf(stage, sizeof(stage), "exit:source:%s", reason);
        write_exit_stage(stage);
        logline_net("exit requested: source=%s", reason);
    }
}

static void request_stream_stop(app_state *state, const char *source) {
    const char *reason = source != NULL && source[0] != '\0' ? source : "unknown";
    pthread_mutex_lock(&state->lock);
    state->stop_requested = true;
    snprintf(state->ui_notice, sizeof(state->ui_notice), "Stopping stream");
    pthread_mutex_unlock(&state->lock);
    logline_net("stop requested: source=%s", reason);
}

static void diag_reset_input(void) {
    atomic_store_explicit(&diag_hid_open_ok, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_hid_open_fail, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_hid_start_reports, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_hid_start_report_len, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_hid_full_reports, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_hid_get_feature, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_hid_get_strings, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_hid_no_device, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_control_warn, 0, memory_order_relaxed);
}

static bool parse_u32_after(const char *message, const char *needle, uint32_t *out) {
    const char *p = strstr(message, needle);
    if (p == NULL) {
        return false;
    }
    p += strlen(needle);
    if (!isdigit((unsigned char)*p)) {
        return false;
    }
    char *end = NULL;
    unsigned long value = strtoul(p, &end, 10);
    if (end == p || value > UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static void diag_note_hid_log(const char *message) {
    if (message == NULL) {
        return;
    }
    if (strstr(message, "=> (no device)") != NULL) {
        atomic_fetch_add_explicit(&diag_hid_no_device, 1, memory_order_relaxed);
    }
    if (strstr(message, "Open(") != NULL) {
        if (strstr(message, "=> id=") != NULL) {
            atomic_fetch_add_explicit(&diag_hid_open_ok, 1, memory_order_relaxed);
        } else if (strstr(message, "=> (nil)") != NULL) {
            atomic_fetch_add_explicit(&diag_hid_open_fail, 1, memory_order_relaxed);
        }
    }
    if (strstr(message, "StartInputReports(") != NULL) {
        uint32_t length = 0;
        atomic_fetch_add_explicit(&diag_hid_start_reports, 1, memory_order_relaxed);
        if (parse_u32_after(message, "length=", &length)) {
            atomic_store_explicit(&diag_hid_start_report_len, length, memory_order_relaxed);
        }
    }
    if (strstr(message, "RequestFullReport(") != NULL) {
        atomic_fetch_add_explicit(&diag_hid_full_reports, 1, memory_order_relaxed);
    }
    if (strstr(message, "GetFeatureReport(") != NULL) {
        atomic_fetch_add_explicit(&diag_hid_get_feature, 1, memory_order_relaxed);
    }
    if (strstr(message, "GetVendorString(") != NULL ||
        strstr(message, "GetProductString(") != NULL ||
        strstr(message, "GetSerialNumberString(") != NULL) {
        atomic_fetch_add_explicit(&diag_hid_get_strings, 1, memory_order_relaxed);
    }
}

#define DIAG_UNHANDLED_TYPES 12
static char diag_unhandled_names[DIAG_UNHANDLED_TYPES][40];
static uint32_t diag_unhandled_counts[DIAG_UNHANDLED_TYPES];
static uint32_t diag_unhandled_type_n;
static pthread_mutex_t diag_unhandled_lock = PTHREAD_MUTEX_INITIALIZER;

/* Renders "Name xN, ..." for up to 8 tracked types; returns chars written. */
static int format_unhandled_types(char *out, size_t cap) {
    pthread_mutex_lock(&diag_unhandled_lock);
    int written = 0;
    for (uint32_t i = 0; i < diag_unhandled_type_n && cap > 1; i++) {
        int w = snprintf(out, cap, "%s%s x%u",
                         i > 0 ? ", " : "", diag_unhandled_names[i],
                         diag_unhandled_counts[i]);
        if (w < 0 || (size_t) w >= cap) {
            break;
        }
        out += w;
        cap -= w;
        written += w;
    }
    pthread_mutex_unlock(&diag_unhandled_lock);
    return written;
}

static void diag_note_control_log(const char *message) {
    if (message == NULL) {
        return;
    }
    if (strstr(message, "Malformed") != NULL ||
        strstr(message, "Failed to decrypt") != NULL ||
        strstr(message, "Mismatched message sequence") != NULL ||
        strstr(message, "Unrecognized packet") != NULL) {
        atomic_fetch_add_explicit(&diag_control_warn, 1, memory_order_relaxed);
    }
    if (strstr(message, "Unhandled control message") != NULL) {
        atomic_fetch_add_explicit(&diag_control_unhandled, 1, memory_order_relaxed);
        /* Record WHICH message type went unhandled, with its name, so the
         * 1 Hz diag line can persist it (the logq ring is volatile). */
        const char *name = strstr(message, ": ");
        if (name != NULL) {
            name += 2;
            pthread_mutex_lock(&diag_unhandled_lock);
            uint32_t slot = diag_unhandled_type_n;
            for (uint32_t i = 0; i < diag_unhandled_type_n; i++) {
                if (strncmp(diag_unhandled_names[i], name,
                            sizeof(diag_unhandled_names[0]) - 1) == 0) {
                    slot = i;
                    break;
                }
            }
            if (slot == diag_unhandled_type_n && diag_unhandled_type_n < DIAG_UNHANDLED_TYPES) {
                snprintf(diag_unhandled_names[slot], sizeof(diag_unhandled_names[0]),
                         "%s", name);
                diag_unhandled_type_n++;
            }
            if (slot < DIAG_UNHANDLED_TYPES) {
                diag_unhandled_counts[slot]++;
            }
            pthread_mutex_unlock(&diag_unhandled_lock);
        }
    }
}

static void ihs_log(IHS_LogLevel level, const char *tag, const char *message) {
    if (tag != NULL && strcmp(tag, "HID") == 0) {
        diag_note_hid_log(message);
    } else if (tag != NULL && strcmp(tag, "Control") == 0) {
        diag_note_control_log(message);
    }
    if (level >= IHS_LogLevelDebug) {
        return;
    }
    logline_net("[IHS:%d][%s] %s", (int)level, tag, message);
}

static const char *mode_name(stream_mode mode) {
    switch (mode) {
    case PROBE_DISCOVERING:
        return "discovering";
    case PROBE_READY:
        return "ready";
    case PROBE_STREAM_REQUESTING:
        return "stream-requesting";
    case PROBE_STREAM_READY:
        return "stream-ready";
    case PROBE_SESSION_CONNECTING:
        return "session-connecting";
    case PROBE_SESSION_ACTIVE:
        return "session-active";
    case PROBE_SESSION_STOPPING:
        return "session-stopping";
    case PROBE_ERROR:
        return "error";
    default:
        return "unknown";
    }
}

static const char *codec_name(IHS_StreamVideoCodec codec) {
    switch (codec) {
    case IHS_StreamVideoCodecH264:
        return "H264";
    case IHS_StreamVideoCodecHEVC:
        return "HEVC";
    case IHS_StreamVideoCodecAV1:
        return "AV1";
    case IHS_StreamVideoCodecNone:
        return "none";
    default:
        return "other";
    }
}

static const char *audio_codec_name(IHS_StreamAudioCodec codec) {
    switch (codec) {
    case IHS_StreamAudioCodecRaw:
        return "Raw";
    case IHS_StreamAudioCodecVorbis:
        return "Vorbis";
    case IHS_StreamAudioCodecOpus:
        return "Opus";
    case IHS_StreamAudioCodecMP3:
        return "MP3";
    case IHS_StreamAudioCodecAAC:
        return "AAC";
    case IHS_StreamAudioCodecNone:
        return "none";
    default:
        return "other";
    }
}

static const char *stream_result_name(IHS_StreamingResult result) {
    switch (result) {
    case IHS_StreamingSuccess:
        return "Success";
    case IHS_StreamingUnauthorized:
        return "Unauthorized";
    case IHS_StreamingScreenLocked:
        return "ScreenLocked";
    case IHS_StreamingFailed:
        return "Failed";
    case IHS_StreamingBusy:
        return "Busy";
    case IHS_StreamingInProgress:
        return "InProgress";
    case IHS_StreamingCanceled:
        return "Canceled";
    case IHS_StreamingDriversNotInstalled:
        return "DriversNotInstalled";
    case IHS_StreamingDisabled:
        return "Disabled";
    case IHS_StreamingBroadcastingActive:
        return "BroadcastingActive";
    case IHS_StreamingVRActive:
        return "VRActive";
    case IHS_StreamingPINRequired:
        return "PINRequired";
    case IHS_StreamingTransportUnavailable:
        return "TransportUnavailable";
    case IHS_StreamingInvisible:
        return "Invisible";
    case IHS_StreamingGameLaunchFailed:
        return "GameLaunchFailed";
    case IHS_StreamingTimeout:
        return "Timeout";
    default:
        return "Other";
    }
}

static bool auth_valid(const sl_auth_file *auth) {
    return memcmp(auth->magic, AUTH_MAGIC, sizeof(auth->magic)) == 0 &&
           auth->version == AUTH_VERSION && auth->size == sizeof(*auth);
}

static bool auth_load(sl_auth_file *auth) {
    FILE *fp = fopen(AUTH_PATH, "rb");
    if (fp == NULL) {
        return false;
    }
    bool ok = fread(auth, 1, sizeof(*auth), fp) == sizeof(*auth);
    fclose(fp);
    return ok && auth_valid(auth);
}

static bool fallback_address(IHS_SocketAddress *address) {
    memset(address, 0, sizeof(*address));
    address->port = 27036;
    return IHS_IPAddressFromString(&address->ip, FALLBACK_HOST);
}

static int host_find(app_state *state, const IHS_HostInfo *host) {
    for (int i = 0; i < state->host_count; i++) {
        const IHS_HostInfo *cur = &state->hosts[i];
        if (cur->clientId == host->clientId && cur->instanceId == host->instanceId &&
            IHS_IPAddressCompare(&cur->address.ip, &host->address.ip) == 0) {
            return i;
        }
    }
    return -1;
}

static void on_discovered(IHS_Client *client, const IHS_HostInfo *host, void *context) {
    (void)client;
    app_state *state = context;
    char *ip = IHS_IPAddressToString(&host->address.ip);

    pthread_mutex_lock(&state->lock);
    int index = host_find(state, host);
    if (index < 0 && state->host_count < MAX_HOSTS) {
        index = state->host_count++;
    }
    if (index >= 0) {
        state->hosts[index] = *host;
        if (state->selected_host < 0) {
            state->selected_host = index;
        }
        if (state->mode == PROBE_DISCOVERING) {
            state->mode = PROBE_READY;
            snprintf(state->status, sizeof(state->status), "Host found; send debug command: stream");
        }
    }
    pthread_mutex_unlock(&state->lock);

    logline_net("host found: %s (%s) gamesRunning=%d clientId=0x%016" PRIx64,
                host->hostname, ip ? ip : "?", (int)host->gamesRunning, host->clientId);
    free(ip);
}

static void on_stream_progress(IHS_Client *client, const IHS_HostInfo *host, void *context) {
    (void)client;
    (void)host;
    app_state *state = context;
    pthread_mutex_lock(&state->lock);
    bool exiting = state->exit_requested;
    if (exiting) {
        snprintf(state->status, sizeof(state->status), "Streaming progress ignored during exit");
    }
    pthread_mutex_unlock(&state->lock);
    if (exiting) {
        logline_net("streaming progress ignored: exit requested");
        return;
    }
    set_status(state, "Streaming request in progress");
    logline_net("streaming request progress");
}

static void on_stream_success(IHS_Client *client, const IHS_HostInfo *host,
                              const IHS_SocketAddress *address, const uint8_t *session_key,
                              size_t session_key_len, void *context) {
    (void)client;
    app_state *state = context;
    char *ip = IHS_IPAddressToString(&address->ip);

    pthread_mutex_lock(&state->lock);
    bool exiting = state->exit_requested;
    if (exiting) {
        state->stream_result = IHS_StreamingCanceled;
        if (state->session == NULL) {
            state->mode = PROBE_READY;
        }
        snprintf(state->status, sizeof(state->status), "Streaming success ignored during exit");
    }
    pthread_mutex_unlock(&state->lock);
    if (exiting) {
        logline_net("streaming success ignored during exit: host=%s", host->hostname);
        free(ip);
        return;
    }

    if (session_key_len > sizeof(state->session_info.sessionKey)) {
        pthread_mutex_lock(&state->lock);
        state->stream_result = IHS_StreamingFailed;
        state->mode = PROBE_READY;
        snprintf(state->status, sizeof(state->status),
                 "Streaming failed: session key too long (%zu)", session_key_len);
        pthread_mutex_unlock(&state->lock);
        logline_net("streaming success rejected: keyLen=%zu max=%zu", session_key_len,
                    sizeof(state->session_info.sessionKey));
        free(ip);
        return;
    }

    pthread_mutex_lock(&state->lock);
    memset(&state->session_info, 0, sizeof(state->session_info));
    state->session_info.address = *address;
    memcpy(state->session_info.sessionKey, session_key, session_key_len);
    state->session_info.sessionKeyLen = session_key_len;
    state->session_info.steamId = state->auth.steam_id;
    state->stream_result = IHS_StreamingSuccess;
    state->mode = PROBE_STREAM_READY;
    state->ui_pin_mode = false;
    snprintf(state->status, sizeof(state->status), "Streaming accepted; starting session");
    pthread_mutex_unlock(&state->lock);

    logline_net("streaming success: host=%s stream=%s:%u keyLen=%zu steamId=%" PRIu64,
                host->hostname, ip ? ip : "?", address->port, session_key_len,
                state->auth.steam_id);
    free(ip);
}

static void on_stream_failed(IHS_Client *client, const IHS_HostInfo *host,
                             IHS_StreamingResult result, void *context) {
    (void)client;
    (void)host;
    app_state *state = context;

    pthread_mutex_lock(&state->lock);
    bool exiting = state->exit_requested;
    if (exiting) {
        state->stream_result = result;
        if (state->session == NULL) {
            state->mode = PROBE_READY;
        }
        snprintf(state->status, sizeof(state->status), "Streaming failed during exit");
        pthread_mutex_unlock(&state->lock);
        logline_net("streaming failed ignored during exit: result=%d (%s)", (int)result,
                    stream_result_name(result));
        return;
    }
    state->stream_result = result;
    state->mode = PROBE_READY;
    if (result == IHS_StreamingPINRequired) {
        state->ui_pin_mode = true;
        state->ui_pin_cursor = 0;
        strncpy(state->ui_pin, "0000", sizeof(state->ui_pin));
        snprintf(state->ui_notice, sizeof(state->ui_notice), "Host PIN required");
        snprintf(state->status, sizeof(state->status),
                 "Streaming PIN required");
    } else {
        snprintf(state->ui_notice, sizeof(state->ui_notice), "Streaming failed: %s",
                 stream_result_name(result));
        snprintf(state->status, sizeof(state->status), "Streaming failed result=%d (%s)",
                 (int)result, stream_result_name(result));
    }
    pthread_mutex_unlock(&state->lock);
    atomic_store_explicit(&watchdog_stream_start_ms, 0, memory_order_relaxed);
    logline_net("streaming failed: result=%d (%s)", (int)result, stream_result_name(result));
}

static void on_session_initialized(IHS_Session *session, void *context) {
    (void)session;
    app_state *state = context;
    set_status(state, "Session initialized");
    logline_net("session initialized");
}

static void on_session_connecting(IHS_Session *session, void *context) {
    (void)session;
    app_state *state = context;
    set_status(state, "Session connecting");
    logline_net("session connecting");
}

static void on_session_configuring(IHS_Session *session, IHS_SessionConfig *config, void *context) {
    (void)session;
    (void)context;
    config->enableAudio = NSTREAMLINK_APP ? true : false;
    config->enableHevc = false;
    config->maxWidth = PROBE_WIDTH;
    config->maxHeight = PROBE_HEIGHT;
    config->maxFps = PROBE_FPS;
    config->maxBitrateKbps = PROBE_BITRATE_KBPS;
    logline_net("session configuring: audio=%d hevc=0 max=%ux%u@%u bitrate=%u",
                config->enableAudio ? 1 : 0, PROBE_WIDTH, PROBE_HEIGHT, PROBE_FPS,
                PROBE_BITRATE_KBPS);
}

static void on_session_connected(IHS_Session *session, void *context) {
    app_state *state = context;
    pthread_mutex_lock(&state->lock);
    state->session_connected = true;
    state->mode = PROBE_SESSION_ACTIVE;
    snprintf(state->status, sizeof(state->status), "Session connected; waiting for video frames");
    pthread_mutex_unlock(&state->lock);
    logline_net("session connected");
#if NSTREAMLINK_APP
    stream_media_set_hid_session(session, true);
    bool hid_notified = IHS_SessionHIDNotifyDeviceChange(session);
    logline_net("hid device change notified: %d", (int)hid_notified);
#else
    (void)session;
#endif
}

static void on_session_disconnected(IHS_Session *session, void *context) {
    (void)session;
    app_state *state = context;
    pthread_mutex_lock(&state->lock);
    state->session_connected = false;
    state->session_finished = true;
    snprintf(state->status, sizeof(state->status), "Session disconnected");
    pthread_mutex_unlock(&state->lock);
    atomic_store_explicit(&watchdog_stream_start_ms, 0, memory_order_relaxed);
    logline_net("session disconnected");
}

static void on_session_finalized(IHS_Session *session, void *context) {
    (void)session;
    app_state *state = context;
    pthread_mutex_lock(&state->lock);
    state->session_finished = true;
    pthread_mutex_unlock(&state->lock);
    logline_net("session finalized");
}

static int on_video_start(IHS_Session *session, const IHS_StreamVideoConfig *config, void *context) {
    app_state *state = context;
    pthread_mutex_lock(&state->lock);
    state->video_started = true;
    state->video_stalled = false;
    state->video_stall_report_ms = 0;
    state->video_width = config->width;
    state->video_height = config->height;
    state->video_codec = config->codec;
    state->video_codec_data_len = config->codecDataLen;
    snprintf(state->status, sizeof(state->status), "Video start: %ux%u %s",
             config->width, config->height, codec_name(config->codec));
    pthread_mutex_unlock(&state->lock);
    logline_net("video start: %ux%u codec=%s(%d) codecData=%zu", config->width,
                config->height, codec_name(config->codec), (int)config->codec,
                config->codecDataLen);
    if (stream_media_video_start(session, config) != 0) {
        stream_media_snapshot media;
        stream_media_get_snapshot(&media);
        pthread_mutex_lock(&state->lock);
        snprintf(state->status, sizeof(state->status), "Video decoder start failed: %s",
                 media.last_error[0] ? media.last_error : "unknown");
        pthread_mutex_unlock(&state->lock);
        logline_net("video decoder start failed: %s",
                    media.last_error[0] ? media.last_error : "unknown");
        return -1;
    }
    return 0;
}

static IHS_StreamVideoSubmitResult on_video_submit(IHS_Session *session, uint16_t frame_id,
                                                   IHS_Buffer *data,
                                                   IHS_StreamVideoFrameFlag flags, void *context) {
    app_state *state = context;
    uint32_t frames = 0;
    uint32_t keyframes = 0;
    uint32_t auto_stop_after = 0;
    bool should_log = false;
    bool requested_stop = false;
    uint64_t now_ms = monotonic_ms();

    pthread_mutex_lock(&state->lock);
    state->frame_count++;
    if (flags & IHS_StreamVideoFrameKeyFrame) {
        state->keyframe_count++;
    }
    state->last_frame_id = frame_id;
    state->last_frame_size = data->size;
    state->encoded_bytes += data->size;
    if (state->first_frame_ms == 0) {
        state->first_frame_ms = now_ms;
    }
    state->last_frame_ms = now_ms;
    if (state->have_expected_frame_id && frame_id != state->expected_frame_id) {
        uint32_t gap = (uint16_t)(frame_id - state->expected_frame_id);
        state->frame_gap_count++;
        if (gap > state->max_frame_gap) {
            state->max_frame_gap = gap;
        }
    }
    state->expected_frame_id = (uint16_t)(frame_id + 1U);
    state->have_expected_frame_id = true;
    frames = state->frame_count;
    keyframes = state->keyframe_count;
    auto_stop_after = state->auto_stop_after_frames;
    should_log = frames <= 5 || (frames % 60U) == 0U;
    if (auto_stop_after > 0 && frames >= auto_stop_after && !state->stop_requested &&
        !state->auto_stop_requested) {
        state->stop_requested = true;
        state->auto_stop_requested = true;
        requested_stop = true;
    }
    snprintf(state->status, sizeof(state->status), "Video frames=%u keyframes=%u last=%zu",
             frames, keyframes, data->size);
    if (state->video_stalled) {
        state->video_stalled = false;
        state->video_stall_report_ms = 0;
        if (strncmp(state->ui_notice, "Video stalled", 13) == 0) {
            state->ui_notice[0] = '\0';
        }
    }
    pthread_mutex_unlock(&state->lock);

    IHS_StreamVideoSubmitResult result = stream_media_video_submit(session, frame_id, data, flags);

    if (should_log) {
        logline_net("video frame: count=%u id=%u bytes=%zu key=%d", frames, frame_id,
                    data->size, (flags & IHS_StreamVideoFrameKeyFrame) != 0);
    }
    if (requested_stop) {
        logline_net("auto stop requested after %u frames", frames);
    }
    if (result != IHS_StreamVideoSubmitOK) {
        logline_net("video decoder submit result=%d frame=%u", (int)result, frame_id);
    }
    return result;
}

static void on_video_stop(IHS_Session *session, void *context) {
    app_state *state = context;
    stream_media_video_stop(session);
    pthread_mutex_lock(&state->lock);
    state->video_started = false;
    state->video_stalled = false;
    state->video_stall_report_ms = 0;
    snprintf(state->status, sizeof(state->status), "Video stopped");
    pthread_mutex_unlock(&state->lock);
    atomic_store_explicit(&watchdog_stream_start_ms, 0, memory_order_relaxed);
    logline_net("video stopped");
}

static int on_video_set_capture_size(IHS_Session *session, int width, int height, void *context) {
    (void)session;
    app_state *state = context;
    pthread_mutex_lock(&state->lock);
    state->video_width = (uint32_t)width;
    state->video_height = (uint32_t)height;
    pthread_mutex_unlock(&state->lock);
    logline_net("video capture size: %dx%d", width, height);
    return 0;
}

static void on_video_target_framerate(IHS_Session *session, uint32_t numerator,
                                      uint32_t denominator, uint32_t reasons, void *context) {
    (void)session;
    (void)context;
    logline_net("video target framerate: %u/%u reasons=0x%x", numerator, denominator, reasons);
}

static void on_video_target_bitrate(IHS_Session *session, int32_t bitrate, void *context) {
    (void)session;
    (void)context;
    logline_net("video target bitrate: %d", bitrate);
}

static void on_video_quality_override(IHS_Session *session, int32_t value, void *context) {
    (void)session;
    (void)context;
    logline_net("video quality override: %d", value);
}

static void on_video_bitrate_override(IHS_Session *session, int32_t value, void *context) {
    (void)session;
    (void)context;
    logline_net("video bitrate override: %d", value);
}

static int on_audio_start(IHS_Session *session, const IHS_StreamAudioConfig *config, void *context) {
    app_state *state = context;
    logline_net("audio start: codec=%s(%d) freq=%u channels=%u codecData=%zu",
                audio_codec_name(config ? config->codec : IHS_StreamAudioCodecNone),
                config ? (int)config->codec : 0,
                config ? config->frequency : 0,
                config ? config->channels : 0,
                config ? config->codecDataLen : 0);
    int rc = stream_media_audio_start(session, config);
    if (rc == 0) {
        pthread_mutex_lock(&state->lock);
        snprintf(state->status, sizeof(state->status), "Audio started: %uHz %uch",
                 config->frequency, config->channels);
        pthread_mutex_unlock(&state->lock);
    } else {
        stream_media_snapshot media;
        stream_media_get_snapshot(&media);
        pthread_mutex_lock(&state->lock);
        snprintf(state->status, sizeof(state->status), "Audio start failed: %s",
                 media.last_error[0] ? media.last_error : "unknown");
        pthread_mutex_unlock(&state->lock);
        logline_net("audio start failed: %s",
                    media.last_error[0] ? media.last_error : "unknown");
    }
    return rc;
}

static int on_audio_submit(IHS_Session *session, IHS_Buffer *data, void *context) {
    (void)context;
    return stream_media_audio_submit(session, data);
}

static void on_audio_stop(IHS_Session *session, void *context) {
    app_state *state = context;
    stream_media_audio_stop(session);
    pthread_mutex_lock(&state->lock);
    snprintf(state->status, sizeof(state->status), "Audio stopped");
    pthread_mutex_unlock(&state->lock);
    logline_net("audio stopped");
}

static const IHS_ClientDiscoveryCallbacks DISCOVERY_CALLBACKS = {
    .discovered = on_discovered,
};

static const IHS_ClientStreamingCallbacks STREAMING_CALLBACKS = {
    .progress = on_stream_progress,
    .success = on_stream_success,
    .failed = on_stream_failed,
};

static const IHS_StreamSessionCallbacks SESSION_CALLBACKS = {
    .initialized = on_session_initialized,
    .connecting = on_session_connecting,
    .configuring = on_session_configuring,
    .connected = on_session_connected,
    .disconnected = on_session_disconnected,
    .finalized = on_session_finalized,
};

static const IHS_StreamVideoCallbacks VIDEO_CALLBACKS = {
    .start = on_video_start,
    .submit = on_video_submit,
    .stop = on_video_stop,
    .setCaptureSize = on_video_set_capture_size,
    .setTargetFramerate = on_video_target_framerate,
    .setTargetBitrate = on_video_target_bitrate,
    .setQualityOverride = on_video_quality_override,
    .setBitrateOverride = on_video_bitrate_override,
};

static const IHS_StreamAudioCallbacks AUDIO_CALLBACKS = {
    .start = on_audio_start,
    .submit = on_audio_submit,
    .stop = on_audio_stop,
};

static bool init_socket_for_stream(void) {
    const SocketInitConfig *base = socketGetDefaultInitConfig();
    SocketInitConfig cfg = *base;
    cfg.udp_rx_buf_size = 1024U * 1024U;
    Result rc = socketInitialize(&cfg);
    bool custom = true;
    if (R_FAILED(rc)) {
        snprintf(socket_summary, sizeof(socket_summary),
                 "socketInitialize custom udp_rx=%u failed rc=0x%x; fallback default",
                 cfg.udp_rx_buf_size, (unsigned)rc);
        logline("%s", socket_summary);
        rc = socketInitializeDefault();
        custom = false;
        if (R_FAILED(rc)) {
            snprintf(socket_summary, sizeof(socket_summary),
                     "socketInitialize default failed rc=0x%x", (unsigned)rc);
            logline("%s", socket_summary);
            return false;
        }
    }

    int actual_rcvbuf = -1;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd >= 0) {
        socklen_t len = sizeof(actual_rcvbuf);
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual_rcvbuf, &len) != 0) {
            actual_rcvbuf = -1;
        }
        close(fd);
    }
    snprintf(socket_summary, sizeof(socket_summary),
             "socketInitialize %s tcpTx=%u tcpRx=%u udpTx=%u udpRx=%u sb=%u sessions=%u sampleRcvbuf=%d",
             custom ? "custom" : "default",
             custom ? cfg.tcp_tx_buf_size : base->tcp_tx_buf_size,
             custom ? cfg.tcp_rx_buf_size : base->tcp_rx_buf_size,
             custom ? cfg.udp_tx_buf_size : base->udp_tx_buf_size,
             custom ? cfg.udp_rx_buf_size : base->udp_rx_buf_size,
             custom ? cfg.sb_efficiency : base->sb_efficiency,
             custom ? cfg.num_bsd_sessions : base->num_bsd_sessions, actual_rcvbuf);
    logline("%s", socket_summary);
    return true;
}

static bool send_discovery_once(app_state *state, IHS_Client *client, char *err, size_t err_len) {
    if (client == NULL) {
        snprintf(err, err_len, "IHS client unavailable");
        return false;
    }

    uint32_t seq = 0;
    pthread_mutex_lock(&state->lock);
    if (state->mode == PROBE_ERROR) {
        snprintf(err, err_len, "app is in error mode");
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    state->mode = PROBE_DISCOVERING;
    state->discovery_frame++;
    seq = ++state->fallback_seq;
    snprintf(state->status, sizeof(state->status), "Discovery command sent");
    pthread_mutex_unlock(&state->lock);

    bool started = IHS_ClientStartDiscovery(client, 0);
    logline("discover-once: StartDiscovery -> %d seq=%u", (int)started, seq);

    IHS_SocketAddress address;
    if (!fallback_address(&address)) {
        snprintf(err, err_len, "fallback host address parse failed");
        return false;
    }
    CMsgRemoteClientBroadcastDiscovery msg = CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
    PROTOBUF_C_SET_VALUE(msg, seq_num, seq);
    bool sent = IHS_ClientSend(client, address, k_ERemoteClientBroadcastMsgDiscovery,
                               (ProtobufCMessage *)&msg);
    logline("discover-once: fallback -> %s:27036 ret=%d", FALLBACK_HOST, (int)sent);
    if (!started && !sent) {
        snprintf(err, err_len, "broadcast and fallback discovery failed");
        return false;
    }
    return true;
}

static bool start_stream_request(app_state *state, IHS_Client *client, bool desktop,
                                 bool hold, uint32_t auto_stop_frames, const char *pin, char *err,
                                 size_t err_len) {
    IHS_HostInfo host;
    uint64_t steam_id = 0;
    uint64_t start_ms = monotonic_ms();

    pthread_mutex_lock(&state->lock);
    if (state->mode == PROBE_ERROR) {
        snprintf(err, err_len, "app is in error mode");
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    if (state->auth.steam_id == 0) {
        snprintf(err, err_len, "auth.bin has no steamId; run M2 pairing first");
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    if (state->session != NULL || state->mode == PROBE_STREAM_REQUESTING ||
        state->mode == PROBE_STREAM_READY || state->mode == PROBE_SESSION_CONNECTING ||
        state->mode == PROBE_SESSION_ACTIVE || state->mode == PROBE_SESSION_STOPPING) {
        snprintf(err, err_len, "stream/session already active");
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    if (state->exit_requested) {
        snprintf(err, err_len, "exit requested");
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    if (state->selected_host < 0 || state->selected_host >= state->host_count) {
        snprintf(err, err_len, "no selected host");
        pthread_mutex_unlock(&state->lock);
        return false;
    }

    host = state->hosts[state->selected_host];
    steam_id = state->auth.steam_id;
    state->mode = PROBE_STREAM_REQUESTING;
    state->stream_result = IHS_StreamingInProgress;
    state->stream_desktop = desktop;
    state->stream_hold = hold;
    state->stream_pin[0] = '\0';
    if (pin != NULL && *pin != '\0') {
        strncpy(state->stream_pin, pin, sizeof(state->stream_pin) - 1);
        state->stream_pin[sizeof(state->stream_pin) - 1] = '\0';
    }
    memset(&state->session_info, 0, sizeof(state->session_info));
    state->session_connected = false;
    state->session_finished = false;
    state->stop_requested = false;
    state->auto_stop_requested = false;
    state->exit_after_auto_stop = !hold;
    state->video_started = false;
    state->video_stalled = false;
    state->video_stall_report_ms = 0;
    state->video_width = 0;
    state->video_height = 0;
    state->video_codec = IHS_StreamVideoCodecNone;
    state->video_codec_data_len = 0;
    state->frame_count = 0;
    state->keyframe_count = 0;
    state->last_frame_id = 0;
    state->last_frame_size = 0;
    state->encoded_bytes = 0;
    state->stream_start_ms = start_ms;
    state->first_frame_ms = 0;
    state->last_frame_ms = 0;
    state->frame_gap_count = 0;
    state->max_frame_gap = 0;
    state->have_expected_frame_id = false;
    state->expected_frame_id = 0;
    state->auto_stop_after_frames = hold ? 0 : auto_stop_frames;
    snprintf(state->status, sizeof(state->status), "Requesting %s stream from %s",
             desktop ? "desktop" : "game", host.hostname);
    pthread_mutex_unlock(&state->lock);

    atomic_store_explicit(&watchdog_displayed_frames, 0, memory_order_relaxed);
    atomic_store_explicit(&watchdog_stream_start_ms, start_ms, memory_order_relaxed);
    diag_reset_input();

    bool discovery_stopped = IHS_ClientStopDiscovery(client);
    logline("stream: StopDiscovery(before request) -> %d", (int)discovery_stopped);

    IHS_StreamingRequest request;
    memset(&request, 0, sizeof(request));
    if (pin != NULL && *pin != '\0') {
        strncpy(request.pin, pin, sizeof(request.pin) - 1);
    }
    request.streamingEnable.video = true;
    request.streamingEnable.audio = NSTREAMLINK_APP ? true : false;
    request.streamingEnable.input = NSTREAMLINK_APP ? true : false;
    request.maxResolution.x = (int32_t)PROBE_WIDTH;
    request.maxResolution.y = (int32_t)PROBE_HEIGHT;
    request.audioChannelCount = NSTREAMLINK_APP ? 2 : 0;
    request.streamingInterface = desktop ? IHS_StreamInterfaceDesktop : IHS_StreamInterfaceBigPicture;
    request.streamDesktop = desktop;
    request.gamepadCount = NSTREAMLINK_APP ? 1 : 0;

    if (!IHS_ClientStreamingRequest(client, &host, &request)) {
        pthread_mutex_lock(&state->lock);
        state->mode = PROBE_READY;
        state->stream_result = IHS_StreamingFailed;
        snprintf(state->status, sizeof(state->status), "IHS_ClientStreamingRequest failed");
        pthread_mutex_unlock(&state->lock);
        atomic_store_explicit(&watchdog_stream_start_ms, 0, memory_order_relaxed);
        snprintf(err, err_len, "IHS_ClientStreamingRequest failed");
        return false;
    }

    char *ip = IHS_IPAddressToString(&host.address.ip);
    logline("stream request: host=%s ip=%s desktop=%d pin=%s steamId=%" PRIu64
            " autoStop=%u",
            host.hostname, ip ? ip : "?", (int)desktop,
            (pin != NULL && *pin != '\0') ? "present" : "empty", steam_id,
            hold ? 0U : auto_stop_frames);
    free(ip);
    return true;
}

typedef struct stream_worker {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t thread;
    app_state *state;
    IHS_Client *client;
    bool started;
    bool stop;
    bool request_pending;
    bool busy;
    bool desktop;
    bool hold;
    uint32_t auto_stop_frames;
    char pin[16];
} stream_worker;

typedef struct stream_runtime {
    IHS_ClientConfig client_config;
    IHS_Client *client;
    stream_worker streamer;
    bool ihs_initialized;
    bool stream_worker_started;
} stream_runtime;

typedef enum local_volume_change {
    LOCAL_VOLUME_NONE = 0,
    LOCAL_VOLUME_UP = 1,
    LOCAL_VOLUME_DOWN = -1,
} local_volume_change;

typedef struct local_controls {
    bool audctl_ready;
    bool have_volume;
    AudioTarget target;
    s32 volume;
    uint64_t next_volume_poll_ms;
} local_controls;

static bool ensure_media_started(app_state *state, char *err, size_t err_len);

static void *stream_worker_main(void *arg) {
    stream_worker *worker = arg;
    for (;;) {
        bool desktop;
        bool hold;
        uint32_t auto_stop_frames;
        char pin[16];

        pthread_mutex_lock(&worker->lock);
        while (!worker->stop && !worker->request_pending) {
            pthread_cond_wait(&worker->cond, &worker->lock);
        }
        if (worker->stop) {
            pthread_mutex_unlock(&worker->lock);
            break;
        }
        desktop = worker->desktop;
        hold = worker->hold;
        auto_stop_frames = worker->auto_stop_frames;
        strncpy(pin, worker->pin, sizeof(pin));
        pin[sizeof(pin) - 1] = '\0';
        worker->request_pending = false;
        worker->busy = true;
        pthread_mutex_unlock(&worker->lock);

        char err[96] = "";
        logline_net("stream worker: begin desktop=%d hold=%d autoStop=%u pin=%s",
                    (int)desktop, (int)hold, hold ? 0U : auto_stop_frames,
                    pin[0] ? "present" : "empty");
        if (!start_stream_request(worker->state, worker->client, desktop, hold,
                                  auto_stop_frames, pin, err, sizeof(err))) {
            logline_net("stream worker: failed: %s", err[0] ? err : "unknown");
        }

        pthread_mutex_lock(&worker->lock);
        worker->busy = false;
        pthread_mutex_unlock(&worker->lock);
    }
    return NULL;
}

static bool stream_worker_init(stream_worker *worker, app_state *state, IHS_Client *client) {
    memset(worker, 0, sizeof(*worker));
    worker->state = state;
    worker->client = client;
    if (client == NULL) {
        return false;
    }
    pthread_mutex_init(&worker->lock, NULL);
    pthread_cond_init(&worker->cond, NULL);
    if (pthread_create(&worker->thread, NULL, stream_worker_main, worker) != 0) {
        pthread_cond_destroy(&worker->cond);
        pthread_mutex_destroy(&worker->lock);
        memset(worker, 0, sizeof(*worker));
        return false;
    }
    worker->started = true;
    return true;
}

static void stream_worker_stop(stream_worker *worker) {
    if (worker == NULL || !worker->started) {
        return;
    }
    pthread_mutex_lock(&worker->lock);
    worker->stop = true;
    pthread_cond_signal(&worker->cond);
    pthread_mutex_unlock(&worker->lock);
}

static void stream_worker_join(stream_worker *worker) {
    if (worker == NULL || !worker->started) {
        return;
    }
    stream_worker_stop(worker);
    logline("cleanup: join stream worker");
    pthread_join(worker->thread, NULL);
    pthread_cond_destroy(&worker->cond);
    pthread_mutex_destroy(&worker->lock);
    memset(worker, 0, sizeof(*worker));
}

static bool stream_worker_enqueue(stream_worker *worker, app_state *state, bool desktop,
                                  bool hold, uint32_t auto_stop_frames, const char *pin, char *err,
                                  size_t err_len) {
    if (worker == NULL || !worker->started) {
        snprintf(err, err_len, "stream worker unavailable");
        return false;
    }

    pthread_mutex_lock(&state->lock);
    bool exiting = state->exit_requested;
    pthread_mutex_unlock(&state->lock);
    if (exiting) {
        snprintf(err, err_len, "exit requested");
        return false;
    }

    pthread_mutex_lock(&worker->lock);
    if (worker->busy || worker->request_pending) {
        pthread_mutex_unlock(&worker->lock);
        snprintf(err, err_len, "stream worker busy");
        return false;
    }
    worker->desktop = desktop;
    worker->hold = hold;
    worker->auto_stop_frames = auto_stop_frames;
    worker->pin[0] = '\0';
    if (pin != NULL && *pin != '\0') {
        strncpy(worker->pin, pin, sizeof(worker->pin) - 1);
        worker->pin[sizeof(worker->pin) - 1] = '\0';
    }
    worker->request_pending = true;
    pthread_cond_signal(&worker->cond);
    pthread_mutex_unlock(&worker->lock);

    pthread_mutex_lock(&state->lock);
    snprintf(state->status, sizeof(state->status), "Stream command queued");
    pthread_mutex_unlock(&state->lock);
    return true;
}

static void update_runtime_flags(app_state *state, const stream_runtime *runtime) {
    pthread_mutex_lock(&state->lock);
    state->ihs_initialized = runtime->ihs_initialized;
    state->ihs_client_ready = runtime->client != NULL;
    state->stream_worker_active = runtime->stream_worker_started;
    pthread_mutex_unlock(&state->lock);
}

static bool local_controls_read_volume(AudioTarget *target_out, s32 *volume_out) {
    AudioTarget target = AudioTarget_Invalid;
    Result rc = audctlGetActiveOutputTarget(&target);
    if (R_FAILED(rc) || target == AudioTarget_Invalid) {
        target = AudioTarget_Speaker;
    }
    s32 volume = 0;
    rc = audctlGetTargetVolume(&volume, target);
    if (R_FAILED(rc)) {
        return false;
    }
    if (target_out != NULL) {
        *target_out = target;
    }
    if (volume_out != NULL) {
        *volume_out = volume;
    }
    return true;
}

static void local_controls_init(local_controls *controls) {
    memset(controls, 0, sizeof(*controls));
    Result rc = audctlInitialize();
    controls->audctl_ready = R_SUCCEEDED(rc);
    if (!controls->audctl_ready) {
        logline("local hotkeys: audctl unavailable rc=0x%x; use debug stop/exit",
                (unsigned int)rc);
        return;
    }
    controls->have_volume = local_controls_read_volume(&controls->target, &controls->volume);
    logline("local hotkeys: hold LStick+RStick and tap VOL+ to exit, VOL- to stop; "
            "audctl=1 volumeReady=%d target=%d volume=%d",
            controls->have_volume ? 1 : 0, (int)controls->target, (int)controls->volume);
}

static void local_controls_shutdown(local_controls *controls) {
    if (controls != NULL && controls->audctl_ready) {
        audctlExit();
        controls->audctl_ready = false;
    }
}

static local_volume_change local_controls_poll_volume(local_controls *controls, uint64_t now_ms) {
    if (controls == NULL || !controls->audctl_ready || now_ms < controls->next_volume_poll_ms) {
        return LOCAL_VOLUME_NONE;
    }
    controls->next_volume_poll_ms = now_ms + LOCAL_VOLUME_POLL_MS;

    AudioTarget target = AudioTarget_Invalid;
    s32 volume = 0;
    if (!local_controls_read_volume(&target, &volume)) {
        controls->have_volume = false;
        return LOCAL_VOLUME_NONE;
    }

    local_volume_change change = LOCAL_VOLUME_NONE;
    if (controls->have_volume && target == controls->target && volume != controls->volume) {
        change = volume > controls->volume ? LOCAL_VOLUME_UP : LOCAL_VOLUME_DOWN;
    }
    controls->target = target;
    controls->volume = volume;
    controls->have_volume = true;
    return change;
}

static void local_controls_publish(app_state *state, const local_controls *controls) {
    if (state == NULL || controls == NULL) {
        return;
    }
    pthread_mutex_lock(&state->lock);
    state->local_hotkeys_ready = controls->audctl_ready;
    state->local_volume_ready = controls->have_volume;
    state->local_volume_target = (int)controls->target;
    state->local_volume_value = (int)controls->volume;
    pthread_mutex_unlock(&state->lock);
}

static bool ensure_ihs_started(app_state *state, stream_runtime *runtime, char *err,
                               size_t err_len) {
    pthread_mutex_lock(&state->lock);
    bool auth_ready = state->auth_loaded && state->auth.steam_id != 0;
    bool error_mode = state->mode == PROBE_ERROR;
    pthread_mutex_unlock(&state->lock);

    if (!auth_ready) {
        snprintf(err, err_len, "auth.bin is not paired");
        return false;
    }
    if (error_mode) {
        snprintf(err, err_len, "app is in error mode");
        return false;
    }

    if (!runtime->ihs_initialized) {
        write_boot_stage("ihs:init:start");
        logline("IHS init requested");
        IHS_Init();
        runtime->ihs_initialized = true;
        write_boot_stage("ihs:init:done");
        update_runtime_flags(state, runtime);
    }

    if (runtime->client == NULL) {
        write_boot_stage("client:create:start");
        runtime->client = IHS_ClientCreate(&runtime->client_config);
        write_boot_stage(runtime->client != NULL ? "client:create:done" : "client:create:failed");
        if (runtime->client == NULL) {
            pthread_mutex_lock(&state->lock);
            state->mode = PROBE_ERROR;
            snprintf(state->status, sizeof(state->status), "IHS_ClientCreate failed");
            pthread_mutex_unlock(&state->lock);
            update_runtime_flags(state, runtime);
            snprintf(err, err_len, "IHS_ClientCreate failed");
            logline("IHS_ClientCreate failed");
            return false;
        }
        IHS_ClientSetLogFunction(runtime->client, ihs_log);
        IHS_ClientSetDiscoveryCallbacks(runtime->client, &DISCOVERY_CALLBACKS, state);
        IHS_ClientSetStreamingCallbacks(runtime->client, &STREAMING_CALLBACKS, state);
        update_runtime_flags(state, runtime);
    }

    if (!runtime->stream_worker_started) {
        runtime->stream_worker_started =
            stream_worker_init(&runtime->streamer, state, runtime->client);
        update_runtime_flags(state, runtime);
        logline("stream worker active=%d", (int)runtime->stream_worker_started);
        if (!runtime->stream_worker_started) {
            snprintf(err, err_len, "stream worker failed to start");
            return false;
        }
    }

    pthread_mutex_lock(&state->lock);
    if (state->mode == PROBE_READY || state->mode == PROBE_DISCOVERING) {
        snprintf(state->status, sizeof(state->status), "IHS client ready");
    }
    pthread_mutex_unlock(&state->lock);
    return true;
}

static bool have_selected_host(app_state *state) {
    pthread_mutex_lock(&state->lock);
    bool have_host = state->selected_host >= 0 && state->selected_host < state->host_count;
    pthread_mutex_unlock(&state->lock);
    return have_host;
}

static bool wait_for_selected_host(app_state *state, uint64_t timeout_ms) {
    uint64_t deadline = monotonic_ms() + timeout_ms;
    while (monotonic_ms() < deadline) {
        if (have_selected_host(state)) {
            return true;
        }
        svcSleepThread(50 * 1000 * 1000);
    }
    return have_selected_host(state);
}

static bool prepare_stream_command(app_state *state, stream_runtime *runtime, bool desktop,
                                   char *err, size_t err_len) {
    (void)desktop;
    if (!ensure_media_started(state, err, err_len)) {
        return false;
    }
    if (!ensure_ihs_started(state, runtime, err, err_len)) {
        return false;
    }
    if (!have_selected_host(state)) {
        if (!send_discovery_once(state, runtime->client, err, err_len)) {
            return false;
        }
        if (!wait_for_selected_host(state, 2500)) {
            snprintf(err, err_len, "no Steam host discovered");
            return false;
        }
    }
    return true;
}

static bool start_session_if_ready(app_state *state, const IHS_ClientConfig *client_config) {
    IHS_SessionInfo info;

    pthread_mutex_lock(&state->lock);
    if (state->exit_requested || state->mode != PROBE_STREAM_READY || state->session != NULL) {
        if (state->exit_requested && state->mode == PROBE_STREAM_READY) {
            state->mode = PROBE_READY;
            state->stream_result = IHS_StreamingCanceled;
            snprintf(state->status, sizeof(state->status),
                     "Session start canceled: exit requested");
        }
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    info = state->session_info;
    state->mode = PROBE_SESSION_CONNECTING;
    snprintf(state->status, sizeof(state->status), "Creating session");
    pthread_mutex_unlock(&state->lock);

    IHS_Session *session = IHS_SessionCreate(client_config, &info);
    if (session == NULL) {
        pthread_mutex_lock(&state->lock);
        state->mode = PROBE_READY;
        snprintf(state->status, sizeof(state->status), "IHS_SessionCreate failed");
        pthread_mutex_unlock(&state->lock);
        logline("IHS_SessionCreate failed");
        return false;
    }

    IHS_SessionSetLogFunction(session, ihs_log);
    IHS_SessionSetSessionCallbacks(session, &SESSION_CALLBACKS, state);
    IHS_SessionSetVideoCallbacks(session, &VIDEO_CALLBACKS, state);
    IHS_SessionSetAudioCallbacks(session, &AUDIO_CALLBACKS, state);
    IHS_SessionStatsSetFullReporting(session, false);

#if NSTREAMLINK_APP
    IHS_HIDProvider *hid_provider = stream_media_create_hid_provider();
    if (hid_provider != NULL) {
        IHS_SessionHIDAddProvider(session, hid_provider);
        logline("hid provider added: SDL unmanaged app-controller");
    } else {
        logline("hid provider unavailable: SDL unmanaged create failed");
    }
#endif

    pthread_mutex_lock(&state->lock);
    state->session = session;
#if NSTREAMLINK_APP
    state->hid_provider = hid_provider;
#endif
    pthread_mutex_unlock(&state->lock);

    if (!IHS_SessionConnect(session)) {
        stream_media_set_hid_session(NULL, false);
        pthread_mutex_lock(&state->lock);
        state->session = NULL;
#if NSTREAMLINK_APP
        state->hid_provider = NULL;
#endif
        state->mode = PROBE_READY;
        snprintf(state->status, sizeof(state->status), "IHS_SessionConnect failed");
        pthread_mutex_unlock(&state->lock);
        logline("IHS_SessionConnect failed");
        IHS_SessionDestroy(session);
#if NSTREAMLINK_APP
        if (hid_provider != NULL) {
            stream_media_destroy_hid_provider(hid_provider);
        }
#endif
        return false;
    }

    char *ip = IHS_IPAddressToString(&info.address.ip);
    logline("session connect started: %s:%u keyLen=%zu steamId=%" PRIu64,
            ip ? ip : "?", info.address.port, info.sessionKeyLen, info.steamId);
    free(ip);
    return true;
}

static void log_perf_summary(app_state *state);

static bool join_destroy_session(app_state *state, bool send_stop) {
    IHS_Session *session = NULL;
#if NSTREAMLINK_APP
    IHS_HIDProvider *hid_provider = NULL;
#endif
    bool finished = false;
    bool connected = false;
    bool exit_after_stop = false;

    pthread_mutex_lock(&state->lock);
    session = state->session;
#if NSTREAMLINK_APP
    hid_provider = state->hid_provider;
#endif
    finished = state->session_finished;
    connected = state->session_connected;
    if (session == NULL) {
        state->stop_requested = false;
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    state->mode = PROBE_SESSION_STOPPING;
    state->stop_requested = false;
    snprintf(state->status, sizeof(state->status), "Stopping session");
    pthread_mutex_unlock(&state->lock);

#if NSTREAMLINK_APP
    stream_media_set_hid_session(NULL, false);
    if (connected && !finished) {
        logline("session stop: reset SDL controllers");
        IHS_HIDResetSDLGameControllers(session);
    }
#endif

    if (send_stop && !finished) {
        logline("session stop: IHS_SessionDisconnect");
        IHS_SessionDisconnect(session);
    } else {
        logline("session stop: joining already-finished session");
    }

    /* Ensure the session worker wakes from its recv loop even if the
     * StopRequest/ACK handshake could not complete (host already gone). */
    IHS_SessionInterrupt(session);
    logline("session stop: join");
    IHS_SessionThreadedJoin(session);
    logline("session stop: destroy");
    IHS_SessionDestroy(session);
#if NSTREAMLINK_APP
    if (hid_provider != NULL) {
        logline("session stop: destroy SDL HID provider");
        stream_media_destroy_hid_provider(hid_provider);
    }
#endif

    pthread_mutex_lock(&state->lock);
    uint32_t frames = state->frame_count;
    uint32_t keyframes = state->keyframe_count;
    state->session = NULL;
#if NSTREAMLINK_APP
    state->hid_provider = NULL;
#endif
    state->session_connected = false;
    state->session_finished = false;
    exit_after_stop = state->auto_stop_requested && state->exit_after_auto_stop;
    state->auto_stop_requested = false;
    state->exit_after_auto_stop = false;
    state->video_started = false;
    state->video_stalled = false;
    state->video_stall_report_ms = 0;
    state->mode = PROBE_READY;
    snprintf(state->status, sizeof(state->status), "Session stopped; frames=%u keyframes=%u",
             frames, keyframes);
    pthread_mutex_unlock(&state->lock);

    logline("session stopped: frames=%u keyframes=%u", frames, keyframes);
    log_perf_summary(state);
    return exit_after_stop;
}

static void state_line(app_state *state, char *out, size_t out_len) {
    IHS_HostInfo host;
    bool have_host = false;
    stream_mode mode;
    int host_count;
    int selected_host;
    uint64_t steam_id;
    bool session_active;
    bool session_connected;
    bool video_started;
    bool ihs_initialized;
    bool ihs_client_ready;
    bool stream_worker_active;
    bool stop_requested;
    bool exit_requested;
    bool local_hotkeys_ready;
    bool local_volume_ready;
    int local_volume_target;
    int local_volume_value;
    uint32_t width, height, frames, keyframes, auto_stop;
    uint32_t decoded, displayed, media_dropped;
    uint32_t frame_gaps, max_frame_gap;
    uint16_t last_frame;
    uint16_t last_displayed;
    size_t last_size;
    uint64_t encoded_bytes, stream_start_ms, first_frame_ms, last_frame_ms;
    uint64_t elapsed_ms = 0;
    uint64_t last_frame_age_ms = 0;
    uint64_t avg_kbps = 0;
    IHS_StreamVideoCodec codec;
    IHS_StreamingResult stream_result;
    bool first_displayed;
    stream_media_snapshot media;
    char decoder[64];
    char media_error[128];
    char exit_reason[sizeof(state->exit_reason)];
    char status[sizeof(state->status)];

    stream_media_get_snapshot(&media);

    pthread_mutex_lock(&state->lock);
    mode = state->mode;
    host_count = state->host_count;
    selected_host = state->selected_host;
    steam_id = state->auth.steam_id;
    session_active = state->session != NULL;
    session_connected = state->session_connected;
    video_started = state->video_started;
    ihs_initialized = state->ihs_initialized;
    ihs_client_ready = state->ihs_client_ready;
    stream_worker_active = state->stream_worker_active;
    stop_requested = state->stop_requested;
    exit_requested = state->exit_requested;
    local_hotkeys_ready = state->local_hotkeys_ready;
    local_volume_ready = state->local_volume_ready;
    local_volume_target = state->local_volume_target;
    local_volume_value = state->local_volume_value;
    width = state->video_width;
    height = state->video_height;
    codec = state->video_codec;
    frames = state->frame_count;
    keyframes = state->keyframe_count;
    decoded = state->decoded_frames;
    displayed = state->displayed_frames;
    media_dropped = state->media_dropped_frames;
    last_frame = state->last_frame_id;
    last_displayed = state->last_displayed_frame;
    last_size = state->last_frame_size;
    encoded_bytes = state->encoded_bytes;
    stream_start_ms = state->stream_start_ms;
    first_frame_ms = state->first_frame_ms;
    last_frame_ms = state->last_frame_ms;
    frame_gaps = state->frame_gap_count;
    max_frame_gap = state->max_frame_gap;
    auto_stop = state->auto_stop_after_frames;
    stream_result = state->stream_result;
    first_displayed = state->first_frame_displayed;
    strncpy(decoder, state->media_decoder, sizeof(decoder));
    decoder[sizeof(decoder) - 1] = '\0';
    strncpy(media_error, state->media_error, sizeof(media_error));
    media_error[sizeof(media_error) - 1] = '\0';
    strncpy(exit_reason, state->exit_reason, sizeof(exit_reason));
    exit_reason[sizeof(exit_reason) - 1] = '\0';
    strncpy(status, state->status, sizeof(status));
    status[sizeof(status) - 1] = '\0';
    if (selected_host >= 0 && selected_host < host_count) {
        host = state->hosts[selected_host];
        have_host = true;
    }
    pthread_mutex_unlock(&state->lock);

    if (stream_start_ms > 0 && last_frame_ms >= stream_start_ms) {
        elapsed_ms = last_frame_ms - stream_start_ms;
    }
    if (elapsed_ms > 0) {
        avg_kbps = (encoded_bytes * 8U) / elapsed_ms;
    }
    uint64_t now_ms = monotonic_ms();
    if (last_frame_ms > 0 && now_ms >= last_frame_ms) {
        last_frame_age_ms = now_ms - last_frame_ms;
    }

    char *ip = have_host ? IHS_IPAddressToString(&host.address.ip) : NULL;
    snprintf(out, out_len,
             "mode=%s hosts=%d selected=%d host=%s ip=%s games=%d paired=%d steamId=%" PRIu64
             " ihs=%d client=%d worker=%d streamResult=%d/%s session=%d connected=%d"
             " stopReq=%d exitReq=%d exitReason=\"%s\""
             " hotkeys=%d volumeReady=%d volumeTarget=%d volume=%d"
             " video=%d codec=%s size=%ux%u"
             " audio=%d audioCodec=%s(%d) audioHz=%d audioCh=%d audioFrames=%u"
             " audioQ=%u audioDrops=%u audioErr=%u"
             " frames=%u keyframes=%u decoded=%u displayed=%u firstFrame=%d mediaDrop=%u"
             " gaps=%u maxGap=%u encodedKB=%" PRIu64 " avgKbps=%" PRIu64
             " firstRxMs=%" PRIu64 " elapsedMs=%" PRIu64
             " lastFrame=%u lastFrameAgeMs=%" PRIu64
             " lastBytes=%zu lastDisplayed=%u decoder=\"%s\" mediaError=\"%s\""
             " autoStop=%u status=\"%s\"",
             mode_name(mode), host_count, selected_host + 1, have_host ? host.hostname : "-",
             ip ? ip : "-", have_host ? (int)host.gamesRunning : -1, steam_id != 0, steam_id,
             ihs_initialized, ihs_client_ready, stream_worker_active, (int)stream_result,
             stream_result_name(stream_result), session_active, session_connected, stop_requested,
             exit_requested, exit_reason[0] ? exit_reason : "-", local_hotkeys_ready,
             local_volume_ready, local_volume_target, local_volume_value, video_started,
             codec_name(codec), width, height, media.audio_active ? 1 : 0,
             audio_codec_name((IHS_StreamAudioCodec)media.audio_codec), media.audio_codec,
             media.audio_frequency, media.audio_channels, media.audio_frames,
             media.audio_queued_bytes, media.audio_queue_drops, media.audio_decode_errors,
             frames, keyframes, decoded, displayed,
             first_displayed, media_dropped, frame_gaps, max_frame_gap, encoded_bytes / 1024U,
             avg_kbps, first_frame_ms > stream_start_ms ? first_frame_ms - stream_start_ms : 0,
             elapsed_ms, last_frame,
             last_frame_age_ms, last_size, last_displayed, decoder[0] ? decoder : "-",
             media_error[0] ? media_error : "-", auto_stop, status[0] ? status : "-");
    free(ip);
}

static uint64_t avg_u64(uint64_t total, uint32_t count) {
    return count > 0 ? total / count : 0;
}

static void perf_line(app_state *state, char *out, size_t out_len) {
    uint32_t frames, keyframes, frame_gaps, max_frame_gap;
    uint64_t encoded_bytes, stream_start_ms, first_frame_ms, last_frame_ms;
    uint32_t auto_stop;
    char status[sizeof(state->status)];
    stream_media_snapshot media;

    stream_media_get_snapshot(&media);

    pthread_mutex_lock(&state->lock);
    frames = state->frame_count;
    keyframes = state->keyframe_count;
    frame_gaps = state->frame_gap_count;
    max_frame_gap = state->max_frame_gap;
    encoded_bytes = state->encoded_bytes;
    stream_start_ms = state->stream_start_ms;
    first_frame_ms = state->first_frame_ms;
    last_frame_ms = state->last_frame_ms;
    auto_stop = state->auto_stop_after_frames;
    strncpy(status, state->status, sizeof(status));
    status[sizeof(status) - 1] = '\0';
    pthread_mutex_unlock(&state->lock);

    uint64_t elapsed_ms = 0;
    if (stream_start_ms > 0 && last_frame_ms >= stream_start_ms) {
        elapsed_ms = last_frame_ms - stream_start_ms;
    }
    uint64_t avg_kbps = elapsed_ms > 0 ? (encoded_bytes * 8U) / elapsed_ms : 0;
    uint64_t first_rx_ms =
        first_frame_ms > stream_start_ms ? first_frame_ms - stream_start_ms : 0;

    snprintf(out, out_len,
             "frames=%u keyframes=%u decoded=%u displayed=%u mediaDrop=%u"
             " gaps=%u maxGap=%u encodedKB=%" PRIu64 " avgKbps=%" PRIu64
             " elapsedMs=%" PRIu64 " firstRxMs=%" PRIu64 " autoStop=%u"
             " decoder=\"%s\" transferFrames=%u vicTransfers=%u transferFallback=%u converted=%u"
             " audio=%d audioFrames=%u audioKB=%" PRIu64
             " audioSamples=%" PRIu64 " audioQ=%u audioDrops=%u audioErr=%u"
             " decodeAvgUs=%" PRIu64 " decodeMaxUs=%u"
             " transferAvgUs=%" PRIu64 " transferMaxUs=%u"
             " convertAvgUs=%" PRIu64 " convertMaxUs=%u"
             " uploadAvgUs=%" PRIu64 " uploadMaxUs=%u"
             " presentAvgUs=%" PRIu64 " presentMaxUs=%u"
             " frameLatAvgUs=%" PRIu64 " frameLatMaxUs=%u"
             " frameWaitAvgUs=%" PRIu64 " frameWaitMaxUs=%u"
             " hidSendAvgUs=%" PRIu64 " hidSendMaxUs=%u"
             " hidEvAgeAvgMs=%" PRIu64 " hidEvAgeMaxMs=%u"
             " mediaError=\"%s\" status=\"%s\"",
             frames, keyframes, media.decoded_frames, media.displayed_frames,
             media.dropped_frames, frame_gaps, max_frame_gap, encoded_bytes / 1024U,
             avg_kbps, elapsed_ms, first_rx_ms, auto_stop,
             media.decoder[0] ? media.decoder : "-", media.transferred_frames,
             media.vic_transfer_frames, media.transfer_fallback_frames,
             media.converted_frames, media.audio_active ? 1 : 0, media.audio_frames,
             media.audio_bytes / 1024U, media.audio_decoded_samples,
             media.audio_queued_bytes, media.audio_queue_drops, media.audio_decode_errors,
             avg_u64(media.decode_us_total, media.decode_samples), media.decode_us_max,
             avg_u64(media.transfer_us_total, media.transferred_frames), media.transfer_us_max,
             avg_u64(media.convert_us_total, media.converted_frames), media.convert_us_max,
             avg_u64(media.upload_us_total, media.displayed_frames), media.upload_us_max,
             avg_u64(media.present_us_total, media.displayed_frames), media.present_us_max,
             avg_u64(media.frame_e2e_us_total, media.frame_e2e_samples), media.frame_e2e_us_max,
             avg_u64(media.frame_wait_us_total, media.frame_wait_samples), media.frame_wait_us_max,
             avg_u64(media.hid_send_us_total, media.hid_send_samples), media.hid_send_us_max,
             avg_u64(media.hid_age_ms_total, media.hid_age_samples), media.hid_age_ms_max,
             media.last_error[0] ? media.last_error : "-", status[0] ? status : "-");
}

static void hid_line(char *out, size_t out_len) {
    static char diag_unhandled_types_scratch[512];
    diag_unhandled_types_scratch[0] = '\0';
    format_unhandled_types(diag_unhandled_types_scratch,
                           sizeof(diag_unhandled_types_scratch));
    stream_media_snapshot media;
    stream_media_get_snapshot(&media);
    snprintf(out, out_len,
             "hidEvents=%u hidSendOk=%u hidSendFail=%u stateFull=%u"
             " rawAxTotal=%u rawBtnTotal=%u styFlTotal=%u sty=%s"
             " minus=%d/%u/%d/%u"
             " providerDevices=%d sdlJoy=%d sdlIndex=%d sdlInstance=%d sdlType=%d"
             " lastEvent=%d/%d/%d/%d"
             " openOk=%u openFail=%u start=%u startLen=%u full=%u"
             " getFeature=%u getStrings=%u noDevice=%u activeInput=1 ctrlWarn=%u unhandled=%u unhandledTypes=[%s]"
             " rel=%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 " retry=%" PRIu64 " fail=%" PRIu64
             " out=%u oldest=%" PRIu64 "ms@%u/%u/%d#%u maxAck=%" PRIu64 "ms"
             " hidSM=%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
             "/%" PRIu64 "/%u/%u@%d"
             " sdlName=\"%s\" sdlGuid=%s",
             media.hid_events, media.hid_send_ok, media.hid_send_fail, media.hid_state_full,
             media.hid_raw_ax_total, media.hid_raw_btn_total,
             media.hid_style_flips_total,
             media.hid_style_state[0] ? media.hid_style_state : "-",
             media.hid_marker_minus_sdl_held ? 1 : 0,
             media.hid_marker_minus_sdl_samples_total,
             media.hid_marker_minus_raw_held ? 1 : 0,
             media.hid_marker_minus_raw_samples_total,
             media.hid_provider_devices, media.hid_sdl_joystick_count,
             media.hid_sdl_controller_index, media.hid_sdl_instance_id,
             media.hid_sdl_controller_type,
             media.hid_last_event_type, media.hid_last_event_which,
             media.hid_last_event_code, media.hid_last_event_value,
             (uint32_t)atomic_load_explicit(&diag_hid_open_ok, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_hid_open_fail, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_hid_start_reports, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_hid_start_report_len, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_hid_full_reports, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_hid_get_feature, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_hid_get_strings, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_hid_no_device, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_control_warn, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_control_unhandled, memory_order_relaxed),
             diag_unhandled_types_scratch,
             media.reliability.reliableTracked,
             media.reliability.reliableAcknowledged,
             media.reliability.reliableSuperseded,
             media.reliability.reliableGiveUps,
             media.reliability.reliableRetries,
             media.reliability.reliableSendFailures,
             media.reliability.reliableOutstanding,
             media.reliability.reliableOldestOutstandingMs,
             media.reliability.reliableOldestChannelId,
             media.reliability.reliableOldestPacketId,
             media.reliability.reliableOldestFragmentId,
             media.reliability.reliableOldestRetryCount,
             media.reliability.reliableMaxAckLatencyMs,
             media.reliability.hidSubmitted,
             media.reliability.hidCoalesced,
             media.reliability.hidSent,
             media.reliability.hidAcknowledged,
             media.reliability.hidSuperseded,
             media.reliability.hidPending,
             media.reliability.hidInFlight,
             media.reliability.hidOldestInFlightPacketId,
             media.hid_sdl_name[0] ? media.hid_sdl_name : "-",
             media.hid_sdl_guid[0] ? media.hid_sdl_guid : "-");
}

static void lat_line(char *out, size_t out_len) {
    stream_media_snapshot media;
    stream_media_get_snapshot(&media);
    snprintf(out, out_len,
             "frameLat=%" PRIu64 "/%uus(n=%u) frameWait=%" PRIu64 "/%uus(n=%u)"
             " hidSend=%" PRIu64 "/%uus(n=%u) hidEvAge=%" PRIu64 "/%ums(n=%u)",
             avg_u64(media.frame_e2e_us_total, media.frame_e2e_samples),
             media.frame_e2e_us_max, media.frame_e2e_samples,
             avg_u64(media.frame_wait_us_total, media.frame_wait_samples),
             media.frame_wait_us_max, media.frame_wait_samples,
             avg_u64(media.hid_send_us_total, media.hid_send_samples),
             media.hid_send_us_max, media.hid_send_samples,
             avg_u64(media.hid_age_ms_total, media.hid_age_samples),
             media.hid_age_ms_max, media.hid_age_samples);
}

static void audio_line(char *out, size_t out_len) {
    stream_media_snapshot media;
    stream_media_get_snapshot(&media);
    snprintf(out, out_len,
             "audio=%d codec=%s(%d) freq=%d channels=%d frames=%u"
             " pcmKB=%" PRIu64 " decodedSamples=%" PRIu64
             " queuedBytes=%u queueDrops=%u errors=%u",
             media.audio_active ? 1 : 0,
             audio_codec_name((IHS_StreamAudioCodec)media.audio_codec), media.audio_codec,
             media.audio_frequency, media.audio_channels, media.audio_frames,
             media.audio_bytes / 1024U, media.audio_decoded_samples,
             media.audio_queued_bytes, media.audio_queue_drops, media.audio_decode_errors);
}

typedef struct diag_marker_net {
    uint32_t frames;
    uint32_t keyframes;
    uint32_t displayed;
    uint32_t media_dropped;
    uint32_t audio_frames;
    uint32_t audio_queued_bytes;
    uint32_t audio_queue_drops;
    uint32_t audio_decode_errors;
    uint32_t frame_gaps;
    uint32_t max_frame_gap;
    uint32_t control_warn;
    uint64_t reliable_retries;
    uint64_t reliable_superseded;
    uint64_t hid_coalesced;
    uint64_t hid_superseded;
    uint32_t reliable_outstanding;
    uint32_t hid_pending;
    uint32_t hid_in_flight;
    uint64_t reliable_oldest_ms;
    uint32_t reliable_oldest_channel;
    uint32_t reliable_oldest_packet;
    int32_t reliable_oldest_fragment;
    uint32_t reliable_oldest_retry;
    int32_t hid_oldest_packet;
    uint64_t encoded_bytes;
    size_t last_frame_size;
    uint32_t frame_delta;
    uint32_t keyframe_delta;
    uint32_t displayed_delta;
    uint32_t media_drop_delta;
    uint32_t audio_delta;
    uint32_t frame_gap_delta;
    uint64_t reliable_retry_delta;
    uint64_t reliable_superseded_delta;
    uint64_t hid_coalesced_delta;
    uint64_t hid_superseded_delta;
    uint32_t control_warn_delta;
    uint64_t encoded_delta;
    uint64_t main_age_ms;
    uint64_t last_frame_age_ms;
} diag_marker_net;

typedef struct diag_disk_prev {
    bool valid;
    uint32_t frames;
    uint32_t keyframes;
    uint32_t displayed;
    uint32_t media_dropped;
    uint32_t audio_frames;
    uint32_t frame_gaps;
    uint32_t control_warn;
    uint64_t reliable_retries;
    uint64_t reliable_superseded;
    uint64_t hid_coalesced;
    uint64_t hid_superseded;
    uint64_t encoded_bytes;
} diag_disk_prev;

static uint32_t diag_counter_delta(uint32_t value, uint32_t previous, bool valid) {
    return valid && value >= previous ? value - previous : 0U;
}

static uint64_t diag_counter_delta64(uint64_t value, uint64_t previous, bool valid) {
    return valid && value >= previous ? value - previous : 0U;
}

static void diag_marker_net_capture(app_state *state, uint64_t now_ms,
                                    diag_disk_prev *prev, diag_marker_net *out) {
    stream_media_snapshot media;
    stream_media_get_snapshot(&media);

    uint64_t last_frame_ms = 0;
    memset(out, 0, sizeof(*out));

    pthread_mutex_lock(&state->lock);
    out->frames = state->frame_count;
    out->keyframes = state->keyframe_count;
    out->displayed = state->displayed_frames;
    out->media_dropped = state->media_dropped_frames;
    out->frame_gaps = state->frame_gap_count;
    out->max_frame_gap = state->max_frame_gap;
    out->encoded_bytes = state->encoded_bytes;
    out->last_frame_size = state->last_frame_size;
    last_frame_ms = state->last_frame_ms;
    pthread_mutex_unlock(&state->lock);

    out->audio_frames = media.audio_frames;
    out->audio_queued_bytes = media.audio_queued_bytes;
    out->audio_queue_drops = media.audio_queue_drops;
    out->audio_decode_errors = media.audio_decode_errors;
    out->control_warn =
        (uint32_t)atomic_load_explicit(&diag_control_warn, memory_order_relaxed);
    out->reliable_retries = media.reliability.reliableRetries;
    out->reliable_superseded = media.reliability.reliableSuperseded;
    out->hid_coalesced = media.reliability.hidCoalesced;
    out->hid_superseded = media.reliability.hidSuperseded;
    out->reliable_outstanding = media.reliability.reliableOutstanding;
    out->hid_pending = media.reliability.hidPending;
    out->hid_in_flight = media.reliability.hidInFlight;
    out->reliable_oldest_ms = media.reliability.reliableOldestOutstandingMs;
    out->reliable_oldest_channel = media.reliability.reliableOldestChannelId;
    out->reliable_oldest_packet = media.reliability.reliableOldestPacketId;
    out->reliable_oldest_fragment = media.reliability.reliableOldestFragmentId;
    out->reliable_oldest_retry = media.reliability.reliableOldestRetryCount;
    out->hid_oldest_packet = media.reliability.hidOldestInFlightPacketId;
    uint64_t last_main_ms =
        atomic_load_explicit(&watchdog_last_main_ms, memory_order_relaxed);
    if (last_main_ms > 0 && now_ms >= last_main_ms) {
        out->main_age_ms = now_ms - last_main_ms;
    }
    if (last_frame_ms > 0 && now_ms >= last_frame_ms) {
        out->last_frame_age_ms = now_ms - last_frame_ms;
    }

    out->frame_delta = diag_counter_delta(out->frames, prev->frames, prev->valid);
    out->keyframe_delta =
        diag_counter_delta(out->keyframes, prev->keyframes, prev->valid);
    out->displayed_delta =
        diag_counter_delta(out->displayed, prev->displayed, prev->valid);
    out->media_drop_delta =
        diag_counter_delta(out->media_dropped, prev->media_dropped, prev->valid);
    out->audio_delta = diag_counter_delta(out->audio_frames, prev->audio_frames, prev->valid);
    out->frame_gap_delta =
        diag_counter_delta(out->frame_gaps, prev->frame_gaps, prev->valid);
    out->reliable_retry_delta =
        diag_counter_delta64(out->reliable_retries, prev->reliable_retries, prev->valid);
    out->reliable_superseded_delta =
        diag_counter_delta64(out->reliable_superseded, prev->reliable_superseded,
                             prev->valid);
    out->hid_coalesced_delta =
        diag_counter_delta64(out->hid_coalesced, prev->hid_coalesced, prev->valid);
    out->hid_superseded_delta =
        diag_counter_delta64(out->hid_superseded, prev->hid_superseded, prev->valid);
    out->control_warn_delta =
        diag_counter_delta(out->control_warn, prev->control_warn, prev->valid);
    out->encoded_delta =
        diag_counter_delta64(out->encoded_bytes, prev->encoded_bytes, prev->valid);

    prev->valid = true;
    prev->frames = out->frames;
    prev->keyframes = out->keyframes;
    prev->displayed = out->displayed;
    prev->media_dropped = out->media_dropped;
    prev->audio_frames = out->audio_frames;
    prev->frame_gaps = out->frame_gaps;
    prev->control_warn = out->control_warn;
    prev->reliable_retries = out->reliable_retries;
    prev->reliable_superseded = out->reliable_superseded;
    prev->hid_coalesced = out->hid_coalesced;
    prev->hid_superseded = out->hid_superseded;
    prev->encoded_bytes = out->encoded_bytes;
}

static void diag_recent_reset(void) {
    pthread_mutex_lock(&diag_recent_lock);
    diag_recent_len = 0;
    diag_recent[0] = '\0';
    pthread_mutex_unlock(&diag_recent_lock);
}

static void diag_recent_append(const char *text) {
    if (text == NULL || text[0] == '\0') {
        return;
    }
    size_t text_len = strlen(text);
    size_t capacity = sizeof(diag_recent) - 1U;
    pthread_mutex_lock(&diag_recent_lock);
    if (text_len >= capacity) {
        memcpy(diag_recent, text + text_len - capacity, capacity);
        diag_recent_len = capacity;
    } else {
        if (diag_recent_len + text_len > capacity) {
            size_t drop = diag_recent_len + text_len - capacity;
            memmove(diag_recent, diag_recent + drop, diag_recent_len - drop);
            diag_recent_len -= drop;
        }
        memcpy(diag_recent + diag_recent_len, text, text_len);
        diag_recent_len += text_len;
    }
    diag_recent[diag_recent_len] = '\0';
    pthread_mutex_unlock(&diag_recent_lock);
}

static bool diag_recent_copy(char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return false;
    }
    pthread_mutex_lock(&diag_recent_lock);
    size_t n = diag_recent_len < out_len - 1U ? diag_recent_len : out_len - 1U;
    if (n > 0) {
        memcpy(out, diag_recent + diag_recent_len - n, n);
    }
    pthread_mutex_unlock(&diag_recent_lock);
    out[n] = '\0';
    return n > 0;
}

static void diag_marker_recent_reset(void) {
    pthread_mutex_lock(&diag_marker_recent_lock);
    diag_marker_recent_len = 0;
    diag_marker_recent[0] = '\0';
    pthread_mutex_unlock(&diag_marker_recent_lock);
}

static void diag_marker_recent_append(const char *text) {
    if (text == NULL || text[0] == '\0') {
        return;
    }
    size_t text_len = strlen(text);
    size_t capacity = sizeof(diag_marker_recent) - 1U;
    pthread_mutex_lock(&diag_marker_recent_lock);
    if (text_len >= capacity) {
        memcpy(diag_marker_recent, text + text_len - capacity, capacity);
        diag_marker_recent_len = capacity;
    } else {
        if (diag_marker_recent_len + text_len > capacity) {
            size_t drop = diag_marker_recent_len + text_len - capacity;
            memmove(diag_marker_recent, diag_marker_recent + drop,
                    diag_marker_recent_len - drop);
            diag_marker_recent_len -= drop;
        }
        memcpy(diag_marker_recent + diag_marker_recent_len, text, text_len);
        diag_marker_recent_len += text_len;
    }
    diag_marker_recent[diag_marker_recent_len] = '\0';
    pthread_mutex_unlock(&diag_marker_recent_lock);
}

static bool diag_marker_recent_copy(char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return false;
    }
    pthread_mutex_lock(&diag_marker_recent_lock);
    size_t n = diag_marker_recent_len < out_len - 1U ? diag_marker_recent_len : out_len - 1U;
    if (n > 0) {
        memcpy(out, diag_marker_recent + diag_marker_recent_len - n, n);
    }
    pthread_mutex_unlock(&diag_marker_recent_lock);
    out[n] = '\0';
    return n > 0;
}

static void diag_disk_printf(FILE *fp, const char *fmt, ...) {
    char line[DEBUG_TX + 512U];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    fputs(line, fp);
    diag_recent_append(line);
}

static void diag_marker_printf(FILE *fp, const char *fmt, ...) {
    char line[DEBUG_TX + 512U];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (fp != NULL) {
        fputs(line, fp);
    }
    diag_marker_recent_append(line);
}

static void diag_disk_write_hid_history(FILE *fp, FILE *marker_fp, uint32_t *last_seq,
                                        const diag_marker_net *net) {
    stream_media_hid_history_entry entries[60];
    size_t count = stream_media_copy_hid_history(entries, sizeof(entries) / sizeof(entries[0]));
    for (size_t i = 0; i < count; i++) {
        const stream_media_hid_history_entry *e = &entries[i];
        if (e->seq <= *last_seq) {
            continue;
        }
        bool marker_seen = e->marker_minus_sdl_held != 0 ||
                           e->marker_minus_sdl_samples != 0 ||
                           e->marker_minus_raw_held != 0 ||
                           e->marker_minus_raw_samples != 0;
        diag_disk_printf(fp,
                         "hidsec seq=%u sec=%u e=%u ok=%u f=%u h=%u p=%u ax=%u btn=%u sen=%u oth=%u "
                         "sup=%u raw=%u/%u sty=%u:%s sticks=%d/%d/%d/%d b=0x%x "
                         "sent=%d/%d/%d/%d b=0x%x#%u "
                         "minus=%u/%u/%u/%u tot=%u/%u/%u/%u/%u last=%d/%d/%d/%d\n",
                         e->seq, e->sec, e->events, e->send_ok, e->send_fail,
                         e->state_full, e->pump, e->ax, e->btn, e->sen, e->oth,
                         e->ev_sup, e->raw_ax, e->raw_btn, e->sty_fl,
                         e->sty[0] ? e->sty : "-", e->left_x, e->left_y,
                         e->right_x, e->right_y, e->buttons,
                         e->sent_lx, e->sent_ly, e->sent_rx, e->sent_ry,
                         e->sent_buttons, e->sent_seq,
                         e->marker_minus_sdl_held, e->marker_minus_sdl_samples,
                         e->marker_minus_raw_held, e->marker_minus_raw_samples,
                         e->events_total,
                         e->send_ok_total, e->state_full_total, e->raw_ax_total,
                         e->raw_btn_total, e->last_type, e->last_which,
                         e->last_code, e->last_value);
        if (marker_seen) {
            diag_marker_printf(marker_fp,
                               "markMinus seq=%u sec=%u e=%u ok=%u f=%u h=%u p=%u ax=%u btn=%u raw=%u/%u "
                               "sticks=%d/%d/%d/%d b=0x%x minus=%u/%u/%u/%u tot=%u/%u/%u/%u/%u last=%d/%d/%d/%d\n",
                               e->seq, e->sec, e->events, e->send_ok, e->send_fail,
                               e->state_full, e->pump, e->ax, e->btn, e->raw_ax,
                               e->raw_btn, e->left_x, e->left_y, e->right_x,
                               e->right_y, e->buttons, e->marker_minus_sdl_held,
                               e->marker_minus_sdl_samples, e->marker_minus_raw_held,
                               e->marker_minus_raw_samples, e->events_total,
                               e->send_ok_total, e->state_full_total, e->raw_ax_total,
                               e->raw_btn_total, e->last_type, e->last_which,
                               e->last_code, e->last_value);
            diag_marker_printf(marker_fp,
                               "markNet seq=%u frames=%u/+%u displayed=%u/+%u audio=%u/+%u "
                               "mainAgeMs=%" PRIu64 " lastFrameAgeMs=%" PRIu64
                               " gaps=%u/%u audioQ=%u "
                               "audioDrop=%u audioErr=%u relRetry=%" PRIu64 "/+%" PRIu64
                               " relSup=%" PRIu64 "/+%" PRIu64
                               " relOut=%u relOldest=%" PRIu64 "@%u/%u/%d#%u"
                               " hidCoal=%" PRIu64 "/+%" PRIu64
                               " hidSup=%" PRIu64 "/+%" PRIu64 " hidWait=%u/%u@%d"
                               " ctrlWarn=%u/+%u\n",
                               e->seq, net->frames, net->frame_delta, net->displayed,
                               net->displayed_delta, net->audio_frames, net->audio_delta,
                               net->main_age_ms, net->last_frame_age_ms, net->frame_gaps,
                               net->max_frame_gap, net->audio_queued_bytes,
                               net->audio_queue_drops,
                               net->audio_decode_errors, net->reliable_retries,
                               net->reliable_retry_delta, net->reliable_superseded,
                               net->reliable_superseded_delta, net->reliable_outstanding,
                               net->reliable_oldest_ms, net->reliable_oldest_channel,
                               net->reliable_oldest_packet, net->reliable_oldest_fragment,
                               net->reliable_oldest_retry, net->hid_coalesced,
                               net->hid_coalesced_delta, net->hid_superseded,
                               net->hid_superseded_delta, net->hid_pending,
                               net->hid_in_flight, net->hid_oldest_packet, net->control_warn,
                               net->control_warn_delta);
        }
        *last_seq = e->seq;
    }
}

static void diag_disk_write_tick(FILE *fp, FILE *marker_fp, app_state *state,
                                 uint32_t *last_hid_seq, diag_disk_prev *prev) {
    uint64_t now = monotonic_ms();
    uint64_t last_main = atomic_load_explicit(&watchdog_last_main_ms, memory_order_relaxed);
    uint64_t main_age = last_main > 0 && now >= last_main ? now - last_main : 0;
    char state_buf[DEBUG_TX];
    char hid_buf[DEBUG_TX];
    char audio_buf[DEBUG_TX];
    diag_marker_net net;

    diag_marker_net_capture(state, now, prev, &net);
    state_line(state, state_buf, sizeof(state_buf));
    hid_line(hid_buf, sizeof(hid_buf));
    audio_line(audio_buf, sizeof(audio_buf));
    char lat_buf[DEBUG_TX];
    lat_line(lat_buf, sizeof(lat_buf));

    diag_disk_printf(fp, "diag ms=%" PRIu64 " mainAgeMs=%" PRIu64 " %s\n", now,
                     main_age, state_buf);
    diag_disk_printf(fp, "diag-hid ms=%" PRIu64 " %s\n", now, hid_buf);
    diag_disk_printf(fp, "diag-audio ms=%" PRIu64 " %s\n", now, audio_buf);
    diag_disk_printf(fp, "diag-lat ms=%" PRIu64 " %s\n", now, lat_buf);
    /* Merge queued IHS logs into the diag file: control-plane events
     * (unhandled messages, disable windows, stop flow) must survive on SD,
     * not evaporate in the volatile console ring. */
    for (;;) {
        pthread_mutex_lock(&logq_lock);
        if (logq_head == logq_tail) {
            pthread_mutex_unlock(&logq_lock);
            break;
        }
        char local[LOGQ_MSG];
        strncpy(local, logq[logq_tail], sizeof(local) - 1);
        local[sizeof(local) - 1] = '\0';
        uint64_t tms = logq_ms[logq_tail];
        logq_tail = (logq_tail + 1) % LOGQ_LEN;
        pthread_mutex_unlock(&logq_lock);
        diag_disk_printf(fp, "log ms=%" PRIu64 " %s\n", tms, local);
    }
    {
        static char hidrep_buf[4096];
        size_t n = IHS_SessionChannelControlDrainPendingHIDReports(
            hidrep_buf, sizeof(hidrep_buf));
        if (n > 0) {
            diag_disk_printf(fp, "%.*s", (int) n, hidrep_buf);
        }
    }
    diag_disk_write_hid_history(fp, marker_fp, last_hid_seq, &net);
    atomic_fetch_add_explicit(&diag_disk_ticks, 1, memory_order_relaxed);
}

static void diag_disk_flush(FILE *fp) {
    fflush(fp);
    int fd = fileno(fp);
    if (fd >= 0) {
        fsync(fd);
    }
}

static void *diag_disk_thread_main(void *arg) {
    app_state *state = (app_state *)arg;
    atomic_store_explicit(&diag_disk_thread_alive, true, memory_order_relaxed);
    atomic_store_explicit(&diag_disk_thread_error, 0, memory_order_relaxed);
    FILE *fp = fopen(DIAG_PATH, "a");
    if (fp == NULL) {
        atomic_store_explicit(&diag_disk_thread_error, (uint32_t)errno, memory_order_relaxed);
        atomic_store_explicit(&diag_disk_thread_alive, false, memory_order_relaxed);
        return NULL;
    }
    FILE *marker_fp = fopen(DIAG_MARKER_PATH, "a");
    if (marker_fp == NULL) {
        atomic_store_explicit(&diag_disk_marker_error, (uint32_t)errno, memory_order_relaxed);
    }
    setvbuf(fp, NULL, _IOLBF, 0);
    if (marker_fp != NULL) {
        setvbuf(marker_fp, NULL, _IOLBF, 0);
    }
    diag_disk_printf(fp, "thread_start ms=%" PRIu64 "\n", monotonic_ms());
    uint32_t last_hid_seq = 0;
    diag_disk_prev prev = {0};
    diag_disk_write_tick(fp, marker_fp, state, &last_hid_seq, &prev);
    diag_disk_flush(fp);
    if (marker_fp != NULL) {
        diag_disk_flush(marker_fp);
    }

    while (!atomic_load_explicit(&diag_disk_stop, memory_order_relaxed)) {
        for (int i = 0; i < 10; i++) {
            if (atomic_load_explicit(&diag_disk_stop, memory_order_relaxed)) {
                break;
            }
            svcSleepThread(100ULL * 1000ULL * 1000ULL);
        }
        if (atomic_load_explicit(&diag_disk_stop, memory_order_relaxed)) {
            break;
        }
        diag_disk_write_tick(fp, marker_fp, state, &last_hid_seq, &prev);
        diag_disk_flush(fp);
        if (marker_fp != NULL) {
            diag_disk_flush(marker_fp);
        }
    }

    diag_disk_printf(fp, "thread_stop ms=%" PRIu64 "\n", monotonic_ms());
    diag_disk_write_tick(fp, marker_fp, state, &last_hid_seq, &prev);
    diag_disk_flush(fp);
    fclose(fp);
    if (marker_fp != NULL) {
        diag_disk_flush(marker_fp);
        fclose(marker_fp);
    }
    atomic_store_explicit(&diag_disk_thread_alive, false, memory_order_relaxed);
    return NULL;
}

static void diag_disk_start(app_state *state) {
    if (diag_disk_started) {
        return;
    }
    int saved_errno = errno;
    atomic_store_explicit(&diag_disk_start_error, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_disk_thread_error, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_disk_marker_error, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_disk_event_error, 0, memory_order_relaxed);
    atomic_store_explicit(&diag_disk_ticks, 0, memory_order_relaxed);
    diag_recent_reset();
    diag_marker_recent_reset();
    if (!ensure_auth_dir()) {
        atomic_store_explicit(&diag_disk_start_error, (uint32_t)errno, memory_order_relaxed);
        logline("diag disk disabled: mkdir errno=%d", errno);
        errno = saved_errno;
        return;
    }
    remove(DIAG_OLDER_PATH);
    if (rename(DIAG_PREV_PATH, DIAG_OLDER_PATH) != 0 && errno != ENOENT) {
        logline("diag older rotate failed: errno=%d", errno);
    }
    if (rename(DIAG_PATH, DIAG_PREV_PATH) != 0 && errno != ENOENT) {
        logline("diag disk rotate failed: errno=%d", errno);
    }
    remove(DIAG_MARKER_OLDER_PATH);
    if (rename(DIAG_MARKER_PREV_PATH, DIAG_MARKER_OLDER_PATH) != 0 && errno != ENOENT) {
        logline("diag marker older rotate failed: errno=%d", errno);
    }
    if (rename(DIAG_MARKER_PATH, DIAG_MARKER_PREV_PATH) != 0 && errno != ENOENT) {
        logline("diag marker rotate failed: errno=%d", errno);
    }

    FILE *fp = fopen(DIAG_PATH, "w");
    if (fp == NULL) {
        atomic_store_explicit(&diag_disk_start_error, (uint32_t)errno, memory_order_relaxed);
        logline("diag disk disabled: fopen errno=%d", errno);
        errno = saved_errno;
        return;
    }
    char header[96];
    snprintf(header, sizeof(header), "run_start ms=%" PRIu64 " app=%d\n", monotonic_ms(),
             (int)NSTREAMLINK_APP);
    fputs(header, fp);
    diag_recent_append(header);
    diag_disk_flush(fp);
    fclose(fp);
    FILE *marker_fp = fopen(DIAG_MARKER_PATH, "w");
    if (marker_fp != NULL) {
        diag_disk_flush(marker_fp);
        fclose(marker_fp);
    } else {
        atomic_store_explicit(&diag_disk_marker_error, (uint32_t)errno, memory_order_relaxed);
    }

    atomic_store_explicit(&diag_disk_stop, false, memory_order_relaxed);
    int rc = pthread_create(&diag_disk_thread, NULL, diag_disk_thread_main, state);
    if (rc != 0) {
        atomic_store_explicit(&diag_disk_start_error, (uint32_t)rc, memory_order_relaxed);
        logline("diag disk disabled: pthread_create rc=%d", rc);
        errno = saved_errno;
        return;
    }
    diag_disk_started = true;
    logline("diag disk active: %s prev=%s older=%s", DIAG_PATH, DIAG_PREV_PATH,
            DIAG_OLDER_PATH);
    errno = saved_errno;
}

static void diag_disk_stop_thread(void) {
    if (!diag_disk_started) {
        return;
    }
    atomic_store_explicit(&diag_disk_stop, true, memory_order_relaxed);
    pthread_join(diag_disk_thread, NULL);
    diag_disk_started = false;
    logline("diag disk stopped");
}

static void diag_status_line(char *out, size_t out_len) {
    snprintf(out, out_len,
             "started=%d alive=%d stop=%d ticks=%u startErr=%u threadErr=%u markerErr=%u "
             "path=%s prev=%s older=%s marker=%s markerPrev=%s markerOlder=%s",
             diag_disk_started ? 1 : 0,
             atomic_load_explicit(&diag_disk_thread_alive, memory_order_relaxed) ? 1 : 0,
             atomic_load_explicit(&diag_disk_stop, memory_order_relaxed) ? 1 : 0,
             (uint32_t)atomic_load_explicit(&diag_disk_ticks, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_disk_start_error, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_disk_thread_error, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&diag_disk_marker_error, memory_order_relaxed),
             DIAG_PATH, DIAG_PREV_PATH, DIAG_OLDER_PATH, DIAG_MARKER_PATH,
             DIAG_MARKER_PREV_PATH, DIAG_MARKER_OLDER_PATH);
}

static void log_perf_summary(app_state *state) {
    char line[DEBUG_TX];
    perf_line(state, line, sizeof(line));
    logline("perf summary: %.210s", line);
    if (strlen(line) > 210) {
        logline("perf summary continued: %.210s", line + 210);
    }
    if (strlen(line) > 420) {
        logline("perf summary continued2: %.210s", line + 420);
    }
}

static void console_draw(app_state *state) {
    if (cons_fd < 0) {
        return;
    }

    IHS_HostInfo hosts[MAX_HOSTS];
    int host_count;
    int selected_host;
    sl_auth_file auth;
    stream_mode mode;
    bool session_active, session_connected, video_started;
    uint32_t width, height, frames, keyframes, auto_stop;
    uint32_t decoded, displayed, media_dropped;
    uint16_t last_frame;
    uint16_t last_displayed;
    size_t last_size;
    IHS_StreamVideoCodec codec;
    bool first_displayed;
    stream_media_snapshot media;
    char decoder[64];
    char media_error[128];
    char status[sizeof(state->status)];

    stream_media_get_snapshot(&media);

    pthread_mutex_lock(&state->lock);
    host_count = state->host_count;
    selected_host = state->selected_host;
    for (int i = 0; i < host_count; i++) {
        hosts[i] = state->hosts[i];
    }
    auth = state->auth;
    mode = state->mode;
    session_active = state->session != NULL;
    session_connected = state->session_connected;
    video_started = state->video_started;
    width = state->video_width;
    height = state->video_height;
    codec = state->video_codec;
    frames = state->frame_count;
    keyframes = state->keyframe_count;
    decoded = state->decoded_frames;
    displayed = state->displayed_frames;
    media_dropped = state->media_dropped_frames;
    last_frame = state->last_frame_id;
    last_displayed = state->last_displayed_frame;
    last_size = state->last_frame_size;
    auto_stop = state->auto_stop_after_frames;
    first_displayed = state->first_frame_displayed;
    strncpy(decoder, state->media_decoder, sizeof(decoder));
    decoder[sizeof(decoder) - 1] = '\0';
    strncpy(media_error, state->media_error, sizeof(media_error));
    media_error[sizeof(media_error) - 1] = '\0';
    strncpy(status, state->status, sizeof(status));
    status[sizeof(status) - 1] = '\0';
    pthread_mutex_unlock(&state->lock);

    dprintf(cons_fd, "\x1b[2J\x1b[H");
    dprintf(cons_fd, "nsteamlink stream selftest\n");
    dprintf(cons_fd, "auth: %s  deviceId: 0x%016" PRIx64 "  steamId: %" PRIu64 "\n",
            auth.steam_id ? "paired" : "not paired", auth.device_id, auth.steam_id);
    dprintf(cons_fd, "mode: %s  status: %s\n\n", mode_name(mode), status[0] ? status : "-");
    dprintf(cons_fd,
            "menu: A start  X mode  Y refresh  B stop | local: L3+R3+VOL+ exit  L3+R3+VOL- stop\n");
    dprintf(cons_fd,
            "Debug UDP %d: state | stats | stream [game] [frames=N|seconds=N|hold] | stop | exit\n\n",
            DEBUG_PORT);

    if (mode == PROBE_ERROR) {
        dprintf(cons_fd, "Error: %s\n", status[0] ? status : "-");
        return;
    }

    dprintf(cons_fd, "Hosts:\n");
    if (host_count == 0) {
        dprintf(cons_fd, "  none yet; Steam must be running on the host\n");
    }
    for (int i = 0; i < host_count; i++) {
        char *ip = IHS_IPAddressToString(&hosts[i].address.ip);
        dprintf(cons_fd, "%c %d. %s  %s  gamesRunning=%d\n",
                i == selected_host ? '>' : ' ', i + 1, hosts[i].hostname,
                ip ? ip : "?", (int)hosts[i].gamesRunning);
        free(ip);
    }

    dprintf(cons_fd, "\nSession:\n");
    dprintf(cons_fd, "  active=%d connected=%d video=%d autoStop=%u\n",
            session_active, session_connected, video_started, auto_stop);
    dprintf(cons_fd, "  codec=%s size=%ux%u frames=%u keyframes=%u\n",
            codec_name(codec), width, height, frames, keyframes);
    dprintf(cons_fd, "  decoded=%u displayed=%u first=%d mediaDrop=%u decoder=%s\n",
            decoded, displayed, first_displayed, media_dropped, decoder[0] ? decoder : "-");
    dprintf(cons_fd, "  audio=%d %s %dHz ch=%d frames=%u queued=%u err=%u drop=%u\n",
            media.audio_active ? 1 : 0,
            audio_codec_name((IHS_StreamAudioCodec)media.audio_codec),
            media.audio_frequency, media.audio_channels, media.audio_frames,
            media.audio_queued_bytes, media.audio_decode_errors, media.audio_queue_drops);
    dprintf(cons_fd, "  lastFrame=%u lastBytes=%zu lastDisplayed=%u\n",
            last_frame, last_size, last_displayed);
    if (media_error[0]) {
        dprintf(cons_fd, "  mediaError=%s\n", media_error);
    }
}

static void update_media_snapshot(app_state *state) {
    stream_media_snapshot media;
    stream_media_get_snapshot(&media);
    atomic_store_explicit(&watchdog_displayed_frames, media.displayed_frames,
                          memory_order_relaxed);

    pthread_mutex_lock(&state->lock);
    state->media_available = media.available;
    state->first_frame_displayed = media.first_frame_displayed;
    state->decoded_frames = media.decoded_frames;
    state->displayed_frames = media.displayed_frames;
    state->media_dropped_frames = media.dropped_frames;
    state->last_displayed_frame = media.last_displayed_frame;
    if (media.width > 0 && media.height > 0) {
        state->video_width = (uint32_t)media.width;
        state->video_height = (uint32_t)media.height;
    }
    strncpy(state->media_decoder, media.decoder, sizeof(state->media_decoder));
    state->media_decoder[sizeof(state->media_decoder) - 1] = '\0';
    strncpy(state->media_error, media.last_error, sizeof(state->media_error));
    state->media_error[sizeof(state->media_error) - 1] = '\0';
    pthread_mutex_unlock(&state->lock);
}

static void ui_set_line(stream_media_ui *ui, int *line, const char *fmt, ...) {
    if (ui == NULL || line == NULL || *line < 0 || *line >= STREAM_MEDIA_UI_LINES) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ui->lines[*line], sizeof(ui->lines[*line]), fmt, ap);
    va_end(ap);
    ui->lines[*line][sizeof(ui->lines[*line]) - 1] = '\0';
    (*line)++;
}

static void note_video_stall_if_needed(app_state *state) {
    uint64_t now = monotonic_ms();
    uint64_t age = 0;
    uint32_t frames = 0;
    bool log_stall = false;

    pthread_mutex_lock(&state->lock);
    bool can_stall = state->session != NULL && state->session_connected && state->video_started &&
                     state->first_frame_ms > 0 && state->last_frame_ms > 0 &&
                     now >= state->last_frame_ms;
    if (can_stall) {
        age = now - state->last_frame_ms;
        frames = state->frame_count;
        if (age > VIDEO_STALL_NOTICE_MS) {
            if (!state->video_stalled) {
                log_stall = true;
            }
            state->video_stalled = true;
            state->video_stall_report_ms = now;
            snprintf(state->status, sizeof(state->status),
                     "Video stalled: no frames for %" PRIu64 "ms", age);
            snprintf(state->ui_notice, sizeof(state->ui_notice),
                     "Video stalled; waiting for Steam");
        }
        /* Host-side game launch stops the stream without telling us; a frozen
         * frame forever reads as a dead app. Give Steam a grace window for a
         * video-channel restart, then auto-stop back to the menu (#11 bridge). */
        if (age > VIDEO_STALL_AUTO_STOP_MS && !state->stop_requested) {
            state->stop_requested = true;
            snprintf(state->ui_notice, sizeof(state->ui_notice),
                     "Host stopped streaming; returning to menu");
            logline_net("video stalled %" PRIu64 "ms after %u frames; auto stop stream", age,
                        frames);
        }
    }
    pthread_mutex_unlock(&state->lock);

    if (log_stall) {
        logline_net("video stalled: no frames for %" PRIu64 "ms after %u frames", age, frames);
    }
}

static void update_screen_ui(app_state *state) {
    if (!stream_media_available()) {
        return;
    }

    stream_media_ui ui;
    memset(&ui, 0, sizeof(ui));

    IHS_HostInfo host;
    bool have_host = false;
    stream_mode mode;
    IHS_StreamingResult stream_result;
    int host_count;
    int selected_host;
    bool auth_loaded;
    bool ui_desktop;
    bool ui_pin_mode;
    int ui_pin_cursor;
    char ui_pin[sizeof(state->ui_pin)];
    char ui_notice[sizeof(state->ui_notice)];
    char status[sizeof(state->status)];
    bool session_active;
    bool video_started;
    uint32_t frames, displayed, dropped, gaps, max_gap;
    stream_media_snapshot media;
    char decoder[sizeof(state->media_decoder)];

    stream_media_get_snapshot(&media);

    pthread_mutex_lock(&state->lock);
    mode = state->mode;
    stream_result = state->stream_result;
    host_count = state->host_count;
    selected_host = state->selected_host;
    if (selected_host >= 0 && selected_host < host_count) {
        host = state->hosts[selected_host];
        have_host = true;
    }
    auth_loaded = state->auth_loaded;
    ui_desktop = state->ui_desktop;
    ui_pin_mode = state->ui_pin_mode;
    ui_pin_cursor = state->ui_pin_cursor;
    strncpy(ui_pin, state->ui_pin, sizeof(ui_pin));
    ui_pin[sizeof(ui_pin) - 1] = '\0';
    strncpy(ui_notice, state->ui_notice, sizeof(ui_notice));
    ui_notice[sizeof(ui_notice) - 1] = '\0';
    strncpy(status, state->status, sizeof(status));
    status[sizeof(status) - 1] = '\0';
    session_active = state->session != NULL;
    video_started = state->video_started;
    frames = state->frame_count;
    displayed = state->displayed_frames;
    dropped = state->media_dropped_frames;
    gaps = state->frame_gap_count;
    max_gap = state->max_frame_gap;
    strncpy(decoder, state->media_decoder, sizeof(decoder));
    decoder[sizeof(decoder) - 1] = '\0';
    pthread_mutex_unlock(&state->lock);

    ui.visible = true;
    ui.dim_background = !video_started || ui_pin_mode || mode == PROBE_ERROR;
    snprintf(ui.title, sizeof(ui.title), "NSTEAMLINK");

    int line = 0;
    if (!auth_loaded || mode == PROBE_ERROR) {
        ui_set_line(&ui, &line, "STATUS: %s", status[0] ? status : "ERROR");
        ui_set_line(&ui, &line, "RUN M2 PAIRING IF AUTH.BIN IS MISSING");
        ui_set_line(&ui, &line, "L3+R3+VOL+ EXIT");
        stream_media_set_ui(&ui);
        return;
    }

    if (ui_notice[0] != '\0') {
        ui_set_line(&ui, &line, "%s", ui_notice);
    }

    if (ui_pin_mode) {
        char decorated[32] = "";
        int off = 0;
        for (int i = 0; i < 4; i++) {
            off += snprintf(decorated + off, sizeof(decorated) - (size_t)off,
                            i == ui_pin_cursor ? "[%c]" : " %c ",
                            ui_pin[i] ? ui_pin[i] : '0');
        }
        ui_set_line(&ui, &line, "HOST PIN REQUIRED");
        ui_set_line(&ui, &line, "PIN: %s", decorated);
        ui_set_line(&ui, &line, "LEFT/RIGHT MOVE  UP/DOWN EDIT");
        ui_set_line(&ui, &line, "A SUBMIT  B CANCEL");
        ui_set_line(&ui, &line, "L3+R3+VOL+ EXIT");
        stream_media_set_ui(&ui);
        return;
    }

    if (session_active || video_started) {
        ui_set_line(&ui, &line, "STREAMING: %s", ui_desktop ? "DESKTOP" : "GAME");
        ui_set_line(&ui, &line, "FRAMES %u  DISPLAYED %u  DROP %u", frames, displayed,
                    dropped);
        ui_set_line(&ui, &line, "GAPS %u  MAX %u  DECODER %s", gaps, max_gap,
                    decoder[0] ? decoder : "-");
        ui_set_line(&ui, &line, "AUDIO %s  Q %u  ERR %u",
                    media.audio_active ? "ON" : "WAIT",
                    media.audio_queued_bytes, media.audio_decode_errors);
        ui_set_line(&ui, &line, "LAT FRAME %u/%u MS  HID %u US",
                    (uint32_t)(avg_u64(media.frame_e2e_us_total, media.frame_e2e_samples) / 1000U),
                    media.frame_e2e_us_max / 1000U,
                    (uint32_t)avg_u64(media.hid_send_us_total, media.hid_send_samples));
        ui_set_line(&ui, &line, "STATUS: %s", status[0] ? status : "-");
        ui_set_line(&ui, &line, "L3+R3+VOL- STOP  L3+R3+VOL+ EXIT");
        stream_media_set_ui(&ui);
        return;
    }

    char *ip = have_host ? IHS_IPAddressToString(&host.address.ip) : NULL;
    if (have_host) {
        ui_set_line(&ui, &line, "HOST %d/%d: %s", selected_host + 1, host_count,
                    host.hostname);
        ui_set_line(&ui, &line, "IP %s  GAMES %d", ip ? ip : "-", (int)host.gamesRunning);
    } else {
        ui_set_line(&ui, &line, "NO STEAM HOST FOUND");
        ui_set_line(&ui, &line, "PRESS Y TO DISCOVER");
    }
    free(ip);

    ui_set_line(&ui, &line, "MODE: %s", ui_desktop ? "DESKTOP" : "GAME");
    ui_set_line(&ui, &line, "A START  X MODE  Y REFRESH");
    ui_set_line(&ui, &line, "UP/DOWN HOST  B STOP");
    ui_set_line(&ui, &line, "L3+R3+VOL- STOP  L3+R3+VOL+ EXIT");
    ui_set_line(&ui, &line, "STATUS: %s", status[0] ? status : stream_result_name(stream_result));
    stream_media_set_ui(&ui);
}

static bool ascii_ieq(const char *a, const char *b) {
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static char *trim_ascii(char *s) {
    while (isspace((unsigned char)*s)) {
        s++;
    }
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return s;
}

static bool parse_button(const char *name, u64 *button) {
    if (ascii_ieq(name, "A")) {
        *button = HidNpadButton_A;
    } else if (ascii_ieq(name, "B")) {
        *button = HidNpadButton_B;
    } else if (ascii_ieq(name, "X")) {
        *button = HidNpadButton_X;
    } else if (ascii_ieq(name, "Y")) {
        *button = HidNpadButton_Y;
    } else if (ascii_ieq(name, "PLUS") || ascii_ieq(name, "+")) {
        *button = HidNpadButton_Plus;
    } else if (ascii_ieq(name, "MINUS") || ascii_ieq(name, "-")) {
        *button = HidNpadButton_Minus;
    } else if (ascii_ieq(name, "MINUS+B") || ascii_ieq(name, "-+B")) {
        *button = HidNpadButton_Minus | HidNpadButton_B;
    } else if (ascii_ieq(name, "MINUS+PLUS") || ascii_ieq(name, "-++")) {
        *button = HidNpadButton_Minus | HidNpadButton_Plus;
    } else if (ascii_ieq(name, "UP")) {
        *button = HidNpadButton_Up;
    } else if (ascii_ieq(name, "DOWN")) {
        *button = HidNpadButton_Down;
    } else if (ascii_ieq(name, "LEFT")) {
        *button = HidNpadButton_Left;
    } else if (ascii_ieq(name, "RIGHT")) {
        *button = HidNpadButton_Right;
    } else {
        return false;
    }
    return true;
}

static bool parse_u32_arg(const char *s, uint32_t min_value, uint32_t max_value,
                          uint32_t *out) {
    if (s == NULL || *s == '\0') {
        return false;
    }
    char *end = NULL;
    unsigned long value = strtoul(s, &end, 10);
    if (end == s || *end != '\0' || value < min_value || value > max_value) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static bool parse_stream_args(const char *arg, bool *desktop, bool *hold,
                              uint32_t *auto_stop_frames, char pin[16], char *err,
                              size_t err_len) {
    char tmp[96];
    *desktop = true;
    *hold = false;
    *auto_stop_frames = PROBE_AUTO_STOP_FRAMES;
    pin[0] = '\0';

    strncpy(tmp, arg ? arg : "", sizeof(tmp));
    tmp[sizeof(tmp) - 1] = '\0';
    char *saveptr = NULL;
    for (char *tok = strtok_r(tmp, " \t\r\n", &saveptr); tok != NULL;
         tok = strtok_r(NULL, " \t\r\n", &saveptr)) {
        if (ascii_ieq(tok, "desktop")) {
            *desktop = true;
        } else if (ascii_ieq(tok, "game") || ascii_ieq(tok, "bigpicture")) {
            *desktop = false;
        } else if (ascii_ieq(tok, "hold")) {
            *hold = true;
            *auto_stop_frames = 0;
        } else if (ascii_ieq(tok, "auto") || ascii_ieq(tok, "once")) {
            *hold = false;
            *auto_stop_frames = PROBE_SHORT_STOP_FRAMES;
        } else if (ascii_ieq(tok, "short")) {
            *hold = false;
            *auto_stop_frames = PROBE_SHORT_STOP_FRAMES;
        } else if (ascii_ieq(tok, "long")) {
            *hold = false;
            *auto_stop_frames = PROBE_LONG_STOP_FRAMES;
        } else if (strncasecmp(tok, "frames=", 7) == 0 || strncasecmp(tok, "f=", 2) == 0) {
            uint32_t value = 0;
            const char *value_s = strchr(tok, '=') + 1;
            if (!parse_u32_arg(value_s, 1, 60U * 60U * 30U, &value)) {
                snprintf(err, err_len, "bad frames value: %s", tok);
                return false;
            }
            *hold = false;
            *auto_stop_frames = value;
        } else if (strncasecmp(tok, "seconds=", 8) == 0 ||
                   strncasecmp(tok, "sec=", 4) == 0 ||
                   strncasecmp(tok, "s=", 2) == 0) {
            uint32_t seconds = 0;
            const char *value_s = strchr(tok, '=') + 1;
            if (!parse_u32_arg(value_s, 1, 30U * 60U, &seconds)) {
                snprintf(err, err_len, "bad seconds value: %s", tok);
                return false;
            }
            *hold = false;
            *auto_stop_frames = seconds * PROBE_FPS;
        } else if (strlen(tok) < 16) {
            strncpy(pin, tok, 15);
            pin[15] = '\0';
        } else {
            snprintf(err, err_len, "bad stream arg: %s", tok);
            return false;
        }
    }
    return true;
}

static void debug_reply(debug_server *dbg, const struct sockaddr_in *peer, const char *fmt, ...) {
    char out[DEBUG_TX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(out, sizeof(out), fmt, ap);
    va_end(ap);
    sendto(dbg->fd, out, strlen(out), 0, (const struct sockaddr *)peer, sizeof(*peer));
}

static bool debug_peer_allowed(const debug_server *dbg, const struct sockaddr_in *peer) {
    return dbg->allowed_host.s_addr == 0 || peer->sin_addr.s_addr == dbg->allowed_host.s_addr;
}

static void debug_reply_state(debug_server *dbg, const struct sockaddr_in *peer, app_state *state,
                              const char *prefix) {
    char line[DEBUG_TX - 16];
    state_line(state, line, sizeof(line));
    debug_reply(dbg, peer, "%s %s", prefix, line);
}

static void debug_reply_hosts(debug_server *dbg, const struct sockaddr_in *peer, app_state *state) {
    IHS_HostInfo hosts[MAX_HOSTS];
    int host_count;
    int selected_host;

    pthread_mutex_lock(&state->lock);
    host_count = state->host_count;
    selected_host = state->selected_host;
    for (int i = 0; i < host_count; i++) {
        hosts[i] = state->hosts[i];
    }
    pthread_mutex_unlock(&state->lock);

    char out[DEBUG_TX];
    int off = snprintf(out, sizeof(out), "OK hosts=%d selected=%d", host_count,
                       selected_host + 1);
    for (int i = 0; i < host_count && off > 0 && off < (int)sizeof(out); i++) {
        char *ip = IHS_IPAddressToString(&hosts[i].address.ip);
        off += snprintf(out + off, sizeof(out) - (size_t)off, "\n%d %s %s games=%d",
                        i + 1, hosts[i].hostname, ip ? ip : "-",
                        (int)hosts[i].gamesRunning);
        free(ip);
    }
    sendto(dbg->fd, out, strlen(out), 0, (const struct sockaddr *)peer, sizeof(*peer));
}

static bool debug_select_host(app_state *state, const char *arg, char *err, size_t err_len) {
    char *end = NULL;
    long one_based = strtol(arg, &end, 10);
    if (end == arg || *trim_ascii(end) != '\0') {
        snprintf(err, err_len, "select expects a host number");
        return false;
    }

    pthread_mutex_lock(&state->lock);
    if (one_based < 1 || one_based > state->host_count) {
        snprintf(err, err_len, "host number out of range");
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    state->selected_host = (int)one_based - 1;
    snprintf(state->status, sizeof(state->status), "Selected host %ld", one_based);
    pthread_mutex_unlock(&state->lock);
    return true;
}

static bool ensure_media_started(app_state *state, char *err, size_t err_len) {
    if (stream_media_available()) {
        update_media_snapshot(state);
        return true;
    }

    write_boot_stage("media:init:start");
    logline("media init requested");
    if (!stream_media_init(media_log)) {
        write_boot_stage("media:init:failed");
        stream_media_snapshot media;
        stream_media_get_snapshot(&media);
        pthread_mutex_lock(&state->lock);
        snprintf(state->status, sizeof(state->status), "media init failed: %s",
                 media.last_error[0] ? media.last_error : "unknown");
        pthread_mutex_unlock(&state->lock);
        snprintf(err, err_len, "media init failed: %s",
                 media.last_error[0] ? media.last_error : "unknown");
        logline("media init failed: %s", media.last_error[0] ? media.last_error : "unknown");
        update_media_snapshot(state);
        return false;
    }
    write_boot_stage("media:init:done");
    update_media_snapshot(state);
    return true;
}

static void handle_input(app_state *state, stream_runtime *runtime, u64 kdown, u64 kheld,
                         local_volume_change volume_change) {
    bool pin_mode = false;
    bool session_active = false;
    pthread_mutex_lock(&state->lock);
    pin_mode = state->ui_pin_mode;
    session_active = state->session != NULL || state->mode == PROBE_SESSION_ACTIVE ||
                     state->mode == PROBE_SESSION_CONNECTING ||
                     state->mode == PROBE_STREAM_REQUESTING ||
                     state->mode == PROBE_STREAM_READY;
    pthread_mutex_unlock(&state->lock);

    if ((kheld & LOCAL_HOTKEY_MASK) == LOCAL_HOTKEY_MASK) {
        if (volume_change == LOCAL_VOLUME_UP) {
            request_app_exit(state, "hotkey:vol_up+sticks");
            return;
        }
        if (volume_change == LOCAL_VOLUME_DOWN) {
            request_stream_stop(state, "hotkey:vol_down+sticks");
            return;
        }
    }

    if (pin_mode) {
        pthread_mutex_lock(&state->lock);
        if (kdown & HidNpadButton_B) {
            state->ui_pin_mode = false;
            snprintf(state->ui_notice, sizeof(state->ui_notice), "PIN entry canceled");
            pthread_mutex_unlock(&state->lock);
            return;
        }
        if (kdown & HidNpadButton_Left) {
            state->ui_pin_cursor = (state->ui_pin_cursor + 3) % 4;
        }
        if (kdown & HidNpadButton_Right) {
            state->ui_pin_cursor = (state->ui_pin_cursor + 1) % 4;
        }
        if (kdown & HidNpadButton_Up) {
            int pos = state->ui_pin_cursor;
            char digit = state->ui_pin[pos] >= '0' && state->ui_pin[pos] <= '9' ?
                             state->ui_pin[pos] :
                             '0';
            state->ui_pin[pos] = (char)('0' + ((digit - '0' + 1) % 10));
        }
        if (kdown & HidNpadButton_Down) {
            int pos = state->ui_pin_cursor;
            char digit = state->ui_pin[pos] >= '0' && state->ui_pin[pos] <= '9' ?
                             state->ui_pin[pos] :
                             '0';
            state->ui_pin[pos] = (char)('0' + ((digit - '0' + 9) % 10));
        }
        bool submit = (kdown & HidNpadButton_A) != 0;
        char pin[sizeof(state->ui_pin)];
        bool desktop = state->stream_desktop;
        strncpy(pin, state->ui_pin, sizeof(pin));
        pin[sizeof(pin) - 1] = '\0';
        if (submit) {
            state->ui_pin_mode = false;
            snprintf(state->ui_notice, sizeof(state->ui_notice), "Submitting PIN");
        }
        pthread_mutex_unlock(&state->lock);

        if (submit) {
            char err[160] = "";
            bool hold = NSTREAMLINK_APP ? true : false;
            uint32_t auto_stop = hold ? 0U : PROBE_AUTO_STOP_FRAMES;
            if (!prepare_stream_command(state, runtime, desktop, err, sizeof(err)) ||
                !stream_worker_enqueue(&runtime->streamer, state, desktop, hold, auto_stop,
                                       pin, err, sizeof(err))) {
                pthread_mutex_lock(&state->lock);
                snprintf(state->status, sizeof(state->status), "%s",
                         err[0] ? err : "PIN stream failed");
                snprintf(state->ui_notice, sizeof(state->ui_notice), "%s",
                         err[0] ? err : "PIN stream failed");
                pthread_mutex_unlock(&state->lock);
            }
        }
        return;
    }

    if (session_active) {
        return;
    }

    if (kdown & HidNpadButton_B) {
        request_stream_stop(state, "input:b");
        return;
    }
    if (kdown & HidNpadButton_X) {
        pthread_mutex_lock(&state->lock);
        state->ui_desktop = !state->ui_desktop;
        snprintf(state->ui_notice, sizeof(state->ui_notice), "Mode: %s",
                 state->ui_desktop ? "desktop" : "game");
        pthread_mutex_unlock(&state->lock);
        return;
    }
    if (kdown & HidNpadButton_Y) {
        char err[160] = "";
        if (!ensure_ihs_started(state, runtime, err, sizeof(err)) ||
            !send_discovery_once(state, runtime->client, err, sizeof(err))) {
            pthread_mutex_lock(&state->lock);
            snprintf(state->ui_notice, sizeof(state->ui_notice), "%s",
                     err[0] ? err : "Discovery failed");
            snprintf(state->status, sizeof(state->status), "%s",
                     err[0] ? err : "Discovery failed");
            pthread_mutex_unlock(&state->lock);
        } else {
            pthread_mutex_lock(&state->lock);
            snprintf(state->ui_notice, sizeof(state->ui_notice), "Discovery sent");
            pthread_mutex_unlock(&state->lock);
        }
        return;
    }
    if (kdown & HidNpadButton_A) {
        char err[160] = "";
        bool desktop = false;
        pthread_mutex_lock(&state->lock);
        desktop = state->ui_desktop;
        snprintf(state->ui_notice, sizeof(state->ui_notice), "Starting %s",
                 desktop ? "desktop" : "game");
        pthread_mutex_unlock(&state->lock);

        bool hold = NSTREAMLINK_APP ? true : false;
        uint32_t auto_stop = hold ? 0U : PROBE_AUTO_STOP_FRAMES;
        if (!prepare_stream_command(state, runtime, desktop, err, sizeof(err)) ||
            !stream_worker_enqueue(&runtime->streamer, state, desktop, hold, auto_stop,
                                   "", err, sizeof(err))) {
            pthread_mutex_lock(&state->lock);
            snprintf(state->ui_notice, sizeof(state->ui_notice), "%s",
                     err[0] ? err : "Stream failed");
            snprintf(state->status, sizeof(state->status), "%s",
                     err[0] ? err : "Stream failed");
            pthread_mutex_unlock(&state->lock);
        }
        return;
    }
    if (kdown & HidNpadButton_Down) {
        pthread_mutex_lock(&state->lock);
        if (state->host_count > 0) {
            state->selected_host = (state->selected_host + 1) % state->host_count;
            snprintf(state->ui_notice, sizeof(state->ui_notice), "Host selected");
        }
        pthread_mutex_unlock(&state->lock);
        return;
    }
    if (kdown & HidNpadButton_Up) {
        pthread_mutex_lock(&state->lock);
        if (state->host_count > 0) {
            state->selected_host = (state->selected_host + state->host_count - 1) %
                                   state->host_count;
            snprintf(state->ui_notice, sizeof(state->ui_notice), "Host selected");
        }
        pthread_mutex_unlock(&state->lock);
        return;
    }
}

static void debug_handle_command(debug_server *dbg, const struct sockaddr_in *peer, app_state *state,
                                 stream_runtime *runtime, char *line) {
    char *cmd = trim_ascii(line);
    char *arg = cmd;
    while (*arg != '\0' && !isspace((unsigned char)*arg)) {
        arg++;
    }
    if (*arg != '\0') {
        *arg++ = '\0';
        arg = trim_ascii(arg);
    }

    if (*cmd == '\0' || ascii_ieq(cmd, "help")) {
        debug_reply(dbg, peer,
                    "OK commands: ping state stats/perf audio hid hidlog [n] "
                    "diag [current|prev|older|status|marker [current|prev]] "
                    "diag-chunk <current|prev|older> <offset> [length] hosts select <n> "
                    "press <A|B|X|Y|MINUS|PLUS|MINUS+B|MINUS+PLUS|UP|DOWN|LEFT|RIGHT> "
                    "ihs-init discover-once media-init media-shutdown "
                    "stream [desktop|game] [short|long|frames=N|seconds=N|hold] [pin] "
                    "stream-pin <pin> stop exit");
    } else if (ascii_ieq(cmd, "ping")) {
        debug_reply(dbg, peer, "OK pong");
    } else if (ascii_ieq(cmd, "state")) {
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "stats") || ascii_ieq(cmd, "perf")) {
        char line_out[DEBUG_TX - 16];
        perf_line(state, line_out, sizeof(line_out));
        debug_reply(dbg, peer, "OK %s", line_out);
    } else if (ascii_ieq(cmd, "audio")) {
        char line_out[DEBUG_TX - 16];
        audio_line(line_out, sizeof(line_out));
        debug_reply(dbg, peer, "OK %s", line_out);
    } else if (ascii_ieq(cmd, "hid")) {
        char line_out[DEBUG_TX - 16];
        hid_line(line_out, sizeof(line_out));
        debug_reply(dbg, peer, "OK %s", line_out);
    } else if (ascii_ieq(cmd, "hidlog")) {
        uint32_t count = 16;
        if (*arg != '\0' && !parse_u32_arg(arg, 1, 60, &count)) {
            debug_reply(dbg, peer, "ERR bad hidlog count");
            return;
        }
        char line_out[DEBUG_TX - 16];
        stream_media_format_hid_history(line_out, sizeof(line_out), count);
        debug_reply(dbg, peer, "OK %s", line_out);
    } else if (ascii_ieq(cmd, "hidreports")) {
        /* Dump recently submitted HID input reports (newest first) — the
         * exact wire payload, for post-mortem of input anomalies. */
        uint32_t count = 32;
        if (*arg != '\0' && !parse_u32_arg(arg, 1, 128, &count)) {
            debug_reply(dbg, peer, "ERR bad hidreports count");
            return;
        }
        char rep_buf[DEBUG_TX];
        char *out = rep_buf;
        size_t cap = sizeof(rep_buf);
        int written = snprintf(out, cap, "OK hidreports\n");
        out += written; cap -= (size_t) written;
        size_t off = 0;
        uint64_t ms; uint16_t len; uint8_t data[96];
        while (off < count && cap > 32) {
            IHS_SessionChannelControlGetRecentHIDReports(&ms, &len, data, &off);
            if (off == (size_t) -1) {
                break;
            }
            written = snprintf(out, cap, "[%llu ms] len=%u ", (unsigned long long) ms, len);
            out += written; cap -= (size_t) written;
            for (uint16_t i = 0; i < len && cap > 4; i++) {
                written = snprintf(out, cap, "%02x", data[i]);
                out += written; cap -= (size_t) written;
            }
            written = snprintf(out, cap, "\n");
            out += written; cap -= (size_t) written;
        }
        debug_reply(dbg, peer, "%s", out == rep_buf ? "OK hidreports (none)" : rep_buf);
    } else if (ascii_ieq(cmd, "marker")) {
        logline_net("[marker] %s", arg);
        debug_reply(dbg, peer, "OK marker recorded");
    } else if (ascii_ieq(cmd, "diag-chunk")) {
        char chunk_arg_buf[DEBUG_RX];
        strncpy(chunk_arg_buf, arg, sizeof(chunk_arg_buf));
        chunk_arg_buf[sizeof(chunk_arg_buf) - 1] = '\0';
        char *saveptr = NULL;
        char *target = strtok_r(chunk_arg_buf, " \t\r\n", &saveptr);
        char *offset_s = strtok_r(NULL, " \t\r\n", &saveptr);
        char *length_s = strtok_r(NULL, " \t\r\n", &saveptr);
        char *extra = strtok_r(NULL, " \t\r\n", &saveptr);
        uint32_t offset = 0;
        uint32_t length = DIAG_CHUNK_BYTES;
        if (target == NULL || offset_s == NULL || extra != NULL ||
            !parse_u32_arg(offset_s, 0, UINT32_MAX, &offset) ||
            (length_s != NULL &&
             !parse_u32_arg(length_s, 1, DIAG_CHUNK_BYTES, &length))) {
            debug_reply(dbg, peer,
                        "ERR usage: diag-chunk <current|prev|older> <offset> [1..%u]",
                        DIAG_CHUNK_BYTES);
            return;
        }
        const char *path = NULL;
        if (ascii_ieq(target, "current") || ascii_ieq(target, "now")) {
            path = DIAG_PATH;
        } else if (ascii_ieq(target, "prev") || ascii_ieq(target, "previous") ||
                   ascii_ieq(target, "last")) {
            path = DIAG_PREV_PATH;
        } else if (ascii_ieq(target, "older") || ascii_ieq(target, "prev2")) {
            path = DIAG_OLDER_PATH;
        } else {
            debug_reply(dbg, peer, "ERR bad diag chunk target");
            return;
        }
        char line_out[DEBUG_TX - 160];
        uint32_t file_size = 0;
        uint32_t next_offset = offset;
        bool eof = true;
        if (!read_text_chunk(path, offset, length, line_out, sizeof(line_out),
                             &file_size, &next_offset, &eof)) {
            debug_reply(dbg, peer, "ERR cannot read %s at offset=%u", path, offset);
            return;
        }
        debug_reply(dbg, peer, "OK %s offset=%u next=%u size=%u eof=%d\n%s",
                    path, offset, next_offset, file_size, eof ? 1 : 0, line_out);
    } else if (ascii_ieq(cmd, "diag") || ascii_ieq(cmd, "diag-tail")) {
        char diag_arg_buf[DEBUG_RX];
        strncpy(diag_arg_buf, arg, sizeof(diag_arg_buf));
        diag_arg_buf[sizeof(diag_arg_buf) - 1] = '\0';
        char *diag_arg = trim_ascii(diag_arg_buf);
        char *diag_rest = diag_arg;
        while (*diag_rest != '\0' && !isspace((unsigned char)*diag_rest)) {
            diag_rest++;
        }
        if (*diag_rest != '\0') {
            *diag_rest++ = '\0';
            diag_rest = trim_ascii(diag_rest);
        }
        if (ascii_ieq(diag_arg, "status")) {
            char status_out[DEBUG_TX - 16];
            diag_status_line(status_out, sizeof(status_out));
            debug_reply(dbg, peer, "OK %s", status_out);
            return;
        }
        if (ascii_ieq(diag_arg, "marker") || ascii_ieq(diag_arg, "markers") ||
            ascii_ieq(diag_arg, "minus")) {
            bool previous = ascii_ieq(diag_rest, "prev") ||
                            ascii_ieq(diag_rest, "previous") ||
                            ascii_ieq(diag_rest, "last");
            bool current = *diag_rest == '\0' || ascii_ieq(diag_rest, "current") ||
                           ascii_ieq(diag_rest, "now");
            if (!previous && !current) {
                debug_reply(dbg, peer, "ERR bad diag marker target");
                return;
            }
            const char *path = previous ? DIAG_MARKER_PREV_PATH : DIAG_MARKER_PATH;
            char line_out[DEBUG_TX - 64];
            if (current && diag_marker_recent_copy(line_out, sizeof(line_out))) {
                debug_reply(dbg, peer, "OK current-marker %s\n%s", path, line_out);
                return;
            }
            if (!read_text_tail(path, line_out, sizeof(line_out))) {
                debug_reply(dbg, peer, "OK %s\n(no marker)", path);
                return;
            }
            debug_reply(dbg, peer, "OK %s\n%s", path, line_out);
            return;
        }
        bool previous = ascii_ieq(diag_arg, "prev") || ascii_ieq(diag_arg, "previous") ||
                        ascii_ieq(diag_arg, "last");
        bool older = ascii_ieq(diag_arg, "older") || ascii_ieq(diag_arg, "prev2");
        bool current = *diag_arg == '\0' || ascii_ieq(diag_arg, "current") ||
                       ascii_ieq(diag_arg, "now");
        if (!previous && !older && !current) {
            debug_reply(dbg, peer, "ERR bad diag target");
            return;
        }
        const char *path = older ? DIAG_OLDER_PATH :
                           (previous ? DIAG_PREV_PATH : DIAG_PATH);
        char line_out[DEBUG_TX - 64];
        if (current && diag_recent_copy(line_out, sizeof(line_out))) {
            debug_reply(dbg, peer, "OK current-memory %s\n%s", path, line_out);
            return;
        }
        if (!read_text_tail(path, line_out, sizeof(line_out))) {
            debug_reply(dbg, peer, "ERR no diag log at %s", path);
            return;
        }
        debug_reply(dbg, peer, "OK %s\n%s", path, line_out);
    } else if (ascii_ieq(cmd, "hosts")) {
        debug_reply_hosts(dbg, peer, state);
    } else if (ascii_ieq(cmd, "ihs-init")) {
        char err[128];
        if (!ensure_ihs_started(state, runtime, err, sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "discover") || ascii_ieq(cmd, "discover-once")) {
        char err[128];
        if (!ensure_ihs_started(state, runtime, err, sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        if (!send_discovery_once(state, runtime->client, err, sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "select")) {
        char err[96];
        if (!debug_select_host(state, arg, err, sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "media-init")) {
        char err[160];
        if (!ensure_media_started(state, err, sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "media-shutdown")) {
        stream_media_shutdown();
        update_media_snapshot(state);
        pthread_mutex_lock(&state->lock);
        snprintf(state->status, sizeof(state->status), "Media shut down");
        pthread_mutex_unlock(&state->lock);
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "press")) {
        u64 button = 0;
        if (!parse_button(arg, &button)) {
            debug_reply(dbg, peer, "ERR unknown button");
            return;
        }
        handle_input(state, runtime, button, button, LOCAL_VOLUME_NONE);
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "stream") || ascii_ieq(cmd, "stream-game") ||
               ascii_ieq(cmd, "stream-desktop")) {
        bool desktop = true;
        bool hold = false;
        uint32_t auto_stop_frames = PROBE_AUTO_STOP_FRAMES;
        char pin[16];
        char err[160];
        if (ascii_ieq(cmd, "stream-game")) {
            desktop = false;
        }
        if (!parse_stream_args(arg, &desktop, &hold, &auto_stop_frames, pin, err,
                               sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        if (ascii_ieq(cmd, "stream-game")) {
            desktop = false;
        } else if (ascii_ieq(cmd, "stream-desktop")) {
            desktop = true;
        }
        if (!prepare_stream_command(state, runtime, desktop, err, sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        if (!stream_worker_enqueue(&runtime->streamer, state, desktop, hold,
                                   auto_stop_frames, pin, err, sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "stream-pin")) {
        char err[160];
        char pin[16];
        if (*arg == '\0' || strlen(arg) >= sizeof(pin)) {
            debug_reply(dbg, peer, "ERR stream-pin expects a short host PIN");
            return;
        }
        strncpy(pin, arg, sizeof(pin));
        pin[sizeof(pin) - 1] = '\0';
        if (!prepare_stream_command(state, runtime, true, err, sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        if (!stream_worker_enqueue(&runtime->streamer, state, true, false,
                                   PROBE_SHORT_STOP_FRAMES, pin, err,
                                   sizeof(err))) {
            debug_reply(dbg, peer, "ERR %s", err);
            return;
        }
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "stop")) {
        request_stream_stop(state, "debug:stop");
        debug_reply_state(dbg, peer, state, "OK");
    } else if (ascii_ieq(cmd, "exit")) {
        request_app_exit(state, "debug:exit");
        debug_reply_state(dbg, peer, state, "OK");
    } else {
        debug_reply(dbg, peer, "ERR unknown command");
    }
}

static void debug_server_init(debug_server *dbg) {
    memset(dbg, 0, sizeof(*dbg));
    dbg->fd = -1;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        logline("debug udp disabled: socket errno=%d", errno);
        return;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEBUG_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        logline("debug udp disabled: bind %d errno=%d", DEBUG_PORT, errno);
        close(fd);
        return;
    }

    dbg->fd = fd;
    dbg->allowed_host = __nxlink_host;
    if (dbg->allowed_host.s_addr != 0) {
        log_udp_open(&dbg->allowed_host);
    }
    logline("debug udp ready: port=%d allowed=%s", DEBUG_PORT,
            dbg->allowed_host.s_addr ? inet_ntoa(dbg->allowed_host) : "any");
}

static void debug_server_poll(debug_server *dbg, app_state *state, stream_runtime *runtime) {
    if (dbg->fd < 0) {
        return;
    }

    for (int i = 0; i < 8; i++) {
        char buf[DEBUG_RX];
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t n = recvfrom(dbg->fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&peer,
                             &peer_len);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                logline("debug udp recv errno=%d", errno);
            }
            return;
        }
        buf[n] = '\0';
        if (!debug_peer_allowed(dbg, &peer)) {
            continue;
        }
        if (!log_udp_ready) {
            log_udp_open(&peer.sin_addr);
        }
        debug_handle_command(dbg, &peer, state, runtime, buf);
    }
}

static void debug_server_close(debug_server *dbg) {
    if (dbg->fd >= 0) {
        close(dbg->fd);
        dbg->fd = -1;
    }
}

static void cleanup_client(IHS_Client *client) {
    if (client == NULL) {
        return;
    }
    logline("cleanup: stop discovery");
    IHS_ClientStopDiscovery(client);
    logline("cleanup: stop IHS client");
    IHS_ClientStop(client);
    logline("cleanup: join IHS client");
    IHS_ClientThreadedJoin(client);
    logline("cleanup: destroy IHS client");
    IHS_ClientDestroy(client);
}

static void read_text_summary(const char *path, char *out, size_t out_len) {
    if (out_len == 0) {
        return;
    }
    out[0] = '\0';
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return;
    }
    size_t n = fread(out, 1, out_len - 1, fp);
    fclose(fp);
    out[n] = '\0';
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)out[i];
        if (ch == '\r' || ch == '\n' || ch == '\t') {
            out[i] = ' ';
        } else if (!isprint(ch)) {
            out[i] = '?';
        }
    }
}

static void log_previous_evidence(const char *label, const char *text) {
    if (text != NULL && text[0] != '\0') {
        char local[256];
        snprintf(local, sizeof(local), "%.220s", text);
        sanitize_text_for_log(local);
        logline("previous %s: %s", label, local);
    }
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    char prev_boot_stage[256];
    char prev_exit_stage[256];
    char prev_watchdog[256];
    char prev_exception[512];
    char prev_diag[768];
    read_text_summary(BOOT_STAGE_PATH, prev_boot_stage, sizeof(prev_boot_stage));
    read_text_summary(EXIT_STAGE_PATH, prev_exit_stage, sizeof(prev_exit_stage));
    read_text_summary(WATCHDOG_PATH, prev_watchdog, sizeof(prev_watchdog));
    read_text_summary(EXCEPTION_PATH, prev_exception, sizeof(prev_exception));
    read_text_tail(DIAG_PATH, prev_diag, sizeof(prev_diag));

    write_boot_stage("main:entered");
    bool console_active = false;
    local_controls local_input;
    memset(&local_input, 0, sizeof(local_input));

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);
    write_boot_stage("pad:ready");

    app_state state;
    memset(&state, 0, sizeof(state));
    pthread_mutex_init(&state.lock, NULL);
    state.selected_host = -1;
    state.mode = PROBE_READY;
    state.stream_result = IHS_StreamingFailed;
    state.ui_desktop = false;
    state.ui_pin_cursor = 0;
    strncpy(state.ui_pin, "0000", sizeof(state.ui_pin));

    atomic_store_explicit(&watchdog_stop, false, memory_order_relaxed);
    atomic_store_explicit(&watchdog_stream_start_ms, 0, memory_order_relaxed);
    atomic_store_explicit(&watchdog_displayed_frames, 0, memory_order_relaxed);
    watchdog_beat();
    pthread_t watchdog_thread;
    bool watchdog_started = pthread_create(&watchdog_thread, NULL, watchdog_thread_main, NULL) == 0;

    if (!auth_load(&state.auth)) {
        snprintf(state.status, sizeof(state.status), "Cannot load paired auth.bin: %s", AUTH_PATH);
        state.mode = PROBE_ERROR;
    } else if (state.auth.steam_id == 0) {
        snprintf(state.status, sizeof(state.status), "auth.bin has no steamId; run M2 pairing first");
        state.mode = PROBE_ERROR;
    } else {
        state.auth_loaded = true;
        snprintf(state.status, sizeof(state.status),
                 NSTREAMLINK_APP ? "Ready" : "Passive boot ready; run discover-once when needed");
    }
    write_boot_stage(state.auth_loaded ? "auth:loaded" : "auth:error");

    logline("nsteamlink stream selftest");
    logline("watchdog active=%d mainStall=%ums noFirstFrame=%ums",
            (int)watchdog_started, WATCHDOG_MAIN_STALL_MS, WATCHDOG_STREAM_NO_FRAME_MS);
    logline("applet exit/sleep locks disabled for M3.3 safety");
    if (!watchdog_started) {
        logline("watchdog thread failed to start");
    }
    if (state.auth_loaded) {
        logline("loaded auth.bin: deviceId=0x%016" PRIx64 " steamId=%" PRIu64
                " lastHost=%s",
                state.auth.device_id, state.auth.steam_id,
                state.auth.last_hostname[0] ? state.auth.last_hostname : "-");
    } else {
        logline("auth.bin not loaded");
    }

    write_boot_stage("socket:init:start");
    if (!init_socket_for_stream()) {
        write_boot_stage("socket:init:failed");
        atomic_store_explicit(&watchdog_stop, true, memory_order_relaxed);
        if (watchdog_started) {
            pthread_join(watchdog_thread, NULL);
        }
        if (cons_fd >= 0) {
            close(cons_fd);
            cons_fd = -1;
        }
        if (console_active) {
            consoleExit(NULL);
        }
        return 1;
    }
    write_boot_stage("socket:init:done");
    write_boot_stage("nxlink:connect:start");
    nxlink_fd = nxlinkConnectToHost(false, false);
    nxlink_active = nxlink_fd >= 0;
    if (nxlink_active) {
        set_nonblocking_log_fd(nxlink_fd);
    }
    write_boot_stage(nxlink_active ? "nxlink:connect:done" : "nxlink:connect:failed");
    logline("nxlink log socket active=%d", (int)nxlink_active);
    if (socket_summary[0] != '\0') {
        logline("%s", socket_summary);
    }
    log_previous_evidence("boot_stage", prev_boot_stage);
    log_previous_evidence("exit_stage", prev_exit_stage);
    log_previous_evidence("watchdog", prev_watchdog);
    log_previous_evidence("exception", prev_exception);
    log_previous_evidence("diag_tail", prev_diag);
    local_controls_init(&local_input);
    local_controls_publish(&state, &local_input);
    write_boot_stage(local_input.audctl_ready ? "local_hotkeys:ready" :
                     "local_hotkeys:disabled");
    if (state.auth_loaded) {
        logline("loaded auth.bin: deviceId=0x%016" PRIx64 " steamId=%" PRIu64
                " lastHost=%s",
                state.auth.device_id, state.auth.steam_id,
                state.auth.last_hostname[0] ? state.auth.last_hostname : "-");
    }

    logline("media init deferred; use debug command media-init");
    write_boot_stage("media:deferred");
    update_media_snapshot(&state);

    debug_server debug;
    debug_server_init(&debug);
    write_boot_stage(debug.fd >= 0 ? "debug:ready" : "debug:disabled");
    diag_disk_start(&state);
    write_boot_stage(diag_disk_started ? "diag:ready" : "diag:disabled");

    stream_runtime runtime;
    memset(&runtime, 0, sizeof(runtime));
    runtime.client_config = (IHS_ClientConfig){
        .deviceId = state.auth.device_id,
        .secretKey = state.auth.secret_key,
        .deviceName = state.auth.device_name,
    };
    update_runtime_flags(&state, &runtime);
    logline("IHS/client/discovery deferred; use debug command discover-once");
    write_boot_stage("ihs:deferred");

    logline("watchdog active=%d mainStall=%ums noFirstFrame=%ums",
            (int)watchdog_started, WATCHDOG_MAIN_STALL_MS, WATCHDOG_STREAM_NO_FRAME_MS);
    logline("applet exit/sleep locks disabled for M3.3 safety");
    logline("stream worker deferred");
    write_boot_stage("loop:ready:passive");

    if (NSTREAMLINK_APP && state.auth_loaded) {
        char err[160] = "";
        if (!ensure_media_started(&state, err, sizeof(err))) {
            logline("app media init failed: %s", err[0] ? err : "unknown");
        } else if (!ensure_ihs_started(&state, &runtime, err, sizeof(err))) {
            logline("app IHS init failed: %s", err[0] ? err : "unknown");
        } else if (!send_discovery_once(&state, runtime.client, err, sizeof(err))) {
            logline("app discovery failed: %s", err[0] ? err : "unknown");
        } else {
            pthread_mutex_lock(&state.lock);
            snprintf(state.status, sizeof(state.status), "Ready");
            snprintf(state.ui_notice, sizeof(state.ui_notice), "Select host and press A");
            pthread_mutex_unlock(&state.lock);
        }
    }

    bool auto_stream_pending = state.auth_loaded && PROBE_AUTO_STREAM_ON_BOOT;

    write_boot_stage("loop:entered");
    for (;;) {
        bool media_was_available = stream_media_available();
        if (!appletMainLoop()) {
            request_app_exit(&state, "applet:main_loop_end");
            break;
        }

        watchdog_beat();
        padUpdate(&pad);
        u64 kdown = padGetButtonsDown(&pad);
        u64 kheld = padGetButtons(&pad);
        local_volume_change volume_change = local_controls_poll_volume(&local_input, monotonic_ms());
        local_controls_publish(&state, &local_input);
        handle_input(&state, &runtime, kdown, kheld, volume_change);
        debug_server_poll(&debug, &state, &runtime);
        if (runtime.client != NULL) {
            start_session_if_ready(&state, &runtime.client_config);
        }
        if (auto_stream_pending) {
            auto_stream_pending = false;
            char err[160] = "";
            if (prepare_stream_command(&state, &runtime, false, err, sizeof(err))) {
                if (stream_worker_enqueue(&runtime.streamer, &state, false, false,
                                          PROBE_AUTO_STOP_FRAMES, "", err, sizeof(err))) {
                    logline("auto stream queued: game autoStop=%u", PROBE_AUTO_STOP_FRAMES);
                    write_boot_stage("auto_stream:queued");
                } else {
                    logline("auto stream enqueue failed: %s", err[0] ? err : "unknown");
                    write_boot_stage("auto_stream:enqueue_failed");
                }
            } else {
                pthread_mutex_lock(&state.lock);
                snprintf(state.status, sizeof(state.status), "Auto stream failed: %s",
                         err[0] ? err : "unknown");
                pthread_mutex_unlock(&state.lock);
                logline("auto stream prepare failed: %s", err[0] ? err : "unknown");
                write_boot_stage("auto_stream:prepare_failed");
            }
        }
        if (media_was_available && stream_media_available()) {
            note_video_stall_if_needed(&state);
            update_screen_ui(&state);
            stream_media_present();
            if (stream_media_exit_requested()) {
                request_app_exit(&state, "media:exit_requested");
            }
            update_media_snapshot(&state);
        } else if (console_active) {
            console_draw(&state);
            consoleUpdate(NULL);
        }

        bool should_stop = false;
        bool should_exit = false;
        bool session_finished = false;
        pthread_mutex_lock(&state.lock);
        should_stop = state.stop_requested;
        should_exit = state.exit_requested;
        session_finished = state.session_finished;
        pthread_mutex_unlock(&state.lock);

        if (should_exit) {
            logline("exit requested");
            write_boot_stage("exit:requested");
            stream_worker_stop(&runtime.streamer);
        }
        if (should_stop || session_finished || should_exit) {
            bool auto_exit = join_destroy_session(&state, should_stop || should_exit);
            if (auto_exit) {
                logline("auto exit requested after selftest stream");
                write_boot_stage("exit:auto_stop");
                request_app_exit(&state, "selftest:auto_stop");
            }
            if (should_exit) {
                break;
            }
        }
        if (!stream_media_available()) {
            svcSleepThread(16 * 1000 * 1000);
        }
    }

    logline("main loop ended");
    write_boot_stage("loop:ended");
    char exit_reason[sizeof(state.exit_reason)];
    pthread_mutex_lock(&state.lock);
    strncpy(exit_reason, state.exit_reason, sizeof(exit_reason));
    exit_reason[sizeof(exit_reason) - 1] = '\0';
    pthread_mutex_unlock(&state.lock);
    logline("cleanup: begin reason=%s", exit_reason[0] ? exit_reason : "loop-ended");
    write_exit_stage("cleanup:begin");

    logline("cleanup: stop stream worker");
    write_exit_stage("cleanup:stream_worker_stop:start");
    stream_worker_stop(&runtime.streamer);
    write_exit_stage("cleanup:stream_worker_stop:done");

    atomic_store_explicit(&watchdog_stop, true, memory_order_relaxed);
    if (watchdog_started) {
        logline("cleanup: join watchdog");
        write_exit_stage("cleanup:watchdog_join:start");
        pthread_join(watchdog_thread, NULL);
        write_exit_stage("cleanup:watchdog_join:done");
    }

    pthread_mutex_lock(&state.lock);
    bool have_session = state.session != NULL;
    pthread_mutex_unlock(&state.lock);
    if (have_session) {
        logline("cleanup: stop active session");
        write_exit_stage("cleanup:session:start");
        join_destroy_session(&state, true);
        write_exit_stage("cleanup:session:done");
    } else {
        pthread_mutex_lock(&state.lock);
        if (state.mode == PROBE_STREAM_REQUESTING || state.mode == PROBE_STREAM_READY ||
            state.mode == PROBE_SESSION_CONNECTING || state.mode == PROBE_SESSION_STOPPING) {
            state.mode = PROBE_READY;
            state.stream_result = IHS_StreamingCanceled;
            snprintf(state.status, sizeof(state.status), "Exit canceled pending stream");
        }
        pthread_mutex_unlock(&state.lock);
        write_exit_stage("cleanup:session:skipped");
    }

    write_exit_stage("cleanup:stream_worker_join:start");
    stream_worker_join(&runtime.streamer);
    runtime.stream_worker_started = false;
    update_runtime_flags(&state, &runtime);
    write_exit_stage("cleanup:stream_worker_join:done");

    write_exit_stage("cleanup:client:start");
    cleanup_client(runtime.client);
    runtime.client = NULL;
    update_runtime_flags(&state, &runtime);
    write_exit_stage("cleanup:client:done");

    if (runtime.ihs_initialized) {
        logline("cleanup: IHS_Quit");
        write_exit_stage("cleanup:ihs_quit:start");
        IHS_Quit();
        runtime.ihs_initialized = false;
        update_runtime_flags(&state, &runtime);
        write_exit_stage("cleanup:ihs_quit:done");
    } else {
        write_exit_stage("cleanup:ihs_quit:skipped");
    }

    logline("cleanup: join diag disk");
    write_exit_stage("cleanup:diag_disk_join:start");
    diag_disk_stop_thread();
    write_exit_stage("cleanup:diag_disk_join:done");

    write_exit_stage("cleanup:media_shutdown:start");
    stream_media_shutdown();
    write_exit_stage("cleanup:media_shutdown:done");

    write_exit_stage("cleanup:debug_close:start");
    debug_server_close(&debug);
    write_exit_stage("cleanup:debug_close:done");

    write_exit_stage("cleanup:local_hotkeys:start");
    local_controls_shutdown(&local_input);
    write_exit_stage("cleanup:local_hotkeys:done");

    logline("cleanup: close nxlink log socket");
    if (nxlink_fd >= 0) {
        write_exit_stage("cleanup:nxlink_close:start");
        nxlink_log_close();
        write_exit_stage("cleanup:nxlink_close:done");
    }

    write_exit_stage("cleanup:socket_exit:start");
    socketExit();
    write_exit_stage("cleanup:socket_exit:done");

    write_exit_stage("cleanup:state_destroy:start");
    pthread_mutex_destroy(&state.lock);
    write_exit_stage("cleanup:state_destroy:done");
    write_boot_stage("cleanup:done");

    if (cons_fd >= 0) {
        close(cons_fd);
        cons_fd = -1;
    }
    if (console_active) {
        consoleExit(NULL);
    }

    return 0;
}
