/* Diagnostics-only large VCL capability stimulus. No Steam session/policy.
 * Software formula -> rendered golden -> strict NVTEGRA GPU readback.
 * Completion is DroppedReset: GPU readback does not prove physical scanout. */
#include "build_identity.h"
#include "gfx_backend.h"
#include "vcl_fixture_probe.h"
#include <SDL.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libavutil/hwcontext_nvtegra.h>
#include <malloc.h>
#include <poll.h>
#include <stdarg.h>
#include <switch.h>
#include <sys/socket.h>
#include <unistd.h>

#if !NSL_DIAGNOSTICS
#error "VCL capability probe requires diagnostics"
#endif
#define PIXELS   (1280u * 720u * 4u)
#define MAP_ROWS 32
extern const unsigned nsl_vcl_probe_limit_bytes;
extern const unsigned char nsl_vcl_pcm720[], nsl_vcl_pcm1080[];
extern const size_t nsl_vcl_pcm720_size, nsl_vcl_pcm1080_size;
static int log_fd = -1;
static char transcript[65536];
static size_t log_size, log_sent;
static bool log_overflow;
static uint64_t run_id;
static const char *stage = "startup";
static unsigned char *readback, *golden[2];

/* The SDK call is forwarded unmodified. Only fixed-size metadata is written
 * here: no allocation, logging, I/O or fixture policy on the decode path.
 * Published rows are read after submit/stop has returned, never mid-call. */
typedef struct map_row {
    atomic_bool ready;
    unsigned before, requested, after, align;
    int heap, flags, result;
} map_row;
static map_row map_rows[MAP_ROWS];
static atomic_uint map_count;
int __real_av_nvtegra_map_realloc(AVNVTegraMap *, uint32_t, uint32_t, int, int);
int __wrap_av_nvtegra_map_realloc(AVNVTegraMap *map, uint32_t size, uint32_t align, int heap,
                                  int flags) {
    unsigned n = atomic_fetch_add_explicit(&map_count, 1, memory_order_relaxed);
    unsigned before = av_nvtegra_map_get_size(map);
    int result = __real_av_nvtegra_map_realloc(map, size, align, heap, flags);
    if (n < MAP_ROWS) {
        map_row *row = &map_rows[n];
        row->before = before;
        row->requested = size;
        row->after = av_nvtegra_map_get_size(map);
        row->align = align;
        row->heap = heap;
        row->flags = flags;
        row->result = result;
        atomic_store_explicit(&row->ready, true, memory_order_release);
    }
    return result;
}
static void send_pending(void) {
    if (log_fd < 0 || log_sent == log_size)
        return;
    ssize_t n = send(log_fd, transcript + log_sent, log_size - log_sent, MSG_DONTWAIT);
    if (n > 0)
        log_sent += n;
}
static void trace(const char *format, ...) {
    char line[1024];
    int prefix = snprintf(line, sizeof(line), "[%llu %s] ", (unsigned long long)run_id, stage);
    va_list args;
    va_start(args, format);
    int count = vsnprintf(line + prefix, sizeof(line) - prefix, format, args);
    va_end(args);
    if (count < 0 || (size_t)count >= sizeof(line) - prefix - 1) {
        log_overflow = true;
        return;
    }
    size_t bytes = strlen(line);
    line[bytes++] = '\n';
    if (bytes <= sizeof(transcript) - log_size) {
        memcpy(transcript + log_size, line, bytes);
        log_size += bytes;
    } else {
        log_overflow = true;
    }
    send_pending();
}
static void enter(const char *name) {
    stage = name;
    trace("STAGE=%s", name);
}
static void diagnostic(const char *message) {
    trace("%s", message);
}
static void av_diagnostic(void *context, int level, const char *format, va_list args) {
    (void)context;
    if (level <= AV_LOG_WARNING) {
        char message[512];
        vsnprintf(message, sizeof(message), format, args);
        trace("FFmpeg: %s", message);
    }
}
static void connect_log(void) {
    if (!__nxlink_host.s_addr)
        return;
    log_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (log_fd < 0)
        return;
    bool nonblocking = fcntl(log_fd, F_SETFL, O_NONBLOCK) == 0;
    struct sockaddr_in host = {
        .sin_family = AF_INET, .sin_port = htons(NXLINK_CLIENT_PORT), .sin_addr = __nxlink_host};
    int rc = nonblocking ? connect(log_fd, (void *)&host, sizeof(host)) : -1;
    if (rc < 0 && nonblocking && errno == EINPROGRESS) {
        struct pollfd p = {.fd = log_fd, .events = POLLOUT};
        int error = 0;
        socklen_t bytes = sizeof(error);
        rc = poll(&p, 1, 2000) > 0 &&
                     getsockopt(log_fd, SOL_SOCKET, SO_ERROR, &error, &bytes) == 0 && !error
                 ? 0
                 : -1;
    }
    if (rc < 0) {
        close(log_fd);
        log_fd = -1;
    }
}
typedef struct display {
    sl_gfx *gfx;
    const vcl_spec *spec;
    unsigned pass, seen, max_diff;
} display;
static void memory_sample(const display *d, const char *name) {
    u64 used = 0;
    Result rc = svcGetInfo(&used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
    struct mallinfo heap = mallinfo();
    trace("VCL_RESOURCE {\"fixture\":\"%s\",\"pass\":%u,\"stage\":\"%s\","
          "\"heap_live_bytes\":%llu,\"process_used_bytes\":%llu,\"query_result\":%u}",
          d->spec->name, d->pass, name, (unsigned long long)heap.uordblks, (unsigned long long)used,
          rc);
}
static void observe_stage(void *context, const char *name) {
    memory_sample(context, name);
}
static bool active(void *context) {
    (void)context;
    return appletMainLoop();
}
static bool drain(sl_gfx *gfx) {
    uint64_t before = vcl_now();
    for (;;) {
        sl_gfx_result result = sl_gfx_poll_drain(gfx);
        if (result == SL_GFX_READY)
            return true;
        if (result != SL_GFX_BUSY || !appletMainLoop() || vcl_now() - before > 5000000)
            return false;
        svcSleepThread(1000000);
    }
}
static bool picture(void *context, sl_video_selection *selected, unsigned index) {
    display *d = context;
    uint64_t start = vcl_now();
    while (appletGetFocusState() != AppletFocusState_InFocus) {
        if (!appletMainLoop() || vcl_now() - start > 5000000)
            return false;
        sl_gfx_collect(d->gfx);
        svcSleepThread(1000000);
    }
    if (index >= 2 || !drain(d->gfx) || sl_gfx_begin(d->gfx) != SL_GFX_READY)
        return false;
    sl_gfx_draw_color(d->gfx, 0, 0, 0, 255);
    sl_gfx_clear(d->gfx);
    bool rendered = sl_gfx_video(d->gfx, selected->frame);
    sl_gfx_present_result result = sl_gfx_present(d->gfx);
    if (!rendered || result.result != SL_GFX_READY || !drain(d->gfx) ||
        !sl_gfx_readback(d->gfx, NULL, readback, PIXELS, 1280 * 4))
        return false;
    if (!d->pass) {
        memcpy(golden[index], readback, PIXELS);
    } else {
        for (size_t n = 0; n < PIXELS; ++n) {
            unsigned diff = abs((int)golden[index][n] - (int)readback[n]);
            if (diff > d->max_diff)
                d->max_diff = diff;
        }
        if (d->max_diff > 3)
            return false;
    }
    ++d->seen;
    return true;
}
static bool map_report(const display *d, unsigned first) {
    unsigned count = atomic_load_explicit(&map_count, memory_order_relaxed);
    bool ok = count <= MAP_ROWS;
    for (unsigned n = first; n < count && n < MAP_ROWS; ++n) {
        map_row *r = &map_rows[n];
        if (!atomic_load_explicit(&r->ready, memory_order_acquire)) {
            ok = false;
            continue;
        }
        trace("VCL_MAP {\"fixture\":\"%s\",\"pass\":%u,\"index\":%u,\"before\":%u,"
              "\"requested\":%u,\"after\":%u,\"align\":%u,\"heap\":%d,\"flags\":%d,\"result\":%d}",
              d->spec->name, d->pass, n, r->before, r->requested, r->after, r->align, r->heap,
              r->flags, r->result);
        ok &= r->result == 0 && r->after >= r->requested;
    }
    /* Require a successful growth large enough for the actual VCL. This is an
     * observed SDK input-map request, not the whole process allocation peak. */
    if (d->pass) {
        bool grew = false;
        for (unsigned n = first; n < count && n < MAP_ROWS; ++n) {
            map_row *r = &map_rows[n];
            if (atomic_load_explicit(&r->ready, memory_order_acquire))
                grew |=
                    r->result == 0 && r->requested > r->before && r->after >= d->spec->vcl_bytes;
        }
        ok &= grew;
    }
    return ok;
}
static bool run_case(unsigned number, const unsigned char *data, size_t size) {
    const vcl_spec *s = &vcl_specs[number];
    sl_video_pipeline *pipeline = NULL;
    sl_gfx *gfx = NULL;
    bool ok = false;
    const char *failure = "create";
    enter("case-create");
    pipeline = sl_video_create();
    gfx = sl_gfx_create(&(sl_gfx_config){.width = 1280,
                                         .height = 720,
                                         .title = "VCL capability probe",
                                         .diagnostic = diagnostic,
                                         .output_height = 720});
    if (!pipeline || !gfx || !sl_gfx_request_readback(gfx))
        goto cleanup;
    for (unsigned pass = 0; pass < 2; ++pass) {
        enter(pass ? "hardware-vcl" : "software-vcl");
        display d = {.gfx = gfx, .spec = s, .pass = pass};
        vcl_callbacks cb = {
            .picture = picture, .stage = observe_stage, .active = active, .context = &d};
        sl_gfx_counters before, after;
        sl_gfx_get_counters(gfx, &before);
        unsigned first_map = atomic_load_explicit(&map_count, memory_order_relaxed);
        vcl_result r;
        bool passed = vcl_run(pipeline, (sl_video_key){100 + 2 * number + pass, 1}, s, data, size,
                              pass != 0, false, &cb, &r);
        sl_gfx_get_counters(gfx, &after);
        bool zero_copy = pass && after.uploads == before.uploads &&
                         after.downloads == before.downloads && after.imports > before.imports;
        bool maps_ok = map_report(&d, first_map);
        if (passed && !maps_ok) {
            passed = false;
            r.failure = "map-growth";
        }
        if (passed && pass && !zero_copy) {
            passed = false;
            r.failure = "hardware-copy";
        }
        passed &= r.pictures == 2 && d.seen == 2 && r.stopped;
        for (unsigned n = 0; n < r.inputs; ++n)
            trace("VCL_ROW {\"fixture\":\"%s\",\"pass\":%u,\"input\":%u,\"bytes\":%u,"
                  "\"status\":%u,\"taken\":%s,\"task\":%u,\"pixel\":%u,\"submit_us\":%llu}",
                  s->name, pass, n + 1, r.rows[n].bytes, r.rows[n].status,
                  r.rows[n].taken ? "true" : "false", r.rows[n].task, r.rows[n].pixel,
                  (unsigned long long)r.rows[n].submit_us);
        trace("VCL_CASE {\"fixture\":\"%s\",\"pass\":%u,\"width\":%u,\"height\":%u,"
              "\"key_bytes\":%u,\"vcl_bytes\":%u,\"sha256\":\"%s\",\"hardware_requested\":%s,"
              "\"hardware_context\":%s,\"zero_copy\":%s,\"inputs\":%u,\"pictures\":%u,"
              "\"stopped\":%s,\"passed\":%s,\"max_diff\":%u,\"failure\":\"%s\"}",
              s->name, pass, s->width, s->height, s->key_bytes, s->vcl_bytes, s->sha256,
              pass ? "true" : "false", r.hardware_context ? "true" : "false",
              zero_copy ? "true" : "false", r.inputs, r.pictures, r.stopped ? "true" : "false",
              passed ? "true" : "false", d.max_diff, r.failure);
        if (!passed) {
            failure = r.failure;
            goto cleanup;
        }
        sl_gfx_forget_video(gfx);
        if (!drain(gfx)) {
            failure = "pass-drain";
            goto cleanup;
        }
        sl_video_reap(pipeline);
    }
    ok = true;
cleanup:
    enter("case-gfx-finish");
    if (gfx) {
        sl_gfx_finish(gfx);
        sl_gfx_counters counters;
        sl_gfx_get_counters(gfx, &counters);
        if (counters.imported_bytes || counters.pool_groups || counters.busy_batches ||
            counters.maps) {
            ok = false;
            failure = "gfx-resources";
        }
        trace("VCL_DRAIN {\"fixture\":\"%s\",\"imported_bytes\":%zu,\"pool_groups\":%u,"
              "\"busy_batches\":%u,\"maps\":%u}",
              s->name, counters.imported_bytes, counters.pool_groups, counters.busy_batches,
              counters.maps);
        sl_gfx_destroy(gfx);
    }
    enter("case-decoder-destroy");
    if (pipeline) {
        sl_video_reap(pipeline);
        if (!sl_video_destroy(pipeline)) {
            trace("VCL_FATAL live-decoder-domain");
            abort(); /* Do not return a dirty ABI to the loader. */
        }
    }
    display d = {.spec = s, .pass = 2};
    memory_sample(&d, "destroyed");
    trace("VCL_CLEANUP {\"fixture\":\"%s\",\"passed\":%s,\"failure\":\"%s\"}", s->name,
          ok ? "true" : "false", ok ? "none" : failure);
    return ok;
}
int main(void) {
    run_id = armGetSystemTick();
    bool sockets = R_SUCCEEDED(socketInitializeDefault()), sdl = false, ok = false;
    if (sockets)
        connect_log();
    trace("VCL_BEGIN build=%s limit=%u fixtures=2 sockets=%d transport=%d", NSL_GIT_COMMIT,
          nsl_vcl_probe_limit_bytes, sockets, log_fd >= 0);
    av_log_set_callback(av_diagnostic);
    enter("buffers");
    readback = malloc(PIXELS);
    for (unsigned n = 0; n < 2; ++n)
        golden[n] = malloc(PIXELS);
    if (!readback || !golden[0] || !golden[1] || nsl_vcl_probe_limit_bytes != 4194304)
        goto cleanup;
    enter("sdl-init");
    if (SDL_Init(SDL_INIT_AUDIO | SDL_INIT_GAMECONTROLLER))
        goto cleanup;
    sdl = true;
    if (SDL_WasInit(SDL_INIT_VIDEO))
        goto cleanup;
    ok = run_case(0, nsl_vcl_pcm720, nsl_vcl_pcm720_size) &&
         run_case(1, nsl_vcl_pcm1080, nsl_vcl_pcm1080_size);
cleanup:
    enter("cleanup-sdl");
    if (sdl)
        SDL_Quit();
    free(readback);
    for (unsigned n = 0; n < 2; ++n)
        free(golden[n]);
    av_log_set_callback(av_log_default_callback);
    ok &= !log_overflow;
    enter("complete");
    trace("VCL_FINAL result=%s overflow=%d", ok ? "PASS" : "FAIL", log_overflow);
    trace("VCL_TRANSPORT closing");
    FILE *saved = fopen("sdmc:/switch/nsteamlink-vcl-probe.log", "w");
    if (saved) {
        fwrite(transcript, 1, log_size, saved);
        fclose(saved);
    }
    uint64_t deadline = vcl_now() + 2000000;
    while (log_fd >= 0 && log_sent < log_size && vcl_now() < deadline) {
        send_pending();
        svcSleepThread(1000000);
    }
    if (log_fd >= 0)
        close(log_fd);
    if (sockets)
        socketExit();
    return ok ? 0 : 1;
}
