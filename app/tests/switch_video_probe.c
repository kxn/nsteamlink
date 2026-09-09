/* Self-contained G1 diagnostic. No Steam session/authentication dependency. */
#include "build_identity.h"
#include "gfx_backend.h"
#include "session/frame_tracker.h"
#include <SDL.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libavcodec/avcodec.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <switch.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PIXELS (1280u * 720u * 4u)
#define FRAMES 16
static unsigned char *golden[FRAMES], *readback;
static uint16_t golden_id[FRAMES];
static unsigned golden_count;
static int log_fd = -1;
static char transcript[128 * 1024];
static size_t transcript_size, transmitted;
static const char *stage = "startup";
static uint64_t run_id;
#define EMBED(name)                                                                                \
    extern const unsigned char nsl_probe_##name[];                                                 \
    extern const size_t nsl_probe_##name##_size
EMBED(padding720);
EMBED(padding1080);
EMBED(sequential);
EMBED(reordered);
static void send_pending(void) {
    if (log_fd < 0 || transmitted == transcript_size)
        return;
    ssize_t n = send(log_fd, transcript + transmitted, transcript_size - transmitted, MSG_DONTWAIT);
    if (n > 0)
        transmitted += (size_t)n;
}
static void trace(const char *format, ...) {
    char line[1024];
    int prefix = snprintf(line, sizeof(line), "[%llu %s] ", (unsigned long long)run_id, stage);
    va_list args;
    va_start(args, format);
    vsnprintf(line + prefix, sizeof(line) - prefix, format, args);
    va_end(args);
    size_t n = strlen(line);
    if (n && line[n - 1] != '\n' && n < sizeof(line) - 1)
        line[n++] = '\n';
    if (n <= sizeof(transcript) - transcript_size) {
        memcpy(transcript + transcript_size, line, n);
        transcript_size += n;
    }
    send_pending();
}
static void enter(const char *name) {
    stage = name;
    trace("STAGE=%s", stage);
}
static void diagnostic(const char *message) {
    trace("%s", message);
}
static void av_diagnostic(void *context, int level, const char *format, va_list args) {
    (void)context;
    if (level > AV_LOG_WARNING)
        return;
    char text[512];
    vsnprintf(text, sizeof(text), format, args);
    trace("FFmpeg: %s", text);
}
static void connect_log(void) {
    if (!__nxlink_host.s_addr)
        return;
    log_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (log_fd < 0)
        return;
    fcntl(log_fd, F_SETFL, O_NONBLOCK);
    struct sockaddr_in host = {
        .sin_family = AF_INET, .sin_port = htons(NXLINK_CLIENT_PORT), .sin_addr = __nxlink_host};
    int rc = connect(log_fd, (void *)&host, sizeof(host));
    if (rc < 0 && errno == EINPROGRESS) {
        struct pollfd p = {.fd = log_fd, .events = POLLOUT};
        int error = 0;
        socklen_t length = sizeof(error);
        rc = poll(&p, 1, 2000) > 0 &&
                     getsockopt(log_fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && !error
                 ? 0
                 : -1;
    }
    if (rc < 0) {
        close(log_fd);
        log_fd = -1;
    }
}
static uint64_t now_us(void) {
    return armTicksToNs(armGetSystemTick()) / 1000;
}
static bool running(void) {
    return appletMainLoop();
}
static bool drain(sl_gfx *gfx) {
    uint64_t start = now_us();
    for (;;) {
        sl_gfx_result result = sl_gfx_poll_drain(gfx);
        if (result == SL_GFX_READY)
            return true;
        if (result != SL_GFX_BUSY || !running() || now_us() - start > 5000000)
            return false;
        svcSleepThread(1000000);
    }
}
static bool draw(sl_gfx *gfx, sl_video_frame *frame) {
    while (appletGetFocusState() != AppletFocusState_InFocus) {
        if (!running())
            return false;
        sl_gfx_collect(gfx);
        svcSleepThread(1000000);
    }
    if (!drain(gfx) || sl_gfx_begin(gfx) != SL_GFX_READY)
        return false;
    sl_gfx_draw_color(gfx, 0, 0, 0, 255);
    sl_gfx_clear(gfx);
    bool ok = sl_gfx_video(gfx, frame);
    sl_gfx_present_result result = sl_gfx_present(gfx);
    return ok && result.result == SL_GFX_READY && drain(gfx) &&
           sl_gfx_readback(gfx, NULL, readback, PIXELS, 1280 * 4);
}
static bool near_pixel(unsigned x, unsigned y, unsigned r, unsigned g, unsigned b) {
    const unsigned char *p = readback + ((size_t)y * 1280 + x) * 4;
    trace("pixel x=%u y=%u rgba=%u,%u,%u,%u expected=%u,%u,%u,255", x, y, p[0], p[1], p[2], p[3], r,
          g, b);
    return abs((int)p[0] - (int)r) <= 2 && abs((int)p[1] - (int)g) <= 2 &&
           abs((int)p[2] - (int)b) <= 2 && p[3] == 255;
}
static bool ui_oracle(sl_gfx *gfx) {
    enter("ui-create-rgba");
    sl_gfx_texture *rgba = sl_gfx_create_texture(gfx, SL_GFX_RGBA8, SL_GFX_STATIC, 1, 1);
    enter("ui-create-glyph");
    sl_gfx_texture *glyph = sl_gfx_create_texture(gfx, SL_GFX_R8, SL_GFX_STATIC, 64, 64);
    enter("ui-create-target");
    sl_gfx_texture *target = sl_gfx_create_texture(gfx, SL_GFX_RGBA8, SL_GFX_TARGET, 64, 64);
    bool ok = false;
    unsigned char red[4] = {255, 0, 0, 128}, alpha[64 * 64];
    memset(alpha, 128, sizeof(alpha));
    enter("ui-upload");
    if (!rgba || !glyph || !target || sl_gfx_upload(rgba, NULL, red, 4) ||
        sl_gfx_upload(glyph, NULL, alpha, 64))
        goto cleanup;
    sl_gfx_texture_blend(rgba, SL_GFX_BLEND_ALPHA);
    sl_gfx_texture_blend(glyph, SL_GFX_BLEND_ALPHA);
    sl_gfx_texture_blend(target, SL_GFX_BLEND_ALPHA);
    sl_gfx_texture_alpha(target, 128);
    enter("ui-begin");
    if (sl_gfx_begin(gfx) != SL_GFX_READY)
        goto cleanup;
    enter("ui-bind-target");
    sl_gfx_target(gfx, target);
    sl_gfx_draw_color(gfx, 0, 0, 0, 0);
    enter("ui-clear-target");
    sl_gfx_clear(gfx);
    enter("ui-draw-rgba");
    sl_gfx_copy(gfx, rgba, NULL, &(sl_gfx_rect){0, 0, 64, 64});
    enter("ui-bind-output");
    sl_gfx_target(gfx, NULL);
    sl_gfx_draw_color(gfx, 0, 0, 0, 255);
    enter("ui-clear-output");
    sl_gfx_clear(gfx);
    enter("ui-draw-target");
    sl_gfx_copy(gfx, target, NULL, &(sl_gfx_rect){0, 0, 64, 64});
    enter("ui-draw-glyph");
    sl_gfx_copy(gfx, glyph, NULL, &(sl_gfx_rect){64, 0, 64, 64});
    sl_gfx_draw_color(gfx, 0, 255, 0, 255);
    enter("ui-draw-solid");
    sl_gfx_fill(gfx, &(sl_gfx_rect){0, 128, 16, 16});
    enter("ui-submit");
    sl_gfx_present(gfx);
    enter("ui-release-handles");
    /* Destroy logical handles before the fence: concrete versions stay pinned. */
    sl_gfx_destroy_texture(rgba);
    rgba = NULL;
    sl_gfx_destroy_texture(glyph);
    glyph = NULL;
    sl_gfx_destroy_texture(target);
    target = NULL;
    enter("ui-drain-readback");
    ok = drain(gfx) && sl_gfx_readback(gfx, NULL, readback, PIXELS, 1280 * 4) &&
         (near_pixel(16, 16, 64, 0, 0) & near_pixel(80, 16, 128, 128, 128) &
          near_pixel(8, 136, 0, 255, 0) & near_pixel(8, 583, 0, 0, 0));
cleanup:
    sl_gfx_destroy_texture(rgba);
    sl_gfx_destroy_texture(glyph);
    sl_gfx_destroy_texture(target);
    trace("UI alpha/atlas/origin/lifetime=%s\n", ok ? "PASS" : "FAIL");
    return ok;
}
static bool compare(sl_video_frame *frame, bool hardware, unsigned index) {
    uint16_t id = IHS_FrameTicketIdentity(frame->ticket).frameId;
    if (index >= FRAMES)
        return false;
    if (!hardware) {
        golden[index] = malloc(PIXELS);
        if (!golden[index])
            return false;
        memcpy(golden[index], readback, PIXELS);
        golden_id[index] = id;
        golden_count = index + 1;
        return true;
    }
    if (index >= golden_count || id != golden_id[index])
        return false;
    unsigned max_delta = 0;
    size_t differing = 0;
    for (size_t i = 0; i < PIXELS; ++i) {
        unsigned delta = abs((int)readback[i] - golden[index][i]);
        if (delta > max_delta)
            max_delta = delta;
        differing += delta > 3;
    }
    trace("frame=%u ticket=%u max_delta=%u outside_tolerance=%zu\n", index, id, max_delta,
          differing);
    /* Both paths use the same shader; allow only normalized-coordinate rounding. */
    return differing == 0;
}
static bool take(sl_video_pipeline *pipeline, sl_gfx *gfx, bool hardware, sl_video_frame **held,
                 unsigned *outputs) {
    sl_video_frame *frame = sl_video_take(pipeline);
    if (!frame)
        return true;
    bool ok = draw(gfx, frame);
    if (!ok)
        trace("draw rejected format=%d size=%dx%d pitch=%d,%d crop=%zu,%zu,%zu,%zu",
              frame->pixels->format, frame->pixels->width, frame->pixels->height,
              frame->pixels->linesize[0], frame->pixels->linesize[1], frame->pixels->crop_left,
              frame->pixels->crop_top, frame->pixels->crop_right, frame->pixels->crop_bottom);
    if (ok)
        ok = compare(frame, hardware, (*outputs)++);
    IHS_FrameOutcome outcome = {.result = ok ? IHS_VideoFrameResultDisplayed
                                             : IHS_VideoFrameResultDroppedReset,
                                .completionUs = now_us(),
                                .presentationSerial = ok ? *outputs : 0};
    sl_video_frame_complete(frame, &outcome);
    if (*held)
        sl_resource_release(&(*held)->ref);
    *held = frame;
    return ok;
}
static bool packet(sl_video_pipeline *pipeline, sl_gfx *gfx, IHS_FrameTracker *tracker,
                   sl_video_key key, bool hardware, const uint8_t *data, int bytes,
                   unsigned *packets, unsigned *outputs, sl_video_frame **held) {
    IHS_FrameReceive receive = {.firstReceiveUs = now_us(), .lastReceiveUs = now_us()};
    IHS_FrameTicket *ticket = NULL;
    if (IHS_FrameTrackerBegin(tracker, key.epoch, ++*packets, &receive, &ticket) !=
        IHS_FrameBeginOK)
        return false;
    bool taken = false, ok = sl_video_submit(pipeline, key, data, bytes, ticket, &taken);
    IHS_FrameTicketRelease(ticket);
    return ok && taken && take(pipeline, gfx, hardware, held, outputs);
}
static bool replay(sl_video_pipeline *pipeline, sl_gfx *gfx, const uint8_t *data, int size,
                   sl_video_key key, bool hardware, sl_video_frame **held) {
    IHS_FrameTracker *tracker = IHS_FrameTrackerCreate(key.session);
    AVCodecParserContext *parser = av_parser_init(AV_CODEC_ID_H264);
    AVCodecContext *parser_context = avcodec_alloc_context3(NULL);
    bool ok = false;
    unsigned packets = 0, outputs = 0;
    sl_gfx_counters before;
    sl_gfx_get_counters(gfx, &before);
    /* The decoder updates dimensions from the fixture SPS. Admission max is 1080p. */
    sl_video_config config = {.width = 1920, .height = 1080, .hardware = hardware};
    if (!tracker || !parser || !parser_context || !IHS_FrameTrackerOpenEpoch(tracker, key.epoch) ||
        !sl_video_open(pipeline, key, &config))
        goto cleanup;
    for (int offset = 0; offset < size;) {
        if (!running())
            goto cleanup;
        uint8_t *out = NULL;
        int bytes = 0;
        int used = av_parser_parse2(parser, parser_context, &out, &bytes, data + offset,
                                    size - offset, AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);
        if (used < 0 || (!used && !bytes))
            goto cleanup;
        offset += used;
        if (bytes &&
            !packet(pipeline, gfx, tracker, key, hardware, out, bytes, &packets, &outputs, held))
            goto cleanup;
    }
    uint8_t *out = NULL;
    int bytes = 0;
    if (av_parser_parse2(parser, parser_context, &out, &bytes, NULL, 0, AV_NOPTS_VALUE,
                         AV_NOPTS_VALUE, 0) < 0)
        goto cleanup;
    if (bytes &&
        !packet(pipeline, gfx, tracker, key, hardware, out, bytes, &packets, &outputs, held))
        goto cleanup;
    if (!sl_video_flush(pipeline, key) || !take(pipeline, gfx, hardware, held, &outputs) ||
        !outputs)
        goto cleanup;
    if (hardware && outputs != golden_count)
        goto cleanup;
    /* No new decode: reuse the same lease for 120 presentations. */
    for (unsigned i = 0; i < 120; ++i) {
        if (!running() || !draw(gfx, *held))
            goto cleanup;
        if (memcmp(readback, golden[outputs - 1], PIXELS)) {
            if (!hardware || !compare(*held, hardware, outputs - 1))
                goto cleanup;
        }
    }
    ok = true;
cleanup:
    sl_gfx_counters counters;
    sl_gfx_get_counters(gfx, &counters);
    if (hardware && counters.uploads != before.uploads)
        ok = false;
    trace("images=%zu imported=%zu pools=%u maps=%u busy=%u imports=%llu uploads=%llu "
          "upload_bytes=%llu retired=%llu\n",
          counters.image_bytes, counters.imported_bytes, counters.pool_groups, counters.maps,
          counters.busy_batches, (unsigned long long)counters.imports,
          (unsigned long long)counters.uploads, (unsigned long long)counters.uploaded_bytes,
          (unsigned long long)counters.retired_groups);
    sl_video_stop(pipeline, key);
    if (tracker)
        IHS_FrameTrackerClose(tracker);
    av_parser_close(parser);
    avcodec_free_context(&parser_context);
    trace("session=%llu hardware=%d packets=%u outputs=%u result=%s\n",
          (unsigned long long)key.session, hardware, packets, outputs, ok ? "PASS" : "FAIL");
    return ok;
}
int main(int argc, char **argv) {
    run_id = armGetSystemTick();
    bool sockets = R_SUCCEEDED(socketInitializeDefault());
    if (sockets)
        connect_log();
    trace("PROBE_BEGIN build=%s fixture=%s avcodec=%u avutil=%u sockets=%d transport=%d",
          NSL_GIT_COMMIT, argc > 1 ? argv[1] : "padding720", avcodec_version(), avutil_version(),
          sockets, log_fd >= 0);
    /* Retrieve the old diagnostic automatically, before replacing its file. */
    FILE *old = fopen("sdmc:/switch/nsteamlink-video-probe.log", "r");
    if (old) {
        char line[512];
        unsigned lines = 0;
        trace("PREVIOUS_LOG_BEGIN");
        while (lines < 64 && fgets(line, sizeof(line), old)) {
            if (strstr(line, "previous:") || strstr(line, "PREVIOUS_LOG"))
                continue;
            trace("previous: %s", line);
            ++lines;
        }
        fclose(old);
        trace("PREVIOUS_LOG_END");
    }
    av_log_set_callback(av_diagnostic);
    const unsigned char *embedded = nsl_probe_padding720;
    size_t size = nsl_probe_padding720_size;
    const char *fixture = argc > 1 ? argv[1] : "padding720";
    bool known = !strcmp(fixture, "padding720");
#define SELECT(name)                                                                               \
    if (!strcmp(fixture, #name)) {                                                                 \
        embedded = nsl_probe_##name;                                                               \
        size = nsl_probe_##name##_size;                                                            \
        known = true;                                                                              \
    }
    SELECT(padding1080);
    SELECT(sequential);
    SELECT(reordered);
    uint8_t *data = NULL;
    sl_video_pipeline *pipeline = NULL;
    sl_gfx *gfx = NULL;
    sl_video_frame *held = NULL;
    bool ok = false, sdl = false;
    enter("fixture");
    if (!known) {
        trace("unknown built-in fixture");
        goto cleanup;
    }
    data = calloc(1, size + AV_INPUT_BUFFER_PADDING_SIZE);
    readback = malloc(PIXELS);
    if (!data || !readback) {
        trace("allocation failed errno=%d", errno);
        goto cleanup;
    }
    memcpy(data, embedded, size);
    trace("embedded fixture bytes=%zu", size);
    enter("sdl-init");
    if (SDL_Init(SDL_INIT_AUDIO | SDL_INIT_GAMECONTROLLER)) {
        trace("SDL_Init: %s", SDL_GetError());
        goto cleanup;
    }
    sdl = true;
    if (SDL_WasInit(SDL_INIT_VIDEO)) {
        trace("unexpected SDL video owner");
        goto cleanup;
    }
    enter("pipeline-create");
    pipeline = sl_video_create();
    if (!pipeline)
        goto cleanup;
    enter("gfx-create");
    gfx = sl_gfx_create(&(sl_gfx_config){
        .width = 1280, .height = 720, .title = "Video probe", .diagnostic = diagnostic});
    if (!gfx) {
        trace("gfx creation rejected");
        goto cleanup;
    }
    enter("readback-allocate");
    if (!sl_gfx_request_readback(gfx))
        goto cleanup;
    enter("ui-oracle");
    if (!ui_oracle(gfx))
        goto cleanup;
    enter("software");
    if (!replay(pipeline, gfx, data, size, (sl_video_key){1, 1}, false, &held))
        goto cleanup;
    enter("hardware-cold");
    if (!replay(pipeline, gfx, data, size, (sl_video_key){2, 1}, true, &held))
        goto cleanup;
    sl_video_reap(pipeline);
    enter("hardware-reopen");
    if (!replay(pipeline, gfx, data, size, (sl_video_key){3, 1}, true, &held))
        goto cleanup;
    ok = true;
cleanup:;
    const char *failed = ok ? "none" : stage;
    if (held)
        sl_resource_release(&held->ref);
    if (gfx) {
        enter("cleanup-gfx-idle");
        sl_gfx_finish(gfx);
        sl_gfx_counters counters;
        sl_gfx_get_counters(gfx, &counters);
        if (counters.imported_bytes || counters.pool_groups || counters.busy_batches) {
            ok = false;
            failed = stage;
        }
        trace("drained imported=%zu pools=%u busy=%u", counters.imported_bytes,
              counters.pool_groups, counters.busy_batches);
        enter("cleanup-gfx-destroy");
        sl_gfx_destroy(gfx);
    }
    if (pipeline) {
        enter("cleanup-decoder");
        sl_video_reap(pipeline);
        if (!sl_video_destroy(pipeline)) {
            trace("decoder resources still live");
            abort();
        }
    }
    if (sdl) {
        enter("cleanup-sdl");
        SDL_Quit();
    }
    for (unsigned i = 0; i < FRAMES; ++i)
        free(golden[i]);
    free(readback);
    free(data);
    av_log_set_callback(av_log_default_callback);
    enter("complete");
    trace("PROBE_FINAL result=%s failed_stage=%s", ok ? "PASS" : "FAIL", failed);
    trace("PROBE_CLEANUP resources=clean transport=closing");
    FILE *saved = fopen("sdmc:/switch/nsteamlink-video-probe.log", "w");
    if (saved) {
        fwrite(transcript, 1, transcript_size, saved);
        fclose(saved);
    }
    uint64_t deadline = now_us() + 2000000;
    while (log_fd >= 0 && transmitted < transcript_size && now_us() < deadline) {
        send_pending();
        svcSleepThread(1000000);
    }
    if (log_fd >= 0)
        close(log_fd);
    if (sockets)
        socketExit();
    return ok ? 0 : 1;
}
