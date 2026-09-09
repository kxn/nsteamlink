/* Self-contained G1 diagnostic. No Steam session/authentication dependency. */
#include "build_identity.h"
#include "gfx_backend.h"
#include "session/frame_tracker.h"
#include <SDL.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext.h>
#include <malloc.h>
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
static char transcript[1024 * 1024];
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
    sl_video_counters decoded;
    if (!sl_video_read_counters(pipeline, key, &decoded) || decoded.decoded != packets ||
        decoded.replaced + outputs != decoded.decoded) {
        trace("decoded/output/replaced accounting failed");
        goto cleanup;
    }
    trace("decode packets=%u decoded=%u presented=%u replaced=%u max_us=%u total_us=%llu", packets,
          decoded.decoded, outputs, decoded.replaced, decoded.decode_max_us,
          (unsigned long long)decoded.decode_total_us);
    sl_gfx_counters redraw_before;
    sl_gfx_get_counters(gfx, &redraw_before);
    /* No new decode: reuse the same lease for 120 presentations. */
    for (unsigned i = 0; i < 120; ++i) {
        if (!running() || !draw(gfx, *held))
            goto cleanup;
        if (memcmp(readback, golden[outputs - 1], PIXELS)) {
            if (!hardware || !compare(*held, hardware, outputs - 1))
                goto cleanup;
        }
    }
    sl_gfx_counters redraw_after;
    sl_gfx_get_counters(gfx, &redraw_after);
    if (redraw_before.uploads != redraw_after.uploads ||
        redraw_before.imports != redraw_after.imports ||
        redraw_before.image_bytes != redraw_after.image_bytes ||
        redraw_before.imported_bytes != redraw_after.imported_bytes) {
        trace("redraw unexpectedly uploaded/imported/grew resources");
        goto cleanup;
    }
    trace("redraw frames=120 new_uploads=0 new_imports=0 resource_growth=0");
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
/* CPU preparation microbenchmark, not end-to-end latency or power measurement.
 * Both variants use the same decoded frame, shader, acquire/present/readback path.
 * Acquire, fence waits and readback are outside the measured interval. */
static int order_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
static bool benchmark(sl_gfx *gfx, sl_video_frame *hardware, uint64_t session, bool reverse) {
    enum { WARMUP = 8, SAMPLES = 64 };
    IHS_FrameTracker *tracker = IHS_FrameTrackerCreate(session);
    AVFrame *cpu = av_frame_alloc();
    bool ok = false;
    if (!tracker || !cpu || !IHS_FrameTrackerOpenEpoch(tracker, 1))
        goto cleanup;
    for (unsigned pass = 0; pass < 2; ++pass) {
        bool copy = reverse ? pass == 0 : pass == 1;
        uint64_t times[SAMPLES];
        sl_gfx_counters before, after;
        sl_gfx_get_counters(gfx, &before);
        for (unsigned i = 0; i < WARMUP + SAMPLES; ++i) {
            IHS_FrameTicket *ticket = NULL;
            IHS_FrameReceive receive = {.firstReceiveUs = now_us(), .lastReceiveUs = now_us()};
            if (!running() || !drain(gfx))
                goto cleanup;
            if (copy &&
                IHS_FrameTrackerBegin(tracker, 1, i + 1, &receive, &ticket) != IHS_FrameBeginOK)
                goto cleanup;
            sl_video_frame software = {.pixels = cpu, .ticket = ticket};
            sl_resource_init(&software.ref, NULL, NULL);
            if (sl_gfx_begin(gfx) != SL_GFX_READY) {
                IHS_FrameTicketRelease(ticket);
                goto cleanup;
            }
            sl_gfx_draw_color(gfx, 0, 0, 0, 255);
            sl_gfx_clear(gfx);
            uint64_t start = now_us();
            bool transferred = !copy || av_hwframe_transfer_data(cpu, hardware->pixels, 0) >= 0;
            if (copy && transferred) {
                cpu->colorspace = hardware->pixels->colorspace;
                cpu->color_range = hardware->pixels->color_range;
                cpu->chroma_location = hardware->pixels->chroma_location;
            }
            bool drawn = transferred && sl_gfx_video(gfx, copy ? &software : hardware);
            uint64_t elapsed = now_us() - start;
            sl_gfx_present_result presented = sl_gfx_present(gfx);
            bool drained = drain(gfx);
            if (ticket) {
                IHS_FrameOutcome outcome = {.result = IHS_VideoFrameResultDroppedReset,
                                            .completionUs = now_us()};
                IHS_FrameTicketComplete(ticket, &outcome);
                IHS_FrameTicketRelease(ticket);
            }
            sl_resource_release(&software.ref);
            if (!drawn || presented.result != SL_GFX_READY || !drained ||
                !sl_gfx_readback(gfx, NULL, readback, PIXELS, 1280 * 4) ||
                memcmp(readback, golden[golden_count - 1], PIXELS))
                goto cleanup;
            if (i >= WARMUP)
                times[i - WARMUP] = elapsed;
        }
        sl_gfx_get_counters(gfx, &after);
        if (after.uploads - before.uploads != (copy ? WARMUP + SAMPLES : 0))
            goto cleanup;
        qsort(times, SAMPLES, sizeof(times[0]), order_u64);
        trace("BENCH path=%s samples=%u warmup=%u cpu_prepare_median_us=%llu p95_us=%llu "
              "uploads=%llu upload_bytes=%llu order=%u",
              copy ? "download-upload" : "direct", SAMPLES, WARMUP,
              (unsigned long long)times[SAMPLES / 2],
              (unsigned long long)times[(SAMPLES * 95 + 99) / 100 - 1],
              (unsigned long long)(after.uploads - before.uploads),
              (unsigned long long)(after.uploaded_bytes - before.uploaded_bytes), pass);
    }
    ok = true;
cleanup:
    /* No CPU frame is retained by software_video; its uploaded image versions
     * belong to the batch. The source hardware lease remains owned by caller. */
    av_frame_free(&cpu);
    if (tracker)
        IHS_FrameTrackerClose(tracker);
    return ok;
}
/* Independent numeric oracle: both video paths sharing one shader is insufficient
 * evidence for matrix/range correctness. Use constant YUV with known RGB values. */
static bool color_oracle(sl_gfx *gfx) {
    IHS_FrameTracker *tracker = IHS_FrameTrackerCreate(UINT64_MAX - 1);
    AVFrame *pixels = av_frame_alloc();
    bool ok = false;
    unsigned id = 0;
    if (!tracker || !pixels || !IHS_FrameTrackerOpenEpoch(tracker, 1))
        goto cleanup;
    for (unsigned planar = 0; planar < 2; ++planar) {
        av_frame_unref(pixels);
        pixels->format = planar ? AV_PIX_FMT_YUV420P : AV_PIX_FMT_NV12;
        pixels->width = pixels->height = 16;
        if (av_frame_get_buffer(pixels, 32) < 0)
            goto cleanup;
        for (unsigned full = 0; full < 2; ++full)
            for (unsigned bt709 = 0; bt709 < 2; ++bt709)
                for (unsigned tone = 0; tone < 3; ++tone) {
                    unsigned y = tone == 0 ? (full ? 0 : 16) : (full ? 255 : 235);
                    unsigned u = 128, v = 128;
                    if (tone == 2) {
                        y = bt709 ? (full ? 54 : 63) : (full ? 76 : 81);
                        u = bt709 ? (full ? 99 : 102) : (full ? 85 : 90);
                        v = full ? 255 : 240;
                    }
                    pixels->colorspace = bt709 ? AVCOL_SPC_BT709 : AVCOL_SPC_SMPTE170M;
                    pixels->color_range = full ? AVCOL_RANGE_JPEG : AVCOL_RANGE_MPEG;
                    pixels->chroma_location = AVCHROMA_LOC_LEFT;
                    for (unsigned row = 0; row < 16; ++row)
                        memset(pixels->data[0] + row * pixels->linesize[0], y, 16);
                    for (unsigned row = 0; row < 8; ++row)
                        for (unsigned x = 0; x < 8; ++x) {
                            if (planar) {
                                pixels->data[1][row * pixels->linesize[1] + x] = u;
                                pixels->data[2][row * pixels->linesize[2] + x] = v;
                            } else {
                                pixels->data[1][row * pixels->linesize[1] + x * 2] = u;
                                pixels->data[1][row * pixels->linesize[1] + x * 2 + 1] = v;
                            }
                        }
                    IHS_FrameTicket *ticket = NULL;
                    IHS_FrameReceive receive = {.firstReceiveUs = now_us(),
                                                .lastReceiveUs = now_us()};
                    if (IHS_FrameTrackerBegin(tracker, 1, ++id, &receive, &ticket) !=
                        IHS_FrameBeginOK)
                        goto cleanup;
                    sl_video_frame frame = {.pixels = pixels, .ticket = ticket};
                    sl_resource_init(&frame.ref, NULL, NULL);
                    bool drawn = draw(gfx, &frame);
                    bool matches = drawn && near_pixel(640, 360, tone ? 255 : 0,
                                                       tone == 1 ? 255 : 0, tone == 1 ? 255 : 0);
                    IHS_FrameOutcome outcome = {.result = IHS_VideoFrameResultDroppedReset,
                                                .completionUs = now_us()};
                    IHS_FrameTicketComplete(ticket, &outcome);
                    IHS_FrameTicketRelease(ticket);
                    sl_resource_release(&frame.ref);
                    if (!matches) {
                        trace("COLOR format=%s full=%u bt709=%u tone=%u result=FAIL",
                              planar ? "IYUV" : "NV12", full, bt709, tone);
                        goto cleanup;
                    }
                }
    }
    ok = true;
cleanup:
    av_frame_free(&pixels);
    if (tracker)
        IHS_FrameTrackerClose(tracker);
    trace("COLOR cases=%u result=%s", id, ok ? "PASS" : "FAIL");
    return ok;
}
static bool atlas_stress(sl_gfx *gfx) {
    unsigned char alpha[8 * 8];
    memset(alpha, 255, sizeof(alpha));
    if (sl_gfx_begin(gfx) != SL_GFX_READY)
        return false;
    unsigned pinned = 0, misses = 0;
    bool ok = true;
    for (unsigned i = 0; i < 600; ++i) {
        sl_gfx_texture *glyph = sl_gfx_create_texture(gfx, SL_GFX_R8, SL_GFX_STATIC, 8, 8);
        if (!glyph) {
            ++misses;
            continue;
        }
        bool drawn = !sl_gfx_upload(glyph, NULL, alpha, 8) &&
                     !sl_gfx_copy(gfx, glyph, NULL,
                                  &(sl_gfx_rect){(int)(i % 80) * 8, (int)(i / 80) * 8, 8, 8});
        sl_gfx_destroy_texture(glyph);
        ok &= drawn;
        ++pinned;
    }
    sl_gfx_present_result result = sl_gfx_present(gfx);
    bool drained = drain(gfx);
    sl_gfx_texture *reused =
        drained ? sl_gfx_create_texture(gfx, SL_GFX_R8, SL_GFX_STATIC, 8, 8) : NULL;
    ok &= result.result == SL_GFX_READY && drained && pinned == 512 && misses == 88 && reused;
    sl_gfx_destroy_texture(reused);
    trace("ATLAS pinned=%u bounded_misses=%u reuse_after_fence=%d result=%s", pinned, misses,
          reused != NULL, ok ? "PASS" : "FAIL");
    return ok;
}
typedef struct fixture_data {
    const char *name;
    const unsigned char *bytes;
    size_t size;
} fixture_data;
static bool run_case(const fixture_data *fixture, unsigned iteration, bool measure) {
    sl_video_pipeline *pipeline = NULL;
    sl_gfx *gfx = NULL;
    sl_video_frame *held = NULL;
    unsigned char *data = NULL;
    bool ok = false;
    for (unsigned i = 0; i < FRAMES; ++i) {
        free(golden[i]);
        golden[i] = NULL;
    }
    golden_count = 0;
    trace("CASE_BEGIN fixture=%s iteration=%u", fixture->name, iteration);
    enter("fixture");
    data = calloc(1, fixture->size + AV_INPUT_BUFFER_PADDING_SIZE);
    if (!data)
        goto cleanup;
    memcpy(data, fixture->bytes, fixture->size);
    enter("pipeline-create");
    pipeline = sl_video_create();
    if (!pipeline)
        goto cleanup;
    enter("gfx-create");
    gfx = sl_gfx_create(&(sl_gfx_config){
        .width = 1280, .height = 720, .title = "Video probe", .diagnostic = diagnostic});
    if (!gfx)
        goto cleanup;
    enter("readback-allocate");
    if (!sl_gfx_request_readback(gfx))
        goto cleanup;
    enter("ui-oracle");
    if (!ui_oracle(gfx))
        goto cleanup;
    enter("color-oracle");
    if (!color_oracle(gfx))
        goto cleanup;
    enter("atlas-stress");
    if (!atlas_stress(gfx))
        goto cleanup;
    uint64_t session = (uint64_t)iteration * 4 + 1;
    enter("software");
    if (!replay(pipeline, gfx, data, fixture->size, (sl_video_key){session, 1}, false, &held))
        goto cleanup;
    enter("hardware-cold");
    if (!replay(pipeline, gfx, data, fixture->size, (sl_video_key){session + 1, 1}, true, &held))
        goto cleanup;
    sl_video_reap(pipeline);
    enter("hardware-reopen");
    if (!replay(pipeline, gfx, data, fixture->size, (sl_video_key){session + 2, 1}, true, &held))
        goto cleanup;
    if (measure) {
        enter("cpu-prepare-benchmark");
        if (!benchmark(gfx, held, session + 3, iteration >= 4))
            goto cleanup;
    }
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
    free(data);
    for (unsigned i = 0; i < FRAMES; ++i) {
        free(golden[i]);
        golden[i] = NULL;
    }
    golden_count = 0;
    u64 used = 0;
    Result memory_result = svcGetInfo(&used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
    struct mallinfo heap = mallinfo();
    trace("MEMORY iteration=%u heap_live_bytes=%llu process_used_bytes=%llu query_result=%u",
          iteration, (unsigned long long)heap.uordblks, (unsigned long long)used, memory_result);
    trace("CASE_FINAL fixture=%s iteration=%u result=%s failed_stage=%s", fixture->name, iteration,
          ok ? "PASS" : "FAIL", failed);
    if (!ok)
        stage = failed;
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
    const fixture_data fixtures[] = {
#define FIXTURE(name) {#name, nsl_probe_##name, nsl_probe_##name##_size}
        FIXTURE(padding720), FIXTURE(padding1080), FIXTURE(sequential), FIXTURE(reordered)};
    const char *selection = argc > 1 ? argv[1] : "padding720";
    bool suite = !strcmp(selection, "suite"), known = suite;
    bool ok = false, sdl = false;
    unsigned completed = 0;
    readback = malloc(PIXELS);
    if (!readback)
        goto cleanup;
    enter("sdl-init");
    if (SDL_Init(SDL_INIT_AUDIO | SDL_INIT_GAMECONTROLLER)) {
        trace("SDL_Init: %s", SDL_GetError());
        goto cleanup;
    }
    sdl = true;
    if (SDL_WasInit(SDL_INIT_VIDEO))
        goto cleanup;
    for (unsigned iteration = 0; iteration < (suite ? 12u : 4u); ++iteration) {
        const fixture_data *fixture = &fixtures[iteration % 4];
        if (!suite && strcmp(selection, fixture->name))
            continue;
        known = true;
        bool measure = suite && iteration % 4 < 2 && (iteration < 4 || iteration >= 8);
        if (!run_case(fixture, iteration, measure))
            goto cleanup;
        ++completed;
    }
    ok = known && completed == (suite ? 12u : 1u);
cleanup:;
    const char *failed = ok ? "none" : stage;
    if (sdl) {
        enter("cleanup-sdl");
        SDL_Quit();
    }
    for (unsigned i = 0; i < FRAMES; ++i)
        free(golden[i]);
    free(readback);
    trace("SUITE cases_completed=%u cases_expected=%u", completed, suite ? 12u : 1u);
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
