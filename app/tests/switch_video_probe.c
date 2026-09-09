/* Offline G1 diagnostic. No session/socket/authentication dependency. */
#include "gfx_backend.h"
#include "session/frame_tracker.h"
#include <SDL.h>
#include <libavcodec/avcodec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <switch.h>
#include <time.h>

#define PIXELS (1280u * 720u * 4u)
#define FRAMES 16
static unsigned char *golden[FRAMES], *readback;
static uint16_t golden_id[FRAMES];
static unsigned golden_count;
static FILE *logfile;
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
    return abs((int)p[0] - (int)r) <= 2 && abs((int)p[1] - (int)g) <= 2 &&
           abs((int)p[2] - (int)b) <= 2 && p[3] == 255;
}
static bool ui_oracle(sl_gfx *gfx) {
    sl_gfx_texture *rgba = sl_gfx_create_texture(gfx, SL_GFX_RGBA8, SL_GFX_STATIC, 1, 1);
    sl_gfx_texture *glyph = sl_gfx_create_texture(gfx, SL_GFX_R8, SL_GFX_STATIC, 64, 64);
    sl_gfx_texture *target = sl_gfx_create_texture(gfx, SL_GFX_RGBA8, SL_GFX_TARGET, 64, 64);
    bool ok = false;
    unsigned char red[4] = {255, 0, 0, 128}, alpha[64 * 64];
    memset(alpha, 128, sizeof(alpha));
    if (!rgba || !glyph || !target || sl_gfx_upload(rgba, NULL, red, 4) ||
        sl_gfx_upload(glyph, NULL, alpha, 64))
        goto cleanup;
    sl_gfx_texture_blend(rgba, SL_GFX_BLEND_ALPHA);
    sl_gfx_texture_blend(glyph, SL_GFX_BLEND_ALPHA);
    sl_gfx_texture_blend(target, SL_GFX_BLEND_ALPHA);
    sl_gfx_texture_alpha(target, 128);
    if (sl_gfx_begin(gfx) != SL_GFX_READY)
        goto cleanup;
    sl_gfx_target(gfx, target);
    sl_gfx_draw_color(gfx, 0, 0, 0, 0);
    sl_gfx_clear(gfx);
    sl_gfx_copy(gfx, rgba, NULL, &(sl_gfx_rect){0, 0, 64, 64});
    sl_gfx_target(gfx, NULL);
    sl_gfx_draw_color(gfx, 0, 0, 0, 255);
    sl_gfx_clear(gfx);
    sl_gfx_copy(gfx, target, NULL, &(sl_gfx_rect){0, 0, 64, 64});
    sl_gfx_copy(gfx, glyph, NULL, &(sl_gfx_rect){64, 0, 64, 64});
    sl_gfx_draw_color(gfx, 0, 255, 0, 255);
    sl_gfx_fill(gfx, &(sl_gfx_rect){0, 128, 16, 16});
    sl_gfx_present(gfx);
    /* Destroy logical handles before the fence: concrete versions stay pinned. */
    sl_gfx_destroy_texture(rgba);
    rgba = NULL;
    sl_gfx_destroy_texture(glyph);
    glyph = NULL;
    sl_gfx_destroy_texture(target);
    target = NULL;
    ok = drain(gfx) && sl_gfx_readback(gfx, NULL, readback, PIXELS, 1280 * 4) &&
         near_pixel(16, 16, 64, 0, 0) && near_pixel(80, 16, 128, 128, 128) &&
         near_pixel(8, 136, 0, 255, 0) && near_pixel(8, 583, 0, 0, 0);
cleanup:
    sl_gfx_destroy_texture(rgba);
    sl_gfx_destroy_texture(glyph);
    sl_gfx_destroy_texture(target);
    fprintf(logfile, "UI alpha/atlas/origin/lifetime=%s\n", ok ? "PASS" : "FAIL");
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
    fprintf(logfile, "frame=%u ticket=%u max_delta=%u outside_tolerance=%zu\n", index, id,
            max_delta, differing);
    /* Both paths use the same shader; allow only normalized-coordinate rounding. */
    return differing == 0;
}
static bool take(sl_video_pipeline *pipeline, sl_gfx *gfx, bool hardware, sl_video_frame **held,
                 unsigned *outputs) {
    sl_video_frame *frame = sl_video_take(pipeline);
    if (!frame)
        return true;
    bool ok = draw(gfx, frame) && compare(frame, hardware, (*outputs)++);
    IHS_FrameOutcome outcome = {.result = ok ? IHS_VideoFrameResultDisplayed
                                             : IHS_VideoFrameResultDroppedReset,
                                .completionUs = now_us(),
                                .presentationSerial = *outputs};
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
    fprintf(logfile,
            "images=%zu imported=%zu pools=%u maps=%u busy=%u imports=%llu uploads=%llu "
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
    fprintf(logfile, "session=%llu hardware=%d packets=%u outputs=%u result=%s\n",
            (unsigned long long)key.session, hardware, packets, outputs, ok ? "PASS" : "FAIL");
    return ok;
}
int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "sdmc:/switch/nsteamlink-video-probe/padding720.h264";
    logfile = fopen("sdmc:/switch/nsteamlink-video-probe.log", "w");
    if (!logfile)
        return 1;
    fprintf(logfile,
            "G1 offline comparison; avcodec=%u avutil=%u SDL-video must stay uninitialized\n",
            avcodec_version(), avutil_version());
    FILE *fixture = fopen(path, "rb");
    uint8_t *data = NULL;
    long size = 0;
    sl_video_pipeline *pipeline = NULL;
    sl_gfx *gfx = NULL;
    sl_video_frame *held = NULL;
    bool ok = false, sdl = false;
    if (!fixture || fseek(fixture, 0, SEEK_END) || (size = ftell(fixture)) <= 0 ||
        size > 2 * 1024 * 1024)
        goto cleanup;
    rewind(fixture);
    data = calloc(1, size + AV_INPUT_BUFFER_PADDING_SIZE);
    readback = malloc(PIXELS);
    if (!data || !readback || fread(data, 1, size, fixture) != (size_t)size)
        goto cleanup;
    fclose(fixture);
    fixture = NULL;
    if (SDL_Init(SDL_INIT_AUDIO | SDL_INIT_GAMECONTROLLER))
        goto cleanup;
    sdl = true;
    if (SDL_WasInit(SDL_INIT_VIDEO))
        goto cleanup;
    pipeline = sl_video_create();
    gfx = sl_gfx_create(&(sl_gfx_config){1280, 720, "Video probe"});
    if (!pipeline || !gfx || !sl_gfx_request_readback(gfx))
        goto cleanup;
    if (!ui_oracle(gfx))
        goto cleanup;
    if (!replay(pipeline, gfx, data, size, (sl_video_key){1, 1}, false, &held))
        goto cleanup;
    /* Keep A alive while B opens. Its lease is released only on B's first output. */
    if (!replay(pipeline, gfx, data, size, (sl_video_key){2, 1}, true, &held))
        goto cleanup;
    sl_video_reap(pipeline);
    if (!replay(pipeline, gfx, data, size, (sl_video_key){3, 1}, true, &held))
        goto cleanup;
    ok = true;
cleanup:
    if (fixture)
        fclose(fixture);
    if (held)
        sl_resource_release(&held->ref);
    if (gfx) {
        sl_gfx_finish(gfx);
        sl_gfx_counters counters;
        sl_gfx_get_counters(gfx, &counters);
        if (counters.imported_bytes || counters.pool_groups || counters.busy_batches)
            ok = false;
        fprintf(logfile, "drained imported=%zu pools=%u busy=%u\n", counters.imported_bytes,
                counters.pool_groups, counters.busy_batches);
        sl_gfx_destroy(gfx);
    }
    if (pipeline) {
        sl_video_reap(pipeline);
        if (!sl_video_destroy(pipeline))
            abort();
    }
    if (sdl)
        SDL_Quit();
    for (unsigned i = 0; i < FRAMES; ++i)
        free(golden[i]);
    free(readback);
    free(data);
    fprintf(logfile, "FINAL=%s; user must independently observe hbmenu return\n",
            ok ? "PASS" : "FAIL");
    fclose(logfile);
    return ok ? 0 : 1;
}
