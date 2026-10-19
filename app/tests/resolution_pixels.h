/* Shared desktop/Switch pixel oracle: one-pixel 1080p detail would disappear in
 * an intermediate 720p target. Native readback is before compositor scaling. */
#pragma once
#include "gfx_backend.h"
#include "session/frame_tracker.h"
#include <SDL.h>
#include <libavutil/frame.h>
#include <stdlib.h>
#include <string.h>

static bool resolution_pixels(sl_gfx *gfx, unsigned expected_height) {
    AVFrame *pixels = av_frame_alloc();
    IHS_FrameTracker *tracker = IHS_FrameTrackerCreate(UINT64_MAX - 7);
    IHS_FrameTicket *ticket = NULL;
    unsigned char *native = NULL;
    bool ok = false;
    if (!pixels || !tracker || !IHS_FrameTrackerOpenEpoch(tracker, 1))
        goto cleanup;
    pixels->format = AV_PIX_FMT_YUV420P;
    pixels->width = 1920;
    pixels->height = 1080;
    pixels->colorspace = AVCOL_SPC_BT709;
    pixels->color_range = AVCOL_RANGE_MPEG;
    pixels->chroma_location = AVCHROMA_LOC_LEFT;
    if (av_frame_get_buffer(pixels, 32) < 0)
        goto cleanup;
    for (int y = 0; y < 1080; ++y)
        for (int x = 0; x < 1920; ++x)
            pixels->data[0][(size_t)y * pixels->linesize[0] + x] = (x + y) & 1 ? 235 : 16;
    for (unsigned p = 1; p < 3; ++p)
        for (unsigned y = 0; y < 540; ++y)
            memset(pixels->data[p] + (size_t)y * pixels->linesize[p], 128, 960);
    IHS_FrameReceive receive = {.firstReceiveUs = 1, .lastReceiveUs = 1};
    if (IHS_FrameTrackerBegin(tracker, 1, 1, &receive, &ticket) != IHS_FrameBeginOK)
        goto cleanup;
    sl_video_frame frame = {.pixels = pixels, .ticket = ticket};
    sl_resource_init(&frame.ref, NULL, NULL);
    if (!sl_gfx_request_readback(gfx) || sl_gfx_begin(gfx) != SL_GFX_READY)
        goto cleanup;
    sl_gfx_draw_color(gfx, 0, 0, 0, 255);
    sl_gfx_clear(gfx);
    bool drawn = sl_gfx_video(gfx, &frame);
    sl_gfx_present_result result = sl_gfx_present(gfx);
    if (!drawn || result.result != SL_GFX_READY)
        goto cleanup;
    sl_gfx_result drain = SL_GFX_BUSY;
    for (unsigned i = 0; i < 5000 && drain == SL_GFX_BUSY; ++i) {
        drain = sl_gfx_poll_drain(gfx);
        if (drain == SL_GFX_BUSY)
            SDL_Delay(1);
    }
    unsigned width, height;
    if (drain != SL_GFX_READY || !sl_gfx_readback_native(gfx, NULL, 0, 0, &width, &height) ||
        height != expected_height || width != expected_height * 16 / 9)
        goto cleanup;
    size_t bytes = (size_t)width * height * 4;
    native = malloc(bytes);
    if (!native || !sl_gfx_readback_native(gfx, native, bytes, width * 4, &width, &height))
        goto cleanup;
    if (height == 1080) {
        /* Verify both directions, including edges and rows beyond 720. A
         * 720p intermediate enlarged to 1080p cannot reproduce these pixels. */
        for (unsigned y = 0; y < height; y += 97)
            for (unsigned x = 0; x < width; ++x) {
                const unsigned char *p = native + ((size_t)y * width + x) * 4;
                unsigned expected = (x + y) & 1 ? 255 : 0;
                if (abs((int)p[0] - (int)expected) > 3 || abs((int)p[1] - (int)expected) > 3 ||
                    abs((int)p[2] - (int)expected) > 3 || p[3] != 255)
                    goto cleanup;
            }
    }
    /* Canonical captures remain 720p, with bounds/capacity checked even when
     * the actual output is 1080p. Guard bytes catch accidental native copies. */
    unsigned char region[4 * 7 * 5 + 16];
    memset(region, 0xa5, sizeof(region));
    sl_gfx_rect box = {1000, 700, 7, 5};
    if (!sl_gfx_readback(gfx, &box, region, 4 * 7 * 5, 4 * 7) ||
        sl_gfx_readback(gfx, &box, region, 4 * 7 * 5 - 1, 4 * 7))
        goto cleanup;
    for (unsigned i = 4 * 7 * 5; i < sizeof(region); ++i)
        if (region[i] != 0xa5)
            goto cleanup;
    ok = pixels->width == 1920 && pixels->height == 1080;
cleanup:
    sl_gfx_finish(gfx);
    IHS_FrameTicketRelease(ticket);
    if (tracker)
        IHS_FrameTrackerClose(tracker);
    av_frame_free(&pixels);
    free(native);
    return ok;
}
