/* Actual decoder inputs, not filler. Shared desktop/device fixture runner.
 * No Steam session, transport, physical display or hardware capability claim
 * follows from the desktop path. Headless completion never says Displayed. */
#pragma once
#include "session/frame_tracker.h"
#include "video_pipeline.h"
#include <libavcodec/avcodec.h>
#include <libavutil/md5.h>
#include <libavutil/pixdesc.h>
#include <libavutil/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
typedef struct vcl_spec {
    const char *name;
    unsigned width, height, key_bytes, p_bytes, vcl_bytes;
    const char *sha256, *pixel_md5;
} vcl_spec;
#include "vcl_fixture_metadata.h"
typedef struct vcl_result {
    const char *failure;
    bool hardware_context, guarded, stopped;
    unsigned inputs, pictures;
    size_t max_input;
    struct {
        unsigned bytes, status, task, pixel;
        bool taken;
        uint64_t submit_us;
    } rows[2];
} vcl_result;
typedef struct vcl_callbacks {
    bool (*picture)(void *, sl_video_selection *, unsigned);
    void (*stage)(void *, const char *);
    bool (*active)(void *);
    void *context;
} vcl_callbacks;
static uint64_t vcl_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
static bool vcl_fixture_valid(const vcl_spec *s, const unsigned char *data, size_t size) {
    if (size != (size_t)s->key_bytes + s->p_bytes)
        return false;
    struct AVSHA *sha = av_sha_alloc();
    if (!sha)
        return false;
    unsigned char digest[32];
    char text[65];
    av_sha_init(sha, 256);
    av_sha_update(sha, data, size);
    av_sha_final(sha, digest);
    av_free(sha);
    for (unsigned n = 0; n < 32; ++n)
        snprintf(text + 2 * n, 3, "%02x", digest[n]);
    return !strcmp(text, s->sha256);
}
static unsigned vcl_sample(unsigned plane, unsigned x, unsigned y) {
    return !plane ? 16 + (3 * (x / 16) + 5 * (y / 16)) % 220
                  : 64 + ((plane == 1 ? x : y) / 8) % 128;
}
static bool vcl_reference_pixels(const vcl_spec *s, const AVFrame *f) {
    if (!f || f->format != AV_PIX_FMT_YUV420P || f->width != (int)s->width ||
        f->height != (int)s->height)
        return false;
    struct AVMD5 *md5 = av_md5_alloc();
    if (!md5)
        return false;
    av_md5_init(md5);
    bool ok = true;
    for (unsigned plane = 0; plane < 3; ++plane) {
        unsigned w = plane ? s->width / 2 : s->width, h = plane ? s->height / 2 : s->height;
        for (unsigned y = 0; y < h; ++y) {
            const unsigned char *row = f->data[plane] + (ptrdiff_t)y * f->linesize[plane];
            av_md5_update(md5, row, w);
            for (unsigned x = 0; x < w; ++x)
                ok &= row[x] == vcl_sample(plane, x, y);
        }
    }
    unsigned char digest[16];
    char text[33];
    av_md5_final(md5, digest);
    av_free(md5);
    for (unsigned n = 0; n < 16; ++n)
        snprintf(text + 2 * n, 3, "%02x", digest[n]);
    return ok && !strcmp(text, s->pixel_md5);
}
static bool vcl_run(sl_video_pipeline *pipeline, sl_video_key key, const vcl_spec *s,
                    const unsigned char *data, size_t size, bool hardware, bool expect_guard,
                    const vcl_callbacks *cb, vcl_result *result) {
    *result = (vcl_result){.failure = "fixture"};
    IHS_FrameTracker *tracker = NULL;
    bool opened = false, ok = false;
    if (!vcl_fixture_valid(s, data, size))
        goto cleanup;
    result->failure = "tracker";
    tracker = IHS_FrameTrackerCreate(key.session);
    if (!tracker || !IHS_FrameTrackerOpenEpoch(tracker, key.epoch))
        goto cleanup;
    result->failure = "open";
    sl_video_config config = {.width = s->width, .height = s->height, .hardware = hardware};
    if (!sl_video_open(pipeline, key, &config))
        goto cleanup;
    opened = true;
    result->hardware_context = sl_video_has_hardware_context(pipeline, key);
    if (cb->stage)
        cb->stage(cb->context, "opened");
    result->failure = "hardware-context";
    if (hardware && !result->hardware_context)
        goto cleanup;
    for (unsigned n = 0; n < 2; ++n) {
        result->failure = "interrupted";
        if (cb->active && !cb->active(cb->context))
            goto cleanup;
        size_t bytes = n ? s->p_bytes : s->key_bytes;
        const unsigned char *packet = data + (n ? s->key_bytes : 0);
        IHS_FrameReceive receive = {.firstReceiveUs = vcl_now(), .lastReceiveUs = vcl_now()};
        IHS_FrameTicket *ticket = NULL;
        result->failure = "input-ticket";
        if (IHS_FrameTrackerBeginInput(tracker, key.epoch, n + 1, &receive, &ticket) !=
            IHS_FrameBeginOK)
            goto cleanup;
        bool taken = false;
        uint64_t before = vcl_now();
        sl_video_submit_result submitted =
            sl_video_submit(pipeline, key, packet, bytes, ticket, &taken, n == 0, NULL, NULL, NULL);
        result->rows[n].submit_us = vcl_now() - before;
        result->rows[n].bytes = bytes;
        result->rows[n].status = submitted;
        result->rows[n].taken = taken;
        ++result->inputs;
        if (result->max_input < bytes)
            result->max_input = bytes;
        if (expect_guard) {
            result->guarded = submitted == SL_VIDEO_SUBMIT_ERROR && !taken;
            if (!taken)
                IHS_FrameTicketAbandonInput(ticket);
            IHS_FrameTicketRelease(ticket);
            ok = result->guarded;
            if (ok)
                result->failure = "none";
            goto cleanup;
        }
        if (!taken)
            IHS_FrameTicketAbandonInput(ticket);
        IHS_FrameTicketRelease(ticket);
        result->failure = "submit";
        if (submitted != SL_VIDEO_SUBMIT_OK || !taken)
            goto cleanup;
        sl_video_selection selected = {0};
        result->failure = "select";
        if (!sl_video_select(pipeline, &selected))
            goto cleanup;
        result->rows[n].task =
            selected.ticket ? IHS_FrameTicketIdentity(selected.ticket).frameId : 0;
        result->rows[n].pixel =
            selected.frame ? IHS_FrameTicketIdentity(selected.frame->ticket).frameId : 0;
        bool pixels = selected.frame && IHS_FrameTicketIdentity(selected.ticket).frameId == n + 1 &&
                      IHS_FrameTicketIdentity(selected.frame->ticket).frameId == n + 1;
        if (pixels)
            pixels = hardware ? selected.frame->pixels->format == av_get_pix_fmt("nvtegra")
                              : vcl_reference_pixels(s, selected.frame->pixels);
        if (pixels && cb->picture)
            pixels = cb->picture(cb->context, &selected, n);
        IHS_FrameOutcome outcome = {.result = IHS_VideoFrameResultDroppedReset,
                                    .completionUs = vcl_now()};
        sl_video_selection_complete(&selected, &outcome);
        sl_video_selection_release(&selected);
        result->failure = "pixels";
        if (!pixels)
            goto cleanup;
        ++result->pictures;
    }
    if (cb->stage)
        cb->stage(cb->context, "decoded");
    result->failure = "none";
    ok = true;
cleanup:
    if (opened) {
        sl_video_stop(pipeline, key);
        result->stopped = true;
    }
    if (tracker)
        IHS_FrameTrackerClose(tracker);
    return ok;
}
