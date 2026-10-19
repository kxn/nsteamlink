/* Decoder-boundary fixture shared by the desktop check and Switch probe.
 * A whole-GOP input gap is explicit; no Steam, transport/FEC or physical scanout
 * is simulated. Actual production submission, selection and task release run. */
#ifndef NSL_VIDEO_RECOVERY_PROBE_H
#define NSL_VIDEO_RECOVERY_PROBE_H
#include "session/frame_tracker.h"
#include "video_pipeline.h"
#include <libavcodec/avcodec.h>
#include <libavutil/md5.h>
#include <stdlib.h>
#include <string.h>

#define RECOVERY_INPUTS 7
static const unsigned recovery_offsets[] = {0, 25334, 37641, 51260, 66618, 80869};
static const unsigned recovery_sizes[] = {25334, 12307, 13619, 15358, 14251, 16198};
static const uint16_t recovery_ids[] = {100, 106, 107, 108, 109, 110, 111};
typedef struct recovery_row {
    unsigned input_id, task_id, pixel_id, bytes, result;
    bool pixels;
    uint64_t submit_us, select_us, render_us;
} recovery_row;
typedef struct recovery_result {
    const char *failure;
    bool hardware, hardware_context, padded, key_seen, next_p_seen, stopped;
    unsigned inputs, tasks, pictures;
    uint64_t key_to_readback_us;
    recovery_row rows[RECOVERY_INPUTS];
} recovery_result;
typedef struct recovery_callbacks {
    uint64_t (*now)(void *);
    /* Called for real pixels; caller supplies a truthful completion outcome.
     * A desktop checksum check never reports a physical Displayed result. */
    bool (*picture)(void *, sl_video_selection *, IHS_FrameOutcome *);
    bool (*running)(void *);
    void (*stage)(void *, const char *, unsigned);
    void *context;
} recovery_callbacks;
static unsigned recovery_index(unsigned id) {
    for (unsigned n = 0; n < RECOVERY_INPUTS; ++n)
        if (recovery_ids[n] == id)
            return n;
    return RECOVERY_INPUTS;
}
/* Independent ffmpeg framemd5, over visible Y/U/V rows (never stride padding).
 * Only the software reference is CPU-readable; hardware uses GPU readback. */
static bool recovery_reference_pixels(const sl_video_frame *image) {
    static const char *expected[] = {
        "c56217f3899351b7cea50f9402892c8d", "158dbb985eae46ffe84efae8d8c45754",
        "1d3b05f4b06f881624de075283c9eac9", "0b0b84633117ddef0d458456d1b0826c",
        "9ddfe1ae1fd0a1e95415eef4c364c60b", "7bebfcc284910ba62d0a28337c6630d8"};
    unsigned index = recovery_index(IHS_FrameTicketIdentity(image->ticket).frameId);
    AVFrame *frame = image->pixels;
    if (index >= RECOVERY_INPUTS || frame->format != AV_PIX_FMT_YUV420P || frame->width != 1280 ||
        frame->height != 720)
        return false;
    struct AVMD5 *md5 = av_md5_alloc();
    if (!md5)
        return false;
    av_md5_init(md5);
    for (unsigned plane = 0; plane < 3; ++plane) {
        unsigned width = plane ? 640 : 1280, height = plane ? 360 : 720;
        for (unsigned y = 0; y < height; ++y)
            av_md5_update(md5, frame->data[plane] + (ptrdiff_t)y * frame->linesize[plane], width);
    }
    unsigned char digest[16];
    av_md5_final(md5, digest);
    av_free(md5);
    const char *hex = "0123456789abcdef", *want = expected[index ? index - 1 : 0];
    for (unsigned n = 0; n < 16; ++n)
        if (hex[digest[n] >> 4] != want[2 * n] || hex[digest[n] & 15] != want[2 * n + 1])
            return false;
    return true;
}
static bool recovery_run(sl_video_pipeline *pipeline, sl_video_key key,
                         const unsigned char *fixture, size_t fixture_size, bool hardware,
                         bool padded, const recovery_callbacks *cb, recovery_result *out) {
    *out = (recovery_result){.failure = "fixture", .hardware = hardware, .padded = padded};
    IHS_FrameTracker *tracker = NULL;
    unsigned char *packet = NULL;
    bool opened = false, ok = false;
    uint64_t key_begin = 0;
    if (fixture_size != 97067 || !cb || !cb->now || !cb->picture || !cb->running)
        goto cleanup;
    out->failure = "tracker";
    tracker = IHS_FrameTrackerCreate(key.session);
    if (!tracker || !IHS_FrameTrackerOpenEpoch(tracker, key.epoch))
        goto cleanup;
    out->failure = "open";
    if (cb->stage)
        cb->stage(cb->context, "open", 0);
    const sl_video_config config = {.width = 1280, .height = 720, .hardware = hardware};
    if (!sl_video_open(pipeline, key, &config))
        goto cleanup;
    opened = true;
    out->hardware_context = sl_video_has_hardware_context(pipeline, key);
    out->failure = "hardware-context";
    if (hardware && !out->hardware_context)
        goto cleanup;
    if (cb->stage)
        cb->stage(cb->context, "opened", 0);
    for (unsigned n = 0; n < RECOVERY_INPUTS; ++n) {
        out->failure = "interrupted";
        if (!cb->running(cb->context))
            goto cleanup;
        unsigned au = n ? n - 1 : 0;
        size_t size = padded ? 65536 : recovery_sizes[au];
        packet = calloc(1, size + AV_INPUT_BUFFER_PADDING_SIZE);
        out->failure = "allocate";
        if (!packet)
            goto cleanup;
        memcpy(packet, fixture + recovery_offsets[au], recovery_sizes[au]);
        if (padded) {
            size_t at = recovery_sizes[au];
            memcpy(packet + at, "\0\0\0\1\x0c", 5);
            memset(packet + at + 5, 255, size - at - 6);
            packet[size - 1] = 128; /* Annex B filler_data_rbsp trailing bits. */
        }
        uint64_t start = cb->now(cb->context);
        IHS_FrameReceive receive = {.firstReceiveUs = start, .lastReceiveUs = start};
        IHS_FrameTicket *ticket = NULL;
        out->failure = "input-ticket";
        if (IHS_FrameTrackerBeginInput(tracker, key.epoch, recovery_ids[n], &receive, &ticket) !=
            IHS_FrameBeginOK)
            goto cleanup;
        bool taken = false;
        if (cb->stage)
            cb->stage(cb->context, "submit", recovery_ids[n]);
        start = cb->now(cb->context);
        if (n == 1)
            key_begin = start;
        sl_video_submit_result result =
            sl_video_submit(pipeline, key, packet, size, ticket, &taken, au == 0, NULL, NULL, NULL);
        uint64_t submitted_us = cb->now(cb->context);
        IHS_FrameTicketRelease(ticket);
        free(packet);
        packet = NULL;
        recovery_row *row = &out->rows[out->inputs++];
        row->input_id = recovery_ids[n];
        row->bytes = (unsigned)size;
        row->result = result;
        row->submit_us = submitted_us - start;
        out->failure = "submit";
        if (result != SL_VIDEO_SUBMIT_OK || !taken)
            goto cleanup;
        sl_video_selection selection = {0};
        if (cb->stage)
            cb->stage(cb->context, "select", recovery_ids[n]);
        start = cb->now(cb->context);
        bool selected = sl_video_select(pipeline, &selection);
        row->select_us = cb->now(cb->context) - start;
        out->failure = "select";
        if (!selected)
            goto cleanup;
        ++out->tasks;
        row->task_id = IHS_FrameTicketIdentity(selection.ticket).frameId;
        row->pixels = selection.frame != NULL;
        IHS_FrameOutcome outcome = {.result = IHS_VideoFrameResultDroppedReset};
        bool presented = true;
        if (selection.frame) {
            row->pixel_id = IHS_FrameTicketIdentity(selection.frame->ticket).frameId;
            if (cb->stage)
                cb->stage(cb->context, "render", row->pixel_id);
            start = cb->now(cb->context);
            presented = recovery_index(row->pixel_id) < RECOVERY_INPUTS &&
                        cb->picture(cb->context, &selection, &outcome);
            row->render_us = cb->now(cb->context) - start;
            if (presented) {
                ++out->pictures;
                if (row->pixel_id == 106) {
                    out->key_seen = outcome.completionUs >= key_begin;
                    if (out->key_seen)
                        out->key_to_readback_us = outcome.completionUs - key_begin;
                }
                if (row->pixel_id == 107)
                    out->next_p_seen = true;
            }
        }
        sl_video_selection_complete(&selection, &outcome);
        sl_video_selection_release(&selection);
        out->failure = "pixels";
        if (!presented)
            goto cleanup;
    }
    out->failure = "recovery-output";
    if (cb->stage)
        cb->stage(cb->context, "decoded", 0);
    ok = out->key_seen && out->next_p_seen;
cleanup:
    free(packet);
    if (opened) {
        if (cb->stage)
            cb->stage(cb->context, "stop", 0);
        sl_video_stop(pipeline, key);
        out->stopped = !sl_video_is_current(pipeline, key);
    }
    if (tracker)
        IHS_FrameTrackerClose(tracker);
    if (ok && out->stopped)
        out->failure = "none";
    return ok && out->stopped;
}
#endif
