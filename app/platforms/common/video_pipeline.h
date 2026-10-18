#pragma once
#include "frame_lifetime.h"
#include <ihslib/frame_ticket.h>
#include <libavutil/frame.h>

typedef struct sl_video_pipeline sl_video_pipeline;
typedef struct sl_video_key {
    uint64_t session, epoch;
} sl_video_key;
typedef struct sl_video_frame {
    sl_resource_ref ref;
    AVFrame *pixels;
    sl_video_key key;
    IHS_FrameTicket *ticket; /* immutable decoded-input identity; not presentation ownership */
    uint64_t decode_begin_us, decode_end_us, publish_seq;
    uint64_t input_serial;
    uint32_t media_timestamp;
    bool has_media_timestamp;
    void *domain;
    atomic_bool available;
} sl_video_frame;
/* Called synchronously inside open/submit SDK format negotiation. Its context
 * is borrowed for that call only; the pipeline clears it before returning. */
typedef void (*sl_video_info_fn)(void *, const char *, unsigned threads);
typedef uint8_t (*sl_video_cpu_count_fn)(void);
typedef struct sl_video_config {
    unsigned width, height;
    bool hardware;
    const unsigned char *extradata;
    size_t extradata_size;
    sl_video_info_fn info;
    void *info_context;
    /* Platform CPU input, queried only for a slice-thread-capable codec.
     * NULL leaves SDK defaults intact. Not retained after open. */
    sl_video_cpu_count_fn cpu_count;
} sl_video_config;

sl_video_pipeline *sl_video_create(void);
/* Decoder operations are serialized internally; close admission never waits on
 * FFmpeg. stop joins the callback domain via the decoder lock, then freezes it.
 * Reap/destroy belong to the runtime worker after callbacks have been excluded. */
bool sl_video_open(sl_video_pipeline *, sl_video_key, const sl_video_config *);
typedef enum sl_video_open_result {
    SL_VIDEO_OPEN_GUARD = -1, SL_VIDEO_OPEN_UNAVAILABLE = 0, SL_VIDEO_OPEN_READY = 1,
} sl_video_open_result;
sl_video_open_result sl_video_open_ex(sl_video_pipeline *, sl_video_key, const sl_video_config *);
bool sl_video_has_hardware_context(sl_video_pipeline *, sl_video_key);
void sl_video_close(sl_video_pipeline *, sl_video_key);
void sl_video_stop(sl_video_pipeline *, sl_video_key);
/* Decoder flush phase: the protocol owner purges encoded fragments. Linux
 * AVCodec is not SDK-flushed; queued/held pixel objects survive until their
 * owners release them. Stop/reap separately closes parser and codec. */
void sl_video_discard_buffers(sl_video_pipeline *, sl_video_key);
typedef enum sl_video_submit_result {
    SL_VIDEO_SUBMIT_ERROR = 0,
    SL_VIDEO_SUBMIT_OK = 1,
    SL_VIDEO_SUBMIT_CORRUPT = 2,
    SL_VIDEO_SUBMIT_RESET = 4,
    SL_VIDEO_SUBMIT_DISABLE_HARDWARE = 8,
} sl_video_submit_result;
/* Synchronous borrowed callback, before player handoff/clock sampling. The
 * backend never retains its context or a session after this call returns. */
typedef void (*sl_video_feedback_fn)(void *, sl_video_submit_result);
sl_video_submit_result sl_video_submit(sl_video_pipeline *, sl_video_key, const unsigned char *,
                                       size_t, IHS_FrameTicket *, bool *ticket_taken,
                                       bool keyframe, sl_video_feedback_fn, sl_video_info_fn, void *);
bool sl_video_flush(sl_video_pipeline *, sl_video_key);
/* Decoded-output observation for codec/probe fixtures. Application playback
 * uses selection below: an input task and physical pixels have separate owners. */
sl_video_frame *sl_video_take(sl_video_pipeline *);
typedef struct sl_video_selection {
    sl_video_frame *frame;
    IHS_FrameTicket *ticket;
    sl_video_key key;
    uint32_t media_timestamp;
} sl_video_selection;
/* Transfers the newest ready task and THIS submission's returned pixels, if
 * any. A format0 placeholder is consumed with frame=NULL, never left waiting
 * for a later task's output. Pixel input identity may differ from task identity. */
bool sl_video_select(sl_video_pipeline *, sl_video_selection *);
void sl_video_selection_complete(sl_video_selection *, const IHS_FrameOutcome *);
void sl_video_selection_release(sl_video_selection *);
/* Original GetVideoWait: -1 without a queued frame, else remaining milliseconds. */
int32_t sl_video_wait(sl_video_pipeline *);
bool sl_video_is_current(sl_video_pipeline *, sl_video_key);
void sl_video_reap(sl_video_pipeline *);
bool sl_video_clean(sl_video_pipeline *);
bool sl_video_destroy(sl_video_pipeline *); /* refuses live domains/leases */
/* Raw codec/probe endpoint completion; application uses selection_complete. */
void sl_video_frame_complete(sl_video_frame *, const IHS_FrameOutcome *);
/* Renderer map groups hold a domain without pinning a reusable decoder surface.
 * The returned cookie is released only after destroying all imported maps. */
void *sl_video_hold_mapping(sl_video_frame *);
void sl_video_release_mapping(void *);

/* Session admission gate; freeze wins even against an open not yet entered. */
void sl_video_freeze(sl_video_pipeline *);
void sl_video_thaw(sl_video_pipeline *);

typedef struct sl_video_counters {
    uint32_t decoded, replaced, decode_max_us;
    uint64_t decode_total_us;
    uint64_t publish_short, publish_long, publish_gap_max_us;
    uint64_t take_empty, take_one, take_many, take_gap_max_us;
    uint64_t submits, submit_bytes, submit_long, submit_gap_max_us;
} sl_video_counters;
bool sl_video_read_counters(sl_video_pipeline *, sl_video_key, sl_video_counters *);

/* Product scheduling metadata, no frame references. Reader cursor is per epoch. */
#define SL_PUBLICATIONS 128
#define SL_PUBLICATION_READ 16
typedef struct sl_publication { uint64_t seq, us; } sl_publication;
typedef struct sl_publication_snapshot {
    sl_video_key key;
    uint64_t latest, pending;
    unsigned count;
    bool overflow;
    sl_publication items[SL_PUBLICATION_READ];
} sl_publication_snapshot;
bool sl_video_publications(sl_video_pipeline *, sl_video_key previous, uint64_t after,
                           sl_publication_snapshot *);
