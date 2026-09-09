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
    IHS_FrameTicket *ticket;
    uint64_t decode_begin_us, decode_end_us;
    void *domain;
    atomic_bool available;
} sl_video_frame;
typedef struct sl_video_config {
    unsigned width, height;
    bool hardware;
    const unsigned char *extradata;
    size_t extradata_size;
} sl_video_config;

sl_video_pipeline *sl_video_create(void);
/* Decoder operations are serialized internally; close admission never waits on
 * FFmpeg. stop joins the callback domain via the decoder lock, then freezes it.
 * Reap/destroy belong to the runtime worker after callbacks have been excluded. */
bool sl_video_open(sl_video_pipeline *, sl_video_key, const sl_video_config *);
void sl_video_close(sl_video_pipeline *, sl_video_key);
void sl_video_stop(sl_video_pipeline *, sl_video_key);
bool sl_video_submit(sl_video_pipeline *, sl_video_key, const unsigned char *, size_t,
                     IHS_FrameTicket *, bool *ticket_taken);
bool sl_video_flush(sl_video_pipeline *, sl_video_key);
sl_video_frame *sl_video_take(sl_video_pipeline *); /* transfers pending reference */
bool sl_video_is_current(sl_video_pipeline *, sl_video_key);
void sl_video_reap(sl_video_pipeline *);
bool sl_video_clean(sl_video_pipeline *);
bool sl_video_destroy(sl_video_pipeline *); /* refuses live domains/leases */
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
} sl_video_counters;
bool sl_video_read_counters(sl_video_pipeline *, sl_video_key, sl_video_counters *);
