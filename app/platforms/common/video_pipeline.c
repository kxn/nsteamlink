#include "video_pipeline.h"
#include "video_timing.h"
#include "session/packet.h"
#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext.h>
#include <libavutil/mem.h>
#include <pthread.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define DOMAIN_COUNT 2
/* Valid 60-sample ages in [0,150] ms bound mean+2*sample_stddev below
 * 244 ms: 15 queued frames at the advertised 60 fps, plus candidate/current,
 * two GPU batches and one publication handoff. Scratch frames remain separate. */
#define LEASE_COUNT  20
#define INPUT_JOB_COUNT 256 /* matches bounded CPU endpoint storage; not an SDK queue policy */
#define MAX_PACKET   (2u * 1024u * 1024u)
typedef struct domain {
    sl_video_key key;
    AVCodecContext *codec;
    AVCodecParserContext *parser;
    AVFrame *scratch;
    bool occupied, stopped, reaping;
    atomic_uint external, mappings;
    enum AVPixelFormat hardware_format;
    sl_video_info_fn info;
    void *info_context; /* Non-NULL only within the borrowed SDK call scope. */
} domain;
typedef struct input_job {
    IHS_FrameTicket *ticket;
    sl_video_key key;
    uint64_t input_serial;
    uint32_t media_timestamp;
    bool has_timestamp, placeholder;
    uint64_t output_seq; /* output of this FinalDecode, independent of pixel input identity */
} input_job;
struct sl_video_pipeline {
    pthread_mutex_t mailbox, decoder;
    domain domains[DOMAIN_COUNT];
    sl_video_frame leases[LEASE_COUNT];
    sl_video_frame *pending[LEASE_COUNT];
    unsigned pending_count;
    sl_video_timing timing;
    input_job jobs[INPUT_JOB_COUNT];
    unsigned job_count;
    sl_video_frame *image;
    sl_video_key active;
    bool accepting;
    bool cancelled, frozen;
    sl_video_counters counters;
    uint64_t publish_seq;
    sl_publication publications[SL_PUBLICATIONS];
#if NSL_DIAGNOSTICS
    uint64_t last_publish_us, last_take_us, last_submit_us, published_since_take;
#endif
};
typedef struct packet_token {
    IHS_FrameTicket *ticket;
    sl_video_key key;
    uint64_t begin_us;
    uint32_t media_timestamp;
    bool has_media_timestamp;
    uint64_t input_serial;
    atomic_bool claimed;
} packet_token;
static uint64_t now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
static bool same(sl_video_key a, sl_video_key b) {
    return a.session == b.session && a.epoch == b.epoch;
}
/* Official Linux PutVideoFrame is after receive/error handling (§91–92).
 * A task owns this call's returned object, not an Android input-PTS lookup. */
static bool queue_task(sl_video_pipeline *p, domain *d, IHS_FrameTicket *ticket,
                           bool hasTimestamp, uint32_t timestamp, uint64_t outputSeq, bool placeholder) {
    if (!IHS_FrameTicketRetain(ticket)) return false;
    uint64_t serial = IHS_FrameTicketIdentity(ticket).receiveSerial;
    pthread_mutex_lock(&p->mailbox);
    bool active = p->accepting && same(p->active,d->key) && p->job_count < INPUT_JOB_COUNT;
    if (active) {
        if (hasTimestamp) sl_video_timing_update(&p->timing,timestamp,IHS_SessionPacketTimestamp(),false);
        p->jobs[p->job_count++] = (input_job){ticket,d->key,serial,timestamp,hasTimestamp,placeholder,
                                             placeholder ? p->publish_seq : outputSeq};
    }
    pthread_mutex_unlock(&p->mailbox);
    if (!active) IHS_FrameTicketRelease(ticket);
    return active;
}
static void dropped(IHS_FrameTicket *ticket, IHS_VideoFrameResult reason) {
    IHS_FrameOutcome result = {.result = reason, .completionUs = now_us()};
    IHS_FrameTicketComplete(ticket, &result);
}
static void free_token(void *unused, uint8_t *data) {
    (void)unused;
    packet_token *token = (void *)data;
    IHS_FrameTicketRelease(token->ticket);
    av_free(token);
}
static void release_frame(void *context) {
    sl_video_frame *frame = context;
    domain *d = frame->domain;
    IHS_FrameTicketRelease(frame->ticket);
    frame->ticket = NULL;
    av_frame_unref(frame->pixels);
    atomic_fetch_sub_explicit(&d->external, 1, memory_order_release);
    /* Last access: another callback may acquire this envelope immediately. */
    atomic_store_explicit(&frame->available, true, memory_order_release);
}
sl_video_pipeline *sl_video_create(void) {
    sl_video_pipeline *p = calloc(1, sizeof(*p));
    if (!p)
        return NULL;
    if (pthread_mutex_init(&p->mailbox, NULL)) {
        free(p);
        return NULL;
    }
    if (pthread_mutex_init(&p->decoder, NULL)) {
        pthread_mutex_destroy(&p->mailbox);
        free(p);
        return NULL;
    }
    for (unsigned i = 0; i < DOMAIN_COUNT; ++i) {
        atomic_init(&p->domains[i].external, 0);
        atomic_init(&p->domains[i].mappings, 0);
        p->domains[i].scratch = av_frame_alloc();
        if (!p->domains[i].scratch)
            goto fail;
    }
    for (unsigned i = 0; i < LEASE_COUNT; ++i) {
        p->leases[i].pixels = av_frame_alloc();
        atomic_init(&p->leases[i].available, true);
        if (!p->leases[i].pixels)
            goto fail;
    }
    return p;
fail:
    for (unsigned i = 0; i < DOMAIN_COUNT; ++i)
        av_frame_free(&p->domains[i].scratch);
    for (unsigned i = 0; i < LEASE_COUNT; ++i)
        av_frame_free(&p->leases[i].pixels);
    pthread_mutex_destroy(&p->decoder);
    pthread_mutex_destroy(&p->mailbox);
    free(p);
    return NULL;
}
static enum AVPixelFormat hardware_format(AVCodecContext *ctx, const enum AVPixelFormat *formats) {
    domain *d = ctx->opaque;
    const enum AVPixelFormat *first = formats;
    enum AVPixelFormat selected = AV_PIX_FMT_NONE;
    for (; *formats != AV_PIX_FMT_NONE; ++formats)
        if (*formats == d->hardware_format) {
            selected = *formats;
            break;
        }
    /* Original selector permits an offered software format when the target
     * hardware path is unavailable. No download of a failed HW frame occurs. */
    if (selected == AV_PIX_FMT_NONE)
        for (formats = first; *formats != AV_PIX_FMT_NONE; ++formats)
            if (*formats == AV_PIX_FMT_YUV420P || *formats == AV_PIX_FMT_YUVJ420P) {
                selected = *formats;
                break;
            }
    if (d->info) {
        char description[128];
        if (selected != AV_PIX_FMT_NONE && selected == d->hardware_format)
            snprintf(description, sizeof(description), "FFmpeg NVDEC");
        else
            snprintf(description, sizeof(description), "libavcodec software decoding with %d thread%s",
                     ctx->thread_count, ctx->thread_count >= 2 ? "s" : "");
        d->info(d->info_context, description, (unsigned)ctx->thread_count);
    }
    return selected;
}
static domain *find_domain(sl_video_pipeline *p, sl_video_key key) {
    for (unsigned i = 0; i < DOMAIN_COUNT; ++i)
        if (p->domains[i].occupied && same(p->domains[i].key, key))
            return &p->domains[i];
    return NULL;
}
bool sl_video_open(sl_video_pipeline *p, sl_video_key key, const sl_video_config *config) {
    return sl_video_open_ex(p, key, config) == SL_VIDEO_OPEN_READY;
}
sl_video_open_result sl_video_open_ex(sl_video_pipeline *p, sl_video_key key, const sl_video_config *config) {
    if (!key.session || !key.epoch || !config || !config->width || !config->height ||
        config->width > 1920 || config->height > 1080 || config->extradata_size > MAX_PACKET ||
        (config->extradata_size && !config->extradata))
        return SL_VIDEO_OPEN_GUARD;
    pthread_mutex_lock(&p->decoder);
    pthread_mutex_lock(&p->mailbox);
    bool admissible = !p->frozen && !p->accepting &&
                      (!p->active.session || key.session > p->active.session ||
                       (key.session == p->active.session && key.epoch > p->active.epoch));
    if (admissible) {
        if (p->active.session != key.session) sl_video_timing_reset(&p->timing);
        p->active = key;
        p->cancelled = false;
        p->counters = (sl_video_counters){0};
        p->publish_seq = 0;
#if NSL_DIAGNOSTICS
        p->last_publish_us = p->last_take_us = p->last_submit_us = p->published_since_take = 0;
#endif
    }
    pthread_mutex_unlock(&p->mailbox);
    domain *d = NULL;
    if (admissible)
        for (unsigned i = 0; i < DOMAIN_COUNT; ++i)
            if (!p->domains[i].occupied) {
                d = &p->domains[i];
                break;
            }
    if (!d) {
        pthread_mutex_unlock(&p->decoder);
        return admissible ? SL_VIDEO_OPEN_UNAVAILABLE : SL_VIDEO_OPEN_GUARD;
    }
    sl_video_open_result failure = SL_VIDEO_OPEN_GUARD;
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (!codec) {
        failure = SL_VIDEO_OPEN_UNAVAILABLE;
        goto fail;
    }
    d->codec = codec ? avcodec_alloc_context3(codec) : NULL;
    if (!d->codec)
        goto fail;
    d->key = key;
    d->hardware_format = AV_PIX_FMT_NONE;
    d->codec->width = config->width;
    d->codec->height = config->height;
    /* Target-ABI dimensions, using the original @324725–756 alignment pattern.
     * Source raw offsets are not proof of bundled SDK field parity (§94);
     * FAST is independently verified through the SDK flags2 option offset. */
    d->codec->coded_width = (config->width + 31u) & ~31u;
    d->codec->coded_height = (config->height + 15u) & ~15u;
    d->codec->flags2 |= AV_CODEC_FLAG2_FAST;
    d->codec->thread_count = 1;
    d->codec->opaque = d;
    d->codec->get_format = hardware_format;
    d->codec->flags |= AV_CODEC_FLAG_COPY_OPAQUE;
    if (config->extradata_size) {
        d->codec->extradata = av_mallocz(config->extradata_size + AV_INPUT_BUFFER_PADDING_SIZE);
        if (!d->codec->extradata)
            goto fail;
        memcpy(d->codec->extradata, config->extradata, config->extradata_size);
        d->codec->extradata_size = config->extradata_size;
    }
    if (config->hardware) {
        enum AVHWDeviceType type = av_hwdevice_find_type_by_name("nvtegra");
        d->hardware_format = AV_PIX_FMT_NONE;
        for (int i = 0;; ++i) {
            const AVCodecHWConfig *hw = avcodec_get_hw_config(codec, i);
            if (!hw)
                break;
            if (hw->device_type == type &&
                (hw->methods & AV_CODEC_HW_CONFIG_METHOD_HW_DEVICE_CTX)) {
                d->hardware_format = hw->pix_fmt;
                break;
            }
        }
        int opened = type == AV_HWDEVICE_TYPE_NONE || d->hardware_format == AV_PIX_FMT_NONE
            ? AVERROR(ENOSYS)
            : av_hwdevice_ctx_create(&d->codec->hw_device_ctx, type, NULL, NULL, 0);
        if (opened == AVERROR(ENOMEM)) goto fail; /* Bounded local allocation guard. */
        if (opened < 0) {
            /* Original VAAPI factory tries its backends then accepts software
             * when offered. Capability failure does not disable config field 7. */
            av_buffer_unref(&d->codec->hw_device_ctx);
            d->hardware_format = AV_PIX_FMT_NONE;
        } else {
            d->codec->extra_hw_frames = 6;
        }
    }
    d->info = config->info;
    d->info_context = config->info_context;
    int opened = avcodec_open2(d->codec, codec, NULL);
    d->info = NULL;
    d->info_context = NULL;
    if (opened < 0) {
        failure = opened == AVERROR(ENOMEM) ? SL_VIDEO_OPEN_GUARD : SL_VIDEO_OPEN_UNAVAILABLE;
        goto fail;
    }
    d->parser = av_parser_init(AV_CODEC_ID_H264);
    if (!d->parser) goto fail;
    d->parser->flags |= PARSER_FLAG_COMPLETE_FRAMES;
    d->occupied = true;
    d->stopped = false;
    pthread_mutex_lock(&p->mailbox);
    bool accepted = !p->cancelled && !p->frozen;
    p->accepting = accepted;
    d->stopped = !accepted;
    pthread_mutex_unlock(&p->mailbox);
    pthread_mutex_unlock(&p->decoder);
    return accepted ? SL_VIDEO_OPEN_READY : SL_VIDEO_OPEN_GUARD;
fail:
    if (d->parser) av_parser_close(d->parser);
    d->parser = NULL;
    avcodec_free_context(&d->codec);
    pthread_mutex_unlock(&p->decoder);
    return failure;
}
bool sl_video_has_hardware_context(sl_video_pipeline *p, sl_video_key key) {
    pthread_mutex_lock(&p->decoder);
    domain *d = find_domain(p, key);
    bool hardware = d && d->codec && d->codec->hw_device_ctx && !d->stopped;
    pthread_mutex_unlock(&p->decoder);
    return hardware;
}
/* Caller holds mailbox. References leave the lock before SDK/unref work. */
static sl_video_frame *pop_pending(sl_video_pipeline *p) {
    if (!p->pending_count) return NULL;
    sl_video_frame *frame = p->pending[0];
    --p->pending_count;
    memmove(p->pending, p->pending + 1, p->pending_count * sizeof(*p->pending));
    return frame;
}
static input_job pop_job(sl_video_pipeline *p) {
    input_job job = p->jobs[0];
    --p->job_count;
    memmove(p->jobs,p->jobs+1,p->job_count*sizeof(*p->jobs));
    return job;
}
static void retire_jobs(input_job *jobs, unsigned count, IHS_VideoFrameResult result) {
    for (unsigned n=0;n<count;++n) {
        dropped(jobs[n].ticket,result);
        IHS_FrameTicketRelease(jobs[n].ticket);
    }
}
void sl_video_close(sl_video_pipeline *p, sl_video_key key) {
    sl_video_frame *old[LEASE_COUNT+1];
    input_job jobs[INPUT_JOB_COUNT+1];
    unsigned count = 0, jobCount=0;
    pthread_mutex_lock(&p->mailbox);
    if (same(p->active, key)) {
        p->cancelled = true;
        p->accepting = false;
        while (p->pending_count) old[count++] = pop_pending(p);
        if (p->image) old[count++]=p->image;
        p->image=NULL;
        while (p->job_count) jobs[jobCount++]=pop_job(p);
    }
    pthread_mutex_unlock(&p->mailbox);
    retire_jobs(jobs,jobCount,IHS_VideoFrameResultDroppedReset);
    for (unsigned n = 0; n < count; ++n) sl_resource_release(&old[n]->ref);
}
void sl_video_stop(sl_video_pipeline *p, sl_video_key key) {
    sl_video_close(p, key);
    pthread_mutex_lock(&p->decoder);
    domain *d = find_domain(p, key);
    if (d) {
        av_frame_unref(d->scratch);
        d->stopped = true;
    }
    pthread_mutex_unlock(&p->decoder);
}
void sl_video_discard_buffers(sl_video_pipeline *p, sl_video_key key) {
    pthread_mutex_lock(&p->decoder);
    domain *d = find_domain(p, key);
    if (d && d->codec && !d->stopped && !d->reaping) {
        av_frame_unref(d->scratch);
        /* Original Linux marked FlushPendingData clears encoded fragments in
         * the protocol owner. It neither flushes AVCodec nor drops player
         * objects already queued. Stop/rebuild retires the codec separately. */
    }
    pthread_mutex_unlock(&p->decoder);
}
bool sl_video_is_current(sl_video_pipeline *p, sl_video_key key) {
    pthread_mutex_lock(&p->mailbox);
    bool ok = p->accepting && same(p->active, key);
    pthread_mutex_unlock(&p->mailbox);
    return ok;
}
static bool publish(sl_video_pipeline *p, domain *d, uint64_t *output_seq) {
    AVFrame *src = d->scratch;
    if (!src->opaque_ref || src->opaque_ref->size != sizeof(packet_token))
        return false;
    packet_token *token = (void *)src->opaque_ref->data;
    if (!same(token->key, d->key))
        return false;
    sl_video_frame *frame = NULL;
    for (unsigned i = 0; i < LEASE_COUNT; ++i) {
        bool available = true;
        if (atomic_compare_exchange_strong_explicit(&p->leases[i].available, &available, false,
                                                    memory_order_acquire, memory_order_relaxed)) {
            frame = &p->leases[i];
            break;
        }
    }
    if (!frame) {
        /* The port has twenty fixed leases. Budget eviction is explicit local
         * resource protection, separate from the normal ready-frame policy. */
        pthread_mutex_lock(&p->mailbox);
        sl_video_frame *evicted = pop_pending(p);
        if (evicted && p->counters.replaced != UINT32_MAX) ++p->counters.replaced;
        pthread_mutex_unlock(&p->mailbox);
        if (evicted) {
            sl_resource_release(&evicted->ref);
        }
        for (unsigned i = 0; i < LEASE_COUNT; ++i) {
            bool available = true;
            if (atomic_compare_exchange_strong_explicit(&p->leases[i].available, &available, false,
                                                        memory_order_acquire, memory_order_relaxed)) {
                frame = &p->leases[i];
                break;
            }
        }
    }
    if (!frame) return false;
    if (!IHS_FrameTicketRetain(token->ticket))
        goto fail;
    if (atomic_exchange_explicit(&token->claimed, true, memory_order_acq_rel)) {
        IHS_FrameTicketRelease(token->ticket);
        goto fail; /* ambiguous multiple output: fail explicitly */
    }
    frame->key = token->key;
    frame->ticket = token->ticket;
    frame->input_serial = token->input_serial;
    frame->media_timestamp = token->media_timestamp;
    frame->has_media_timestamp = token->has_media_timestamp;
    frame->decode_begin_us = token->begin_us;
    frame->decode_end_us = now_us();
    frame->domain = d;
    av_buffer_unref(&src->opaque_ref);
    av_frame_move_ref(frame->pixels, src);
    atomic_fetch_add_explicit(&d->external, 1, memory_order_relaxed);
    sl_resource_init(&frame->ref, release_frame, frame);
    pthread_mutex_lock(&p->mailbox);
    bool accepted = p->accepting && same(p->active, d->key);
    if (accepted && p->publish_seq == UINT64_MAX) accepted = false;
    if (accepted) {
        frame->publish_seq = ++p->publish_seq;
        if (output_seq) *output_seq = frame->publish_seq;
        p->publications[frame->publish_seq % SL_PUBLICATIONS] =
            (sl_publication){frame->publish_seq, now_us()};
#if NSL_DIAGNOSTICS
        uint64_t stamp = now_us();
        if (p->last_publish_us) {
            uint64_t gap = stamp - p->last_publish_us;
            p->counters.publish_short += gap < 8000;
            p->counters.publish_long += gap > 25000;
            if (gap > p->counters.publish_gap_max_us)
                p->counters.publish_gap_max_us = gap;
        }
        p->last_publish_us = stamp;
        ++p->published_since_take;
#endif
        assert(p->pending_count < LEASE_COUNT);
        p->pending[p->pending_count++] = frame;
        if (p->counters.decoded != UINT32_MAX)
            ++p->counters.decoded;
        uint64_t elapsed = frame->decode_end_us - frame->decode_begin_us;
        p->counters.decode_total_us += elapsed;
        if (elapsed > p->counters.decode_max_us)
            p->counters.decode_max_us = elapsed > UINT32_MAX ? UINT32_MAX : elapsed;
    }
    pthread_mutex_unlock(&p->mailbox);
    if (!accepted)
        sl_resource_release(&frame->ref);
    return true;
fail:
    atomic_store_explicit(&frame->available, true, memory_order_release);
    return false;
}
static int receive_one(sl_video_pipeline *p, domain *d, uint64_t *seq, bool *valid_size, bool *guard) {
    *seq = 0;
    *valid_size = false;
    *guard = false;
    int result = avcodec_receive_frame(d->codec, d->scratch);
    if (result != 0) return result;
    AVFrame *frame = d->scratch;
    *valid_size = frame->width > 0 && frame->height > 0;
    /* Official FinalDecode checks dimensions/format, not decoded input PTS or
     * missing-reference flags. API-successful unknown formats are metadata-only. */
    bool pixels = *valid_size && (frame->format == AV_PIX_FMT_YUV420P ||
        frame->format == AV_PIX_FMT_YUVJ420P ||
        (d->hardware_format != AV_PIX_FMT_NONE && frame->format == d->hardware_format));
    bool ok = !pixels || publish(p, d, seq);
    *guard = !ok;
    av_frame_unref(frame);
    return ok ? 0 : AVERROR_BUG; /* local identity/ownership/resource guard */
}
static int receive_frames(sl_video_pipeline *p, domain *d) {
    for (unsigned n = 0; n < 256; ++n) {
        uint64_t seq;
        bool valid, guard;
        int result = receive_one(p, d, &seq, &valid, &guard);
        if (result != 0) return result;
    }
    return AVERROR_BUG;
}
sl_video_submit_result sl_video_submit(sl_video_pipeline *p, sl_video_key key,
                                       const unsigned char *data, size_t size,
                                       IHS_FrameTicket *ticket, bool *taken, bool keyframe,
                                       sl_video_feedback_fn feedback, sl_video_info_fn info,
                                       void *feedback_context) {
    *taken = false;
    if ((size && !data) || size > MAX_PACKET || !ticket)
        return SL_VIDEO_SUBMIT_ERROR;
    IHS_FrameIdentity identity = IHS_FrameTicketIdentity(ticket);
    if (identity.sessionId != key.session || identity.epoch != key.epoch)
        return SL_VIDEO_SUBMIT_ERROR;
    pthread_mutex_lock(&p->decoder);
    domain *d = find_domain(p, key);
    if (!d || d->stopped || !sl_video_is_current(p, key))
        goto fail;
    /* A mark purges encoded fragments in the protocol owner. The AVCodec
     * backend retains its state; an asynchronous reset rebuilds it separately. */
    if (keyframe) {
        av_frame_unref(d->scratch);
    }
    AVPacket *packet = av_packet_alloc();
    if (!packet)
        goto fail;
    if (av_new_packet(packet, (int)size) < 0) {
        av_packet_free(&packet);
        goto fail;
    }
    if (size) memcpy(packet->data, data, size);
    uint8_t *parsed = NULL;
    int parsed_size = 0;
    int consumed = av_parser_parse2(d->parser, d->codec, &parsed, &parsed_size,
        packet->data, (int)size, AV_NOPTS_VALUE, AV_NOPTS_VALUE, AV_NOPTS_VALUE);
    if (consumed != (int)size) {
        dropped(ticket, IHS_VideoFrameResultDroppedDecodeCorrupt);
        av_packet_free(&packet);
        pthread_mutex_unlock(&p->decoder);
        return SL_VIDEO_SUBMIT_OK; /* original parser rejection: no Put/DataLost */
    }
    if (parsed_size < 0 || (unsigned)parsed_size > MAX_PACKET ||
        (parsed_size && (!parsed || (parsed == packet->data && (size_t)parsed_size > size)))) {
        av_packet_free(&packet);
        goto fail;
    }
    if (parsed_size && parsed != packet->data) {
        AVPacket *copy = av_packet_alloc();
        if (!copy || av_new_packet(copy, parsed_size) < 0) {
            av_packet_free(&copy);
            av_packet_free(&packet);
            goto fail;
        }
        memcpy(copy->data, parsed, parsed_size);
        av_packet_free(&packet);
        packet = copy;
    }
    packet->size = parsed_size;
    if (!parsed_size && !parsed) av_packet_unref(packet); /* preserve parser's NULL/zero output */
    packet_token *token = av_mallocz(sizeof(*token));
    if (!token) {
        av_free(token);
        av_packet_free(&packet);
        goto fail;
    }
    if (!IHS_FrameTicketRetain(ticket)) {
        av_free(token);
        av_packet_free(&packet);
        goto fail;
    }
    *taken = true;
    token->ticket = ticket;
    token->key = key;
    token->has_media_timestamp = IHS_FrameTicketVideoTimestamp(ticket, &token->media_timestamp);
    token->begin_us = now_us();
    token->input_serial = identity.receiveSerial; /* local opaque identity only */
#if NSL_DIAGNOSTICS
    pthread_mutex_lock(&p->mailbox);
    if (same(p->active, key)) {
        ++p->counters.submits;
        p->counters.submit_bytes += size;
        if (p->last_submit_us) {
            uint64_t gap = token->begin_us - p->last_submit_us;
            p->counters.submit_long += gap > 25000;
            if (gap > p->counters.submit_gap_max_us)
                p->counters.submit_gap_max_us = gap;
        }
        p->last_submit_us = token->begin_us;
    }
    pthread_mutex_unlock(&p->mailbox);
#endif
    atomic_init(&token->claimed, false);
    packet->opaque_ref = av_buffer_create((uint8_t *)token, sizeof(*token), free_token, NULL, 0);
    if (!packet->opaque_ref) {
        free_token(NULL, (void *)token);
        av_packet_free(&packet);
        goto fail;
    }
    /* Keep the packet/token live through receive and Put; send failure still
     * reaches one receive and never drains/retries the same compressed packet. */
    d->info = info;
    d->info_context = feedback_context;
    int sent = avcodec_send_packet(d->codec, packet);
    sl_video_submit_result status = sent ? SL_VIDEO_SUBMIT_RESET : SL_VIDEO_SUBMIT_OK;
    if (sent == AVERROR(EIO)) status |= SL_VIDEO_SUBMIT_DISABLE_HARDWARE;
    if (feedback && (status & SL_VIDEO_SUBMIT_RESET))
        feedback(feedback_context, status);
    uint64_t output_seq;
    bool valid_size, guard;
    int result = receive_one(p, d, &output_seq, &valid_size, &guard);
    d->info = NULL;
    d->info_context = NULL;
    if (guard) {
        dropped(ticket, IHS_VideoFrameResultDroppedDecodeCorrupt);
        status = SL_VIDEO_SUBMIT_ERROR;
    } else {
        if (result != 0) {
            if (result == AVERROR(EAGAIN)) dropped(ticket, IHS_VideoFrameResultDroppedReset);
            dropped(ticket, IHS_VideoFrameResultDroppedDecodeCorrupt);
            status = (status & (SL_VIDEO_SUBMIT_RESET | SL_VIDEO_SUBMIT_DISABLE_HARDWARE)) |
                     SL_VIDEO_SUBMIT_CORRUPT;
        }
        if (feedback && (status & SL_VIDEO_SUBMIT_CORRUPT))
            feedback(feedback_context, SL_VIDEO_SUBMIT_CORRUPT);
        if (result != 0) av_frame_unref(d->scratch);
        if (result != 0 || valid_size) {
            if (!queue_task(p,d,ticket,token->has_media_timestamp,token->media_timestamp,
                                output_seq,output_seq == 0))
                status = SL_VIDEO_SUBMIT_ERROR;
        }
    }
    av_packet_free(&packet);
    pthread_mutex_unlock(&p->decoder);
    return status;
fail:
    pthread_mutex_unlock(&p->decoder);
    return SL_VIDEO_SUBMIT_ERROR;
}
bool sl_video_flush(sl_video_pipeline *p, sl_video_key key) {
    pthread_mutex_lock(&p->decoder);
    domain *d = find_domain(p, key);
    bool ok = d && !d->stopped && avcodec_send_packet(d->codec, NULL) >= 0;
    if (ok)
        ok = receive_frames(p, d) == AVERROR_EOF;
    pthread_mutex_unlock(&p->decoder);
    return ok;
}
int32_t sl_video_wait(sl_video_pipeline *p) {
    pthread_mutex_lock(&p->mailbox);
    input_job *head = p->job_count ? &p->jobs[0] : NULL;
    int32_t wait = head ? (head->has_timestamp ?
        sl_video_timing_wait(&p->timing,head->media_timestamp,IHS_SessionPacketTimestamp()) : 0) : -1;
    pthread_mutex_unlock(&p->mailbox);
    return wait;
}
#if NSL_DIAGNOSTICS
static void observe_take(sl_video_pipeline *p) {
    uint64_t stamp = now_us();
    if (p->accepting) {
        p->counters.take_empty += p->published_since_take == 0;
        p->counters.take_one += p->published_since_take == 1;
        p->counters.take_many += p->published_since_take > 1;
        if (p->last_take_us && stamp - p->last_take_us > p->counters.take_gap_max_us)
            p->counters.take_gap_max_us = stamp - p->last_take_us;
        p->last_take_us = stamp;
    }
    p->published_since_take = 0;
}
#endif
bool sl_video_select(sl_video_pipeline *p, sl_video_selection *out) {
    input_job skipped[INPUT_JOB_COUNT];unsigned count=0;
    sl_video_frame *discarded[LEASE_COUNT+1];unsigned discardedCount=0;
    *out=(sl_video_selection){0};
    input_job selected={0};
    pthread_mutex_lock(&p->mailbox);
#if NSL_DIAGNOSTICS
    observe_take(p);
#endif
    if (!p->accepting) goto done;
    uint32_t now=IHS_SessionPacketTimestamp();
    while (p->job_count) {
        input_job *head=&p->jobs[0];
        if (head->has_timestamp && !sl_video_timing_ready(&p->timing,head->media_timestamp,now)) break;
        if (selected.ticket) skipped[count++]=selected;
        selected=pop_job(p);
    }
    if (!selected.ticket) goto done;
    sl_video_frame *chosen=NULL;
    while (p->pending_count && p->pending[0]->publish_seq <= selected.output_seq) {
        sl_video_frame *frame=pop_pending(p);
        if (!selected.placeholder && frame->publish_seq==selected.output_seq) chosen=frame;
        else discarded[discardedCount++]=frame;
    }
    if (p->image) discarded[discardedCount++]=p->image;
    p->image=chosen;
    bool held_image=!p->image || sl_resource_retain(&p->image->ref);
    out->frame=held_image?p->image:NULL;out->ticket=selected.ticket;out->key=selected.key;
    out->media_timestamp=selected.media_timestamp;
done:
    if (p->counters.replaced<=UINT32_MAX-count) p->counters.replaced+=count;
    else p->counters.replaced=UINT32_MAX;
    pthread_mutex_unlock(&p->mailbox);
    retire_jobs(skipped,count,IHS_VideoFrameResultDroppedLate);
    if (out->ticket && !selected.placeholder && !out->frame)
        dropped(out->ticket,IHS_VideoFrameResultDroppedLate); /* explicit local lease eviction */
    for (unsigned n=0;n<discardedCount;++n) sl_resource_release(&discarded[n]->ref);
    return out->ticket!=NULL;
}
void sl_video_selection_complete(sl_video_selection *s,const IHS_FrameOutcome *outcome) {
    if (s->ticket) IHS_FrameTicketComplete(s->ticket,outcome);
}
void sl_video_selection_release(sl_video_selection *s) {
    if (s->ticket) {
        dropped(s->ticket,IHS_VideoFrameResultDroppedReset);
        IHS_FrameTicketRelease(s->ticket);
    }
    if (s->frame) sl_resource_release(&s->frame->ref);
    *s=(sl_video_selection){0};
}
sl_video_frame *sl_video_take(sl_video_pipeline *p) {
    sl_video_frame *discarded[LEASE_COUNT], *frame = NULL;
    unsigned count = 0;
    pthread_mutex_lock(&p->mailbox);
#if NSL_DIAGNOSTICS
    observe_take(p);
#endif
    uint32_t now = IHS_SessionPacketTimestamp();
    while (p->pending_count) {
        sl_video_frame *head = p->pending[0];
        if (head->has_media_timestamp &&
            !sl_video_timing_ready(&p->timing, head->media_timestamp, now)) break;
        if (frame) discarded[count++] = frame;
        frame = pop_pending(p);
    }
    if (p->counters.replaced <= UINT32_MAX - count) p->counters.replaced += count;
    else p->counters.replaced = UINT32_MAX;
    pthread_mutex_unlock(&p->mailbox);
    for (unsigned n = 0; n < count; ++n) {
        sl_resource_release(&discarded[n]->ref);
    }
    return frame;
}
void sl_video_frame_complete(sl_video_frame *frame, const IHS_FrameOutcome *outcome) {
    IHS_FrameTicketComplete(frame->ticket, outcome);
}
void sl_video_reap(sl_video_pipeline *p) {
    for (unsigned i = 0; i < DOMAIN_COUNT; ++i) {
        pthread_mutex_lock(&p->decoder);
        domain *d = &p->domains[i];
        AVCodecContext *codec = NULL;
        AVCodecParserContext *parser = NULL;
        if (d->occupied && d->stopped && !d->reaping &&
            atomic_load_explicit(&d->external, memory_order_acquire) == 0 &&
            atomic_load_explicit(&d->mappings, memory_order_acquire) == 0) {
            d->reaping = true;
            codec = d->codec;
            d->codec = NULL;
            parser = d->parser;
            d->parser = NULL;
        }
        pthread_mutex_unlock(&p->decoder);
        if (!codec)
            continue;
        /* No active B decode can be blocked by A's SDK teardown. The occupied
         * flag prevents A's storage from being reused until destruction returns. */
        av_parser_close(parser);
        avcodec_free_context(&codec);
        pthread_mutex_lock(&p->decoder);
        d->occupied = d->reaping = false;
        pthread_mutex_unlock(&p->decoder);
    }
}
bool sl_video_clean(sl_video_pipeline *p) {
    pthread_mutex_lock(&p->decoder);
    bool clean = true;
    for (unsigned i = 0; i < DOMAIN_COUNT; ++i)
        clean &= !p->domains[i].occupied;
    pthread_mutex_lock(&p->mailbox);
    clean &= !p->job_count && !p->pending_count && !p->image;
    pthread_mutex_unlock(&p->mailbox);
    pthread_mutex_unlock(&p->decoder);
    return clean;
}
bool sl_video_destroy(sl_video_pipeline *p) {
    if (!p)
        return true;
    if (!sl_video_clean(p))
        return false;
    for (unsigned i = 0; i < LEASE_COUNT; ++i)
        if (!atomic_load_explicit(&p->leases[i].available, memory_order_acquire))
            return false;
    for (unsigned i = 0; i < DOMAIN_COUNT; ++i)
        av_frame_free(&p->domains[i].scratch);
    for (unsigned i = 0; i < LEASE_COUNT; ++i)
        av_frame_free(&p->leases[i].pixels);
    pthread_mutex_destroy(&p->decoder);
    pthread_mutex_destroy(&p->mailbox);
    free(p);
    return true;
}

void *sl_video_hold_mapping(sl_video_frame *frame) {
    domain *d = frame->domain;
    atomic_fetch_add_explicit(&d->mappings, 1, memory_order_relaxed);
    return d;
}
void sl_video_release_mapping(void *cookie) {
    domain *d = cookie;
    atomic_fetch_sub_explicit(&d->mappings, 1, memory_order_release);
}

void sl_video_freeze(sl_video_pipeline *p) {
    pthread_mutex_lock(&p->mailbox);
    p->frozen=true;p->cancelled=true;p->accepting=false;
    sl_video_key key=p->active;
    pthread_mutex_unlock(&p->mailbox);
    sl_video_close(p,key);
}
void sl_video_thaw(sl_video_pipeline *p) {
    pthread_mutex_lock(&p->mailbox);
    p->frozen = false;
    pthread_mutex_unlock(&p->mailbox);
}

bool sl_video_read_counters(sl_video_pipeline *p, sl_video_key key, sl_video_counters *out) {
    pthread_mutex_lock(&p->mailbox);
    bool same_key = same(p->active, key);
    if (same_key)
        *out = p->counters;
    pthread_mutex_unlock(&p->mailbox);
    return same_key;
}

bool sl_video_publications(sl_video_pipeline *p, sl_video_key previous, uint64_t after,
                           sl_publication_snapshot *out) {
    if (!p) return false;
    pthread_mutex_lock(&p->mailbox);
    bool active = p->accepting;
    if (active) {
        out->key = p->active;
        out->latest = p->publish_seq;
        out->pending = p->pending_count ? p->pending[p->pending_count - 1]->publish_seq : 0;
        out->count = 0; out->overflow = false;
        if (!same(previous, p->active)) after = 0;
        if (after > p->publish_seq) after = 0;
        if (p->publish_seq - after > SL_PUBLICATIONS) {
            after = p->publish_seq - SL_PUBLICATIONS;
            out->overflow = true;
        }
        while (after < p->publish_seq && out->count < SL_PUBLICATION_READ) {
            ++after;
            out->items[out->count++] = p->publications[after % SL_PUBLICATIONS];
        }
    }
    pthread_mutex_unlock(&p->mailbox);
    return active;
}
