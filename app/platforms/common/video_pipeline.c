#include "video_pipeline.h"
#include "video_timing.h"
#include "session/packet.h"
#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext.h>
#include <libavutil/mem.h>
#include <pthread.h>
#include <assert.h>
#include <stdlib.h>
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
    AVFrame *scratch;
    bool occupied, stopped, reaping;
    atomic_uint external, mappings;
    enum AVPixelFormat hardware_format;
    sl_video_timestamp_state timestamp;
} domain;
typedef struct input_job {
    IHS_FrameTicket *ticket;
    sl_video_key key;
    uint64_t codec_timestamp;
    uint32_t media_timestamp;
    bool has_timestamp, empty;
} input_job;
struct sl_video_pipeline {
    pthread_mutex_t mailbox, decoder;
    domain domains[DOMAIN_COUNT];
    sl_video_frame leases[LEASE_COUNT];
    sl_video_frame *pending[LEASE_COUNT];
    unsigned pending_count;
    sl_video_timing timing;
    input_job jobs[INPUT_JOB_COUNT], waiting;
    unsigned job_count;
    bool waiting_output;
    uint64_t requested_timestamp;
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
    uint64_t codec_timestamp;
    atomic_bool claimed, accepted;
} packet_token;
static uint64_t now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
static bool same(sl_video_key a, sl_video_key b) {
    return a.session == b.session && a.epoch == b.epoch;
}
/* Official PutVideoFrame samples after accepted SDK input, before the
 * renderer maps/waits for decoder output. Codec output latency is independent. */
static bool accepted_input(sl_video_pipeline *p, domain *d, IHS_FrameTicket *ticket,
                           bool hasTimestamp, uint32_t timestamp, uint64_t *codecTimestamp, bool empty) {
    if (!IHS_FrameTicketRetain(ticket)) return false;
    uint64_t pts = hasTimestamp ? sl_video_timestamp_next(&d->timestamp, timestamp)
                               : IHS_FrameTicketIdentity(ticket).receiveSerial;
    if (codecTimestamp) *codecTimestamp = pts;
    pthread_mutex_lock(&p->mailbox);
    bool active = p->accepting && same(p->active,d->key) && p->job_count < INPUT_JOB_COUNT;
    if (active) {
        if (hasTimestamp) sl_video_timing_update(&p->timing,timestamp,IHS_SessionPacketTimestamp(),false);
        p->jobs[p->job_count++] = (input_job){ticket,d->key,pts,timestamp,hasTimestamp,empty};
    }
    pthread_mutex_unlock(&p->mailbox);
    if (!active) IHS_FrameTicketRelease(ticket);
    IHS_FrameTicketVideoDecodeStage(ticket, true);
    return active;
}
static void dropped(IHS_FrameTicket *ticket, IHS_VideoFrameResult reason) {
    IHS_FrameOutcome result = {.result = reason, .completionUs = now_us()};
    IHS_FrameTicketComplete(ticket, &result);
}
static void free_token(void *unused, uint8_t *data) {
    (void)unused;
    packet_token *token = (void *)data;
    if (!atomic_exchange_explicit(&token->claimed, true, memory_order_acq_rel) &&
        !atomic_load_explicit(&token->accepted, memory_order_acquire))
        dropped(token->ticket, IHS_VideoFrameResultDroppedDecodeCorrupt);
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
    for (; *formats != AV_PIX_FMT_NONE; ++formats)
        if (*formats == d->hardware_format)
            return *formats;
    return AV_PIX_FMT_NONE; /* hardware import failures cannot hide behind download */
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
        p->requested_timestamp = 0;
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
    d->timestamp = (sl_video_timestamp_state){0};
    d->codec->width = config->width;
    d->codec->height = config->height;
    d->codec->thread_count = 1;
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
        if (opened < 0) {
            failure = opened == AVERROR(ENOMEM) ? SL_VIDEO_OPEN_GUARD : SL_VIDEO_OPEN_UNAVAILABLE;
            goto fail;
        }
        d->codec->opaque = d;
        d->codec->get_format = hardware_format;
        d->codec->extra_hw_frames = 6;
    }
    int opened = avcodec_open2(d->codec, codec, NULL);
    if (opened < 0) {
        failure = opened == AVERROR(ENOMEM) ? SL_VIDEO_OPEN_GUARD : SL_VIDEO_OPEN_UNAVAILABLE;
        goto fail;
    }
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
    avcodec_free_context(&d->codec);
    pthread_mutex_unlock(&p->decoder);
    return failure;
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
        if (p->waiting.ticket) jobs[jobCount++]=p->waiting;
        p->waiting=(input_job){0};p->waiting_output=false;
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
    sl_video_frame *old[LEASE_COUNT];unsigned count=0;
    pthread_mutex_lock(&p->decoder);
    domain *d = find_domain(p, key);
    if (d && d->codec && !d->stopped && !d->reaping) {
        av_frame_unref(d->scratch);
        avcodec_flush_buffers(d->codec);
        pthread_mutex_lock(&p->mailbox);
        if (same(p->active,key)) while (p->pending_count) old[count++]=pop_pending(p);
        pthread_mutex_unlock(&p->mailbox);
    }
    pthread_mutex_unlock(&p->decoder);
    for (unsigned n=0;n<count;++n) sl_resource_release(&old[n]->ref);
}
bool sl_video_is_current(sl_video_pipeline *p, sl_video_key key) {
    pthread_mutex_lock(&p->mailbox);
    bool ok = p->accepting && same(p->active, key);
    pthread_mutex_unlock(&p->mailbox);
    return ok;
}
static bool publish(sl_video_pipeline *p, domain *d) {
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
    frame->codec_timestamp = token->codec_timestamp;
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
static int receive_frames(sl_video_pipeline *p, domain *d) {
    for (unsigned n = 0; n < 256; ++n) {
        int result = avcodec_receive_frame(d->codec, d->scratch);
        if (result == AVERROR(EAGAIN) || result == AVERROR_EOF)
            return result;
        if (result < 0)
            return result;
        if ((d->scratch->flags & AV_FRAME_FLAG_CORRUPT) || d->scratch->decode_error_flags) {
            av_frame_unref(d->scratch);
            return AVERROR_INVALIDDATA;
        }
        bool ok = publish(p, d);
        av_frame_unref(d->scratch);
        if (!ok)
            return AVERROR_BUG; /* identity/ownership/resource failure is NOT codec corruption */
    }
    return AVERROR_BUG;
}
sl_video_submit_result sl_video_submit(sl_video_pipeline *p, sl_video_key key,
                                       const unsigned char *data, size_t size,
                                       IHS_FrameTicket *ticket, bool *taken, bool keyframe) {
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
    /* Complete-frame compatibility callers can request this fallback. The
     * production protocol path already flushes at the first marked fragment
     * and suppresses it here. Caller-held AVFrame/map references stay valid. */
    if (keyframe) {
        av_frame_unref(d->scratch);
        avcodec_flush_buffers(d->codec);
    }
    /* A fully padded video fragment can complete an empty frame. The original
     * SDK call uses size=0/flags=0; FFmpeg uses NULL/zero packets for drain/EOF. Consume
     * this protocol input without draining the codec or creating a pixel/token.
     * Endpoint metadata remains pending until ordinary expiration/close. */
    if (!size) {
        uint32_t mediaTimestamp;
        bool hasTimestamp = IHS_FrameTicketVideoTimestamp(ticket,&mediaTimestamp);
        bool accepted = accepted_input(p,d,ticket,hasTimestamp,hasTimestamp ? mediaTimestamp : 0,NULL,true);
        pthread_mutex_unlock(&p->decoder);
        return accepted ? SL_VIDEO_SUBMIT_OK : SL_VIDEO_SUBMIT_ERROR;
    }
    AVPacket *packet = av_packet_alloc();
    if (!packet)
        goto fail;
    packet_token *token = av_mallocz(sizeof(*token));
    if (!token || av_new_packet(packet, (int)size) < 0) {
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
    atomic_init(&token->accepted, false);
    packet->opaque_ref = av_buffer_create((uint8_t *)token, sizeof(*token), free_token, NULL, 0);
    if (!packet->opaque_ref) {
        free_token(NULL, (void *)token);
        av_packet_free(&packet);
        goto fail;
    }
    memcpy(packet->data, data, size);
    packet->pts = (int64_t)identity.receiveSerial;
    int result = avcodec_send_packet(d->codec, packet);
    if (result == AVERROR(EAGAIN)) {
        int drained = receive_frames(p, d);
        if (drained == AVERROR(EAGAIN))
            result = avcodec_send_packet(d->codec, packet);
        else
            result = drained;
    }
    if (result >= 0) {
        bool accepted = accepted_input(p,d,ticket,token->has_media_timestamp,token->media_timestamp,&token->codec_timestamp,false);
        atomic_store_explicit(&token->accepted,true,memory_order_release);
        if (!accepted) result=AVERROR(ENOMEM);
    }
    av_packet_free(&packet);
    sl_video_submit_result status = SL_VIDEO_SUBMIT_ERROR;
    if (result >= 0) {
        result = receive_frames(p, d);
        if (result == AVERROR(EAGAIN) || result == AVERROR_EOF)
            status = SL_VIDEO_SUBMIT_OK;
    }
    if (result == AVERROR_INVALIDDATA)
        status = SL_VIDEO_SUBMIT_CORRUPT;
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
    int32_t wait = p->waiting.ticket ? 0 : head ? (head->has_timestamp ?
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
    pthread_mutex_lock(&p->mailbox);
#if NSL_DIAGNOSTICS
    observe_take(p);
#endif
    if (!p->accepting) goto done;
    if (!p->waiting.ticket) {
        uint32_t now=IHS_SessionPacketTimestamp();
        while (p->job_count) {
            input_job *head=&p->jobs[0];
            if (head->has_timestamp && !sl_video_timing_ready(&p->timing,head->media_timestamp,now)) break;
            if (p->waiting.ticket) skipped[count++]=p->waiting;
            p->waiting=pop_job(p);
        }
        if (!p->waiting.ticket) goto done;
        p->waiting_output=p->waiting.codec_timestamp > p->requested_timestamp;
        if (p->waiting_output) p->requested_timestamp=p->waiting.codec_timestamp;
        if (!p->pending_count && p->image && p->image->codec_timestamp==p->waiting.codec_timestamp)
            p->waiting_output=false; /* already acquired actual target pixels */
    }
    if (p->waiting_output && p->waiting.empty && !p->pending_count)
        p->waiting_output=false; /* metadata-only input has no FFmpeg pixel */
    if (p->waiting_output) {
        /* Polling an empty FFmpeg output queue is not an NDK timeout. Keep the
         * selected task while normal UI drawing continues; no EAGAIN flush. */
        if (!p->pending_count) goto done;
        sl_video_frame *chosen=NULL;
        while (p->pending_count) {
            if (chosen) discarded[discardedCount++]=chosen;
            chosen=pop_pending(p);
            if (chosen->codec_timestamp==p->waiting.codec_timestamp) break;
        }
        if (p->image) discarded[discardedCount++]=p->image;
        p->image=chosen;
    }
    if (p->image && !sl_resource_retain(&p->image->ref)) goto done;
    out->frame=p->image;out->ticket=p->waiting.ticket;out->key=p->waiting.key;
    out->media_timestamp=p->waiting.media_timestamp;
    p->waiting=(input_job){0};p->waiting_output=false;
done:
    if (p->counters.replaced<=UINT32_MAX-count) p->counters.replaced+=count;
    else p->counters.replaced=UINT32_MAX;
    pthread_mutex_unlock(&p->mailbox);
    retire_jobs(skipped,count,IHS_VideoFrameResultDroppedLate);
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
        if (d->occupied && d->stopped && !d->reaping &&
            atomic_load_explicit(&d->external, memory_order_acquire) == 0 &&
            atomic_load_explicit(&d->mappings, memory_order_acquire) == 0) {
            d->reaping = true;
            codec = d->codec;
            d->codec = NULL;
        }
        pthread_mutex_unlock(&p->decoder);
        if (!codec)
            continue;
        /* No active B decode can be blocked by A's SDK teardown. The occupied
         * flag prevents A's storage from being reused until destruction returns. */
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
    clean &= !p->job_count && !p->waiting.ticket && !p->pending_count && !p->image;
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
