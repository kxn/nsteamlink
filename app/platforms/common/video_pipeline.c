#include "video_pipeline.h"
#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext.h>
#include <libavutil/mem.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DOMAIN_COUNT 2
#define LEASE_COUNT  6
#define MAX_PACKET   (2u * 1024u * 1024u)
typedef struct domain {
    sl_video_key key;
    AVCodecContext *codec;
    AVFrame *scratch;
    bool occupied, stopped, reaping;
    atomic_uint external, mappings;
    enum AVPixelFormat hardware_format;
} domain;
struct sl_video_pipeline {
    pthread_mutex_t mailbox, decoder;
    domain domains[DOMAIN_COUNT];
    sl_video_frame leases[LEASE_COUNT];
    sl_video_frame *pending;
    sl_video_key active;
    bool accepting;
    bool cancelled, frozen;
    sl_video_counters counters;
};
typedef struct packet_token {
    IHS_FrameTicket *ticket;
    sl_video_key key;
    uint64_t begin_us;
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
static void dropped(IHS_FrameTicket *ticket, IHS_VideoFrameResult reason) {
    IHS_FrameOutcome result = {.result = reason, .completionUs = now_us()};
    IHS_FrameTicketComplete(ticket, &result);
}
static void free_token(void *unused, uint8_t *data) {
    (void)unused;
    packet_token *token = (void *)data;
    if (!atomic_exchange_explicit(&token->claimed, true, memory_order_acq_rel))
        dropped(token->ticket, IHS_VideoFrameResultDroppedDecodeCorrupt);
    IHS_FrameTicketRelease(token->ticket);
    av_free(token);
}
static void release_frame(void *context) {
    sl_video_frame *frame = context;
    domain *d = frame->domain;
    dropped(frame->ticket, IHS_VideoFrameResultDroppedReset);
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
    if (!key.session || !key.epoch || !config || !config->width || !config->height ||
        config->width > 1920 || config->height > 1080 || config->extradata_size > MAX_PACKET ||
        (config->extradata_size && !config->extradata))
        return false;
    pthread_mutex_lock(&p->decoder);
    pthread_mutex_lock(&p->mailbox);
    bool admissible = !p->frozen && !p->accepting &&
                      (!p->active.session || key.session > p->active.session ||
                       (key.session == p->active.session && key.epoch > p->active.epoch));
    if (admissible) {
        p->active = key;
        p->cancelled = false;
        p->counters = (sl_video_counters){0};
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
        return false;
    }
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    d->codec = codec ? avcodec_alloc_context3(codec) : NULL;
    if (!d->codec)
        goto fail;
    d->key = key;
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
        if (type == AV_HWDEVICE_TYPE_NONE || d->hardware_format == AV_PIX_FMT_NONE ||
            av_hwdevice_ctx_create(&d->codec->hw_device_ctx, type, NULL, NULL, 0) < 0)
            goto fail;
        d->codec->opaque = d;
        d->codec->get_format = hardware_format;
        d->codec->extra_hw_frames = 6;
    }
    if (avcodec_open2(d->codec, codec, NULL) < 0)
        goto fail;
    d->occupied = true;
    d->stopped = false;
    pthread_mutex_lock(&p->mailbox);
    bool accepted = !p->cancelled && !p->frozen;
    p->accepting = accepted;
    d->stopped = !accepted;
    pthread_mutex_unlock(&p->mailbox);
    pthread_mutex_unlock(&p->decoder);
    return accepted;
fail:
    avcodec_free_context(&d->codec);
    pthread_mutex_unlock(&p->decoder);
    return false;
}
void sl_video_close(sl_video_pipeline *p, sl_video_key key) {
    sl_video_frame *old = NULL;
    pthread_mutex_lock(&p->mailbox);
    if (same(p->active, key)) {
        p->cancelled = true;
        p->accepting = false;
        old = p->pending;
        p->pending = NULL;
    }
    pthread_mutex_unlock(&p->mailbox);
    if (old)
        sl_resource_release(&old->ref);
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
    if (!frame)
        return false;
    if (!IHS_FrameTicketRetain(token->ticket))
        goto fail;
    if (atomic_exchange_explicit(&token->claimed, true, memory_order_acq_rel)) {
        IHS_FrameTicketRelease(token->ticket);
        goto fail; /* ambiguous multiple output: fail explicitly */
    }
    frame->key = token->key;
    frame->ticket = token->ticket;
    frame->decode_begin_us = token->begin_us;
    frame->decode_end_us = now_us();
    IHS_FrameTicketDecodeStage(frame->ticket, true, frame->decode_end_us);
    frame->domain = d;
    av_buffer_unref(&src->opaque_ref);
    av_frame_move_ref(frame->pixels, src);
    atomic_fetch_add_explicit(&d->external, 1, memory_order_relaxed);
    sl_resource_init(&frame->ref, release_frame, frame);
    pthread_mutex_lock(&p->mailbox);
    sl_video_frame *old = NULL;
    bool accepted = p->accepting && same(p->active, d->key);
    if (accepted) {
        old = p->pending;
        p->pending = frame;
        if (p->counters.decoded != UINT32_MAX)
            ++p->counters.decoded;
        if (old && p->counters.replaced != UINT32_MAX)
            ++p->counters.replaced;
        uint64_t elapsed = frame->decode_end_us - frame->decode_begin_us;
        p->counters.decode_total_us += elapsed;
        if (elapsed > p->counters.decode_max_us)
            p->counters.decode_max_us = elapsed > UINT32_MAX ? UINT32_MAX : elapsed;
    }
    pthread_mutex_unlock(&p->mailbox);
    if (old)
        sl_resource_release(&old->ref);
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
        bool ok = publish(p, d);
        av_frame_unref(d->scratch);
        if (!ok)
            return AVERROR_INVALIDDATA;
    }
    return AVERROR_INVALIDDATA;
}
bool sl_video_submit(sl_video_pipeline *p, sl_video_key key, const unsigned char *data, size_t size,
                     IHS_FrameTicket *ticket, bool *taken) {
    *taken = false;
    if (!data || !size || size > MAX_PACKET || !ticket)
        return false;
    IHS_FrameIdentity identity = IHS_FrameTicketIdentity(ticket);
    if (identity.sessionId != key.session || identity.epoch != key.epoch)
        return false;
    pthread_mutex_lock(&p->decoder);
    domain *d = find_domain(p, key);
    if (!d || d->stopped || !sl_video_is_current(p, key))
        goto fail;
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
    token->begin_us = now_us();
    IHS_FrameTicketDecodeStage(ticket, false, token->begin_us);
    atomic_init(&token->claimed, false);
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
    av_packet_free(&packet);
    if (result < 0)
        goto fail;
    result = receive_frames(p, d);
    pthread_mutex_unlock(&p->decoder);
    return result == AVERROR(EAGAIN) || result == AVERROR_EOF;
fail:
    pthread_mutex_unlock(&p->decoder);
    return false;
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
sl_video_frame *sl_video_take(sl_video_pipeline *p) {
    pthread_mutex_lock(&p->mailbox);
    sl_video_frame *frame = p->pending;
    p->pending = NULL;
    pthread_mutex_unlock(&p->mailbox);
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
    p->frozen = true;
    p->cancelled = true;
    p->accepting = false;
    sl_video_frame *old = p->pending;
    p->pending = NULL;
    pthread_mutex_unlock(&p->mailbox);
    if (old)
        sl_resource_release(&old->ref);
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
