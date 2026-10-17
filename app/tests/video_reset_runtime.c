/* Use the production runtime callback table, media, real FFmpeg and IHS worker.
 * Initial avcodec_open2 failure and one submit result are declared platform
 * inputs. This verifies local ownership of actual pixels/tickets/map leases;
 * it does not derive a MediaCodec -> AVERROR mapping or exercise a real GPU. */
#include "../platforms/common/runtime.c"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "session/channels/ch_control.h"
#include "session/channels/ch_data.h"
#include "session/channels/video/ch_data_video.h"
#include "session/session_pri.h"
#include "test_session.h"
#include <assert.h>
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libavutil/md5.h>
#include <unistd.h>

static sl_video_pipeline *pipeline;
static atomic_uint processed;
static unsigned infos, losses, opens;
static bool failOpen = true;
static atomic_bool requestReset;
static bool watchStop, buffersDiscarded, recoveryMarked;
static unsigned phaseOrder, playerAt, decoderAt, markAt, stopAt, codecFlushAt, codecFreeAt;
void __real_sl_video_close(sl_video_pipeline *, sl_video_key);
void __wrap_sl_video_close(sl_video_pipeline *p, sl_video_key key) {
    if (watchStop)
        playerAt = ++phaseOrder;
    __real_sl_video_close(p, key);
}
void __real_sl_video_discard_buffers(sl_video_pipeline *, sl_video_key);
void __wrap_sl_video_discard_buffers(sl_video_pipeline *p, sl_video_key key) {
    if (watchStop) {
        assert(playerAt && !recoveryMarked);
        decoderAt = ++phaseOrder;
    }
    __real_sl_video_discard_buffers(p, key);
    if (watchStop)
        buffersDiscarded = true;
}
void __real_sl_video_stop(sl_video_pipeline *, sl_video_key);
void __wrap_sl_video_stop(sl_video_pipeline *p, sl_video_key key) {
    if (watchStop) {
        assert(recoveryMarked);
        stopAt = ++phaseOrder;
    }
    __real_sl_video_stop(p, key);
}
void __real_avcodec_flush_buffers(AVCodecContext *);
void __wrap_avcodec_flush_buffers(AVCodecContext *codec) {
    if (watchStop) {
        assert(decoderAt && !recoveryMarked);
        codecFlushAt = ++phaseOrder;
    }
    __real_avcodec_flush_buffers(codec);
}
void __real_avcodec_free_context(AVCodecContext **);
void __wrap_avcodec_free_context(AVCodecContext **codec) {
    if (watchStop && *codec) {
        assert(recoveryMarked && stopAt);
        codecFreeAt = ++phaseOrder;
    }
    __real_avcodec_free_context(codec);
}
static void pixelHash(sl_video_frame *frame, uint8_t hash[16]) {
    uint8_t visible[128 * 72 * 3 / 2];
    assert(av_image_copy_to_buffer(
               visible, sizeof(visible), (const uint8_t *const *)frame->pixels->data,
               frame->pixels->linesize, AV_PIX_FMT_YUV420P, 128, 72, 1) == sizeof(visible));
    av_md5_sum(hash, visible, sizeof(visible));
}
static void unchanged(sl_video_frame *frame, const uint8_t saved[16]) {
    uint8_t actual[16];
    pixelHash(frame, actual);
    assert(!memcmp(saved, actual, 16));
}
sl_video_pipeline *__real_sl_video_create(void);
sl_video_pipeline *__wrap_sl_video_create(void) {
    pipeline = __real_sl_video_create();
    return pipeline;
}
int __real_avcodec_open2(AVCodecContext *, const AVCodec *, AVDictionary **);
int __wrap_avcodec_open2(AVCodecContext *c, const AVCodec *codec, AVDictionary **opts) {
    ++opens;
    if (failOpen) {
        failOpen = false;
        return AVERROR(EIO);
    }
    return __real_avcodec_open2(c, codec, opts);
}
IHS_StreamVideoSubmitResult __real_sl_media_video_submit_tracked(IHS_Session *,
                                                                 const IHS_VideoEpochInfo *,
                                                                 uint16_t, IHS_FrameTicket *,
                                                                 IHS_Buffer *,
                                                                 IHS_StreamVideoFrameFlag, bool *);
IHS_StreamVideoSubmitResult
__wrap_sl_media_video_submit_tracked(IHS_Session *s, const IHS_VideoEpochInfo *e, uint16_t id,
                                     IHS_FrameTicket *t, IHS_Buffer *b, IHS_StreamVideoFrameFlag f,
                                     bool *taken) {
    if (atomic_exchange(&requestReset, false)) {
        *taken = false;
        return IHS_StreamVideoSubmitReset;
    }
    return __real_sl_media_video_submit_tracked(s, e, id, t, b, f, taken);
}
void __real_IHS_SessionPacketsWindowReleaseFrame(IHS_SessionFrame *);
void __wrap_IHS_SessionPacketsWindowReleaseFrame(IHS_SessionFrame *f) {
    __real_IHS_SessionPacketsWindowReleaseFrame(f);
    atomic_fetch_add(&processed, 1);
}
uint32_t __wrap_IHS_SessionPacketTimestamp(void) {
    if (watchStop && buffersDiscarded && !recoveryMarked) {
        recoveryMarked = true;
        markAt = ++phaseOrder;
    }
    return 1000000;
}
bool __wrap_IHS_BaseSend(IHS_Base *b, IHS_SocketAddress a, const IHS_Buffer *p) {
    (void)b;
    (void)a;
    (void)p;
    return true;
}
bool __real_IHS_SessionSendControlMessage(IHS_Session *, EStreamControlMessage,
                                          const ProtobufCMessage *);
bool __wrap_IHS_SessionSendControlMessage(IHS_Session *s, EStreamControlMessage t,
                                          const ProtobufCMessage *m) {
    if (t == k_EStreamControlVideoDecoderInfo) {
        ++infos;
        return true;
    }
    return __real_IHS_SessionSendControlMessage(s, t, m);
}
void __real_IHS_SessionChannelDataLost(IHS_SessionChannel *);
void __wrap_IHS_SessionChannelDataLost(IHS_SessionChannel *c) {
    ++losses;
    __real_IHS_SessionChannelDataLost(c);
}
static void control(IHS_Session *s, EStreamControlMessage t, const ProtobufCMessage *m) {
    IHS_Buffer b = IHS_BUFFER_INIT(64, 4096);
    IHS_BufferAppendMessage(&b, m);
    IHS_SessionPacketHeader h = {.type = IHS_SessionPacketTypeReliable, .channelId = 1};
    IHS_SessionChannelControlHandoff(s->channels[1], t, &b, &h);
    IHS_SessionChannelControlDrainIncoming(s->channels[1]);
    IHS_BufferClear(&b, true);
}
static unsigned target;
static void feed(IHS_Session *s, uint16_t id, bool key, const uint8_t *bytes, size_t len) {
    IHS_SessionFrame f = {.header = {.type = IHS_SessionPacketTypeReliable,
                                     .channelId = 3,
                                     .sendTimestamp = 1000000,
                                     .receiveTimestamp = 1000000,
                                     .receiveBegin = 1000000}};
    IHS_BufferInit(&f.body, 64, 65536);
    IHS_BufferAppendUInt8(&f.body, k_EStreamDataPacket);
    IHS_BufferAppendUInt16LE(&f.body, id);
    IHS_BufferAppendUInt32LE(&f.body, 1000000);
    IHS_BufferAppendUInt16LE(&f.body, 0);
    IHS_BufferAppendUInt32LE(&f.body, 0);
    IHS_BufferAppendUInt16LE(&f.body, id - 1);
    IHS_BufferAppendUInt8(&f.body, VideoFrameFlagFrameFinish | (key ? VideoFrameFlagKeyFrame : 0));
    IHS_BufferAppendUInt16LE(&f.body, 0);
    IHS_BufferAppendUInt16LE(&f.body, 0);
    IHS_BufferAppendMem(&f.body, bytes, len);
    IHS_SessionDeliverReliableFrame(s, &f);
    IHS_SessionFrameClear(&f, true);
    ++target;
    for (unsigned n = 0; n < 5000 && atomic_load(&processed) < target; ++n)
        usleep(1000);
    assert(atomic_load(&processed) == target);
}
static void reset(sl_runtime *r, unsigned epoch, unsigned expectedOpens, unsigned expectedInfos) {
    bool wasReady = sl_video_is_current(pipeline, (sl_video_key){90, r->facts.epoch});
    phaseOrder = playerAt = decoderAt = markAt = stopAt = codecFlushAt = codecFreeAt = 0;
    buffersDiscarded = recoveryMarked = false;
    watchStop = true;
    r->session->base.callbacks.run->update(&r->session->base,
                                           r->session->base.callbackContexts.run);
    watchStop = false;
    assert(playerAt && decoderAt > playerAt && markAt > decoderAt && stopAt > markAt);
    assert((codecFlushAt != 0) == wasReady);
    if (codecFlushAt)
        assert(codecFlushAt > decoderAt && codecFlushAt < markAt);
    if (codecFreeAt)
        assert(codecFreeAt > stopAt);
    assert(r->facts.epoch == epoch && !r->facts.paused && !r->session->base.interrupted);
    assert(opens == expectedOpens && infos == expectedInfos && losses == epoch - 1);
    stream_media_snapshot snap;
    stream_media_get_snapshot(&snap);
    assert(snap.video_active && snap.video_epoch == epoch && snap.session_id == 90 &&
           !snap.last_error[0]);
}
static sl_video_frame *take(unsigned epoch) {
    sl_video_frame *f = sl_video_take(pipeline);
    assert(f && f->key.session == 90 && f->key.epoch == epoch && f->ticket);
    assert(f->pixels->width == 128 && f->pixels->height == 72 && f->pixels->data[0]);
    return f;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL) && pipeline);
    IHS_Init();
    sl_runtime r = {0};
    pthread_mutex_init(&r.lock, NULL);
    r.facts.session_id = 90;
    r.session = IHS_TestSessionCreate();
    assert(r.session);
    IHS_TimerTaskStopImmediate(r.session->retransmission.timer);
    r.session->state.connectionState = IHS_SessionConnectionStateConnected;
    r.session->negotiatedVideoCodec = k_EStreamVideoCodecH264;
    assert(IHS_SessionSetVideoTrackingIdentity(r.session, 90));
    IHS_SessionSetVideoCallbacks(r.session, &video_cb, &r);
    CStartVideoDataMsg m = CSTART_VIDEO_DATA_MSG__INIT;
    m.channel = 3;
    m.has_width = m.has_height = true;
    m.width = 128;
    m.height = 72;
    control(r.session, k_EStreamControlStartVideoData, &m.base);
    assert(r.facts.epoch == 1 && opens == 1 && infos == 0 && !r.session->base.interrupted);
    FILE *in = fopen(argv[1], "rb");
    assert(in && !fseek(in, 0, SEEK_END));
    long size = ftell(in);
    assert(size > 0 && size < 65536);
    rewind(in);
    uint8_t *input = calloc(1, size + AV_INPUT_BUFFER_PADDING_SIZE);
    assert(input && fread(input, 1, size, in) == (size_t)size);
    fclose(in);
    AVCodecParserContext *parser = av_parser_init(AV_CODEC_ID_H264);
    AVCodecContext *ctx = avcodec_alloc_context3(NULL);
    uint8_t *packet;
    int bytes;
    assert(av_parser_parse2(parser, ctx, &packet, &bytes, input, size, AV_NOPTS_VALUE,
                            AV_NOPTS_VALUE, 0) > 0 &&
           bytes > 0);
    feed(r.session, 1, true, packet, bytes);
    assert(!infos && !losses);
    reset(&r, 2, 2, 1); /* Real initial open failure -> retained actor -> retry succeeds. */
    feed(r.session, 2, true, packet, bytes);
    sl_video_frame *a = take(2);
    uint8_t hashA[16], hashB[16];
    pixelHash(a, hashA);
    void *mapA = sl_video_hold_mapping(a);
    assert(mapA);
    atomic_store(&requestReset, true);
    feed(r.session, 3, false, packet, bytes);
    reset(&r, 3, 3, 2);
    unchanged(a, hashA);
    assert(a->pixels->data[0] && IHS_FrameTicketIdentity(a->ticket).epoch == 2);
    feed(r.session, 4, true, packet, bytes);
    sl_video_frame *b = take(3);
    pixelHash(b, hashB);
    void *mapB = sl_video_hold_mapping(b);
    assert(mapB && mapA != mapB);
    atomic_store(&requestReset, true);
    feed(r.session, 5, false, packet, bytes);
    reset(&r, 4, 3, 2);
    assert(!sl_video_is_current(pipeline, (sl_video_key){90, 4})); /* Both old domains pinned. */
    sl_resource_release(&a->ref); /* Imported map alone must keep old codec domain alive. */
    feed(r.session, 6, true, packet, bytes);
    reset(&r, 5, 3, 2);
    sl_video_release_mapping(mapA);
    feed(r.session, 7, true, packet, bytes);
    reset(&r, 6, 4, 3);
    unchanged(b, hashB);
    assert(b->pixels->data[0] && IHS_FrameTicketIdentity(b->ticket).epoch == 3);
    feed(r.session, 8, true, packet, bytes);
    sl_video_frame *c = take(6);
    CStopVideoDataMsg stop = CSTOP_VIDEO_DATA_MSG__INIT;
    control(r.session, k_EStreamControlStopVideoData, &stop.base);
    assert(r.facts.paused);
    IHS_SessionDestroy(r.session);
    r.session = NULL;
    IHS_Quit();
    assert(!sl_media_video_clean());
    unchanged(b, hashB);
    IHS_FrameOutcome shown = {.result = IHS_VideoFrameResultDisplayed, .presentationSerial = 99};
    sl_video_frame_complete(b, &shown);
    sl_resource_release(&b->ref);
    assert(!sl_media_video_clean()); /* Map B survives even final pixel release. */
    sl_video_release_mapping(mapB);
    sl_resource_release(&c->ref);
    assert(sl_media_video_clean());
    av_parser_close(parser);
    avcodec_free_context(&ctx);
    free(input);
    pthread_mutex_destroy(&r.lock);
    stream_media_shutdown();
    return 0;
}
