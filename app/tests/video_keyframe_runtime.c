/* Production runtime callback table + control parser + real IHS worker/FFmpeg.
 * Split/replaced/repeated key fragments must flush immediately and exactly once
 * per wire mark, preserve the player/epoch and keep old pixels/map leases valid.
 * Bit6 transitions use the real actor; pending requests suppress SDK submission.
 * SDL dummy/software output is used; no physical GPU/Steam/loader claim. */
#include "../platforms/common/runtime.c"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "session/channels/ch_control.h"
#include "session/channels/video/ch_data_video.h"
#include "session/session_pri.h"
#include "test_session.h"
#include <assert.h>
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libavutil/md5.h>
#include <unistd.h>
static sl_video_pipeline *pipeline;
static atomic_uint processed, flushes, sends, losses;
static unsigned target, opens;
sl_video_pipeline *__real_sl_video_create(void);
sl_video_pipeline *__wrap_sl_video_create(void) {
    return pipeline = __real_sl_video_create();
}
int __real_avcodec_open2(AVCodecContext *, const AVCodec *, AVDictionary **);
int __wrap_avcodec_open2(AVCodecContext *c, const AVCodec *codec, AVDictionary **o) {
    ++opens;
    return __real_avcodec_open2(c, codec, o);
}
void __real_avcodec_flush_buffers(AVCodecContext *);
void __wrap_avcodec_flush_buffers(AVCodecContext *c) {
    atomic_fetch_add(&flushes, 1);
    __real_avcodec_flush_buffers(c);
}
int __real_avcodec_send_packet(AVCodecContext *, const AVPacket *);
int __wrap_avcodec_send_packet(AVCodecContext *c, const AVPacket *p) {
    assert(p && p->size == 2204);
    atomic_fetch_add(&sends, 1);
    return __real_avcodec_send_packet(c, p);
}
void __real_IHS_SessionPacketsWindowReleaseFrame(IHS_SessionFrame *);
void __wrap_IHS_SessionPacketsWindowReleaseFrame(IHS_SessionFrame *f) {
    __real_IHS_SessionPacketsWindowReleaseFrame(f);
    atomic_fetch_add(&processed, 1);
}
uint32_t __wrap_IHS_SessionPacketTimestamp(void) {
    return 1000000;
}
bool __wrap_IHS_BaseSend(IHS_Base *b, IHS_SocketAddress a, const IHS_Buffer *p) {
    (void)b;
    (void)a;
    (void)p;
    return true;
}
bool __wrap_IHS_SessionSendControlMessage(IHS_Session *s, EStreamControlMessage t,
                                          const ProtobufCMessage *m) {
    (void)s;
    (void)t;
    (void)m;
    return true;
}
void __real_IHS_SessionChannelDataLost(IHS_SessionChannel *);
void __wrap_IHS_SessionChannelDataLost(IHS_SessionChannel *ch) {
    atomic_fetch_add(&losses, 1);
    __real_IHS_SessionChannelDataLost(ch);
}
static void control(IHS_Session *s, EStreamControlMessage t, const ProtobufCMessage *m) {
    IHS_Buffer b = IHS_BUFFER_INIT(64, 4096);
    IHS_BufferAppendMessage(&b, m);
    IHS_SessionPacketHeader h = {.type = IHS_SessionPacketTypeReliable, .channelId = 1};
    IHS_SessionChannelControlHandoff(s->channels[1], t, &b, &h);
    IHS_SessionChannelControlDrainIncoming(s->channels[1]);
    IHS_BufferClear(&b, true);
}
static void feed(IHS_Session *s, uint16_t fid, uint16_t seq, uint8_t flags, const uint8_t *bytes,
                 size_t len) {
    IHS_SessionFrame f = {.header = {.type = IHS_SessionPacketTypeReliable,
                                     .channelId = 3,
                                     .sendTimestamp = 1000000,
                                     .receiveTimestamp = 1000000,
                                     .receiveBegin = 1000000}};
    IHS_BufferInit(&f.body, 64, 65536);
    IHS_BufferAppendUInt8(&f.body, k_EStreamDataPacket);
    IHS_BufferAppendUInt16LE(&f.body, fid);
    IHS_BufferAppendUInt32LE(&f.body, 1000000);
    IHS_BufferAppendUInt16LE(&f.body, 0);
    IHS_BufferAppendUInt32LE(&f.body, 0);
    IHS_BufferAppendUInt16LE(&f.body, seq);
    IHS_BufferAppendUInt8(&f.body, flags);
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
static void hash(sl_video_frame *f, uint8_t out[16]) {
    uint8_t b[128 * 72 * 3 / 2];
    assert(av_image_copy_to_buffer(b, sizeof(b), (const uint8_t *const *)f->pixels->data,
                                   f->pixels->linesize, AV_PIX_FMT_YUV420P, 128, 72,
                                   1) == sizeof(b));
    av_md5_sum(out, b, sizeof(b));
}
static void counts(sl_runtime *r, unsigned fs, unsigned ss, sl_video_frame *old,
                   const uint8_t saved[16]) {
    assert(atomic_load(&flushes) == fs && atomic_load(&sends) == ss && opens == 1);
    assert(r->facts.epoch == 1 && !r->facts.paused && !r->session->base.interrupted &&
           sl_video_is_current(pipeline, (sl_video_key){90, 1}));
    if (old) {
        uint8_t actual[16];
        hash(old, actual);
        assert(!memcmp(actual, saved, 16));
    }
}
static void output(unsigned epoch) {
    sl_video_frame *f = sl_video_take(pipeline);
    assert(f && f->key.epoch == epoch);
    sl_resource_release(&f->ref);
}
static void modeCounts(sl_runtime *r, unsigned fs, unsigned ss, unsigned epoch,
                       sl_video_frame *old, const uint8_t saved[16]) {
    assert(atomic_load(&flushes) == fs && atomic_load(&sends) == ss && opens == epoch);
    assert(r->facts.epoch == epoch && !r->facts.paused && !r->session->base.interrupted &&
           sl_video_is_current(pipeline, (sl_video_key){90, epoch}));
    assert(atomic_load(&losses) == epoch - 1);
    uint8_t actual[16];
    hash(old, actual);
    assert(!memcmp(actual, saved, 16));
}
static void reset(sl_runtime *r) {
    r->session->base.callbacks.run->update(&r->session->base,
                                           r->session->base.callbackContexts.run);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    IHS_Init();
    sl_runtime r = {0};
    pthread_mutex_init(&r.lock, NULL);
    r.facts.session_id = 90;
    r.session = IHS_TestSessionCreate();
    assert(r.session);
    IHS_TimerTaskStopImmediate(r.session->retransmission.timer);
    r.session->state.connectionState = IHS_SessionConnectionStateConnected;
    assert(IHS_SessionSetVideoTrackingIdentity(r.session, 90));
    IHS_SessionSetVideoCallbacks(r.session, &video_cb, &r);
    CStartVideoDataMsg m = CSTART_VIDEO_DATA_MSG__INIT;
    m.channel = 3;
    m.has_codec = m.has_width = m.has_height = true;
    m.codec = k_EStreamVideoCodecH264;
    m.width = 128;
    m.height = 72;
    control(r.session, k_EStreamControlStartVideoData, &m.base);
    FILE *in = fopen(argv[1], "rb");
    assert(in);
    uint8_t packet[2204];
    assert(fread(packet, 1, sizeof(packet), in) == sizeof(packet));
    fclose(in);
    const unsigned half = 1102;
    feed(r.session, 1, 0, 24, packet, sizeof(packet));
    counts(&r, 1, 1, NULL, NULL);
    sl_video_frame *old = sl_video_take(pipeline);
    assert(old);
    uint8_t saved[16];
    hash(old, saved);
    void *mapping = sl_video_hold_mapping(old);
    assert(mapping);
    feed(r.session, 2, 1, 16, packet, half);
    counts(&r, 2, 1, old, saved);
    assert(!sl_video_take(pipeline));
    feed(r.session, 2, 2, 8, packet + half, half);
    counts(&r, 2, 2, old, saved);
    output(1);
    feed(r.session, 3, 3, 16, packet, half);
    counts(&r, 3, 2, old, saved);
    feed(r.session, 4, 4, 16, packet, half);
    counts(&r, 4, 2, old, saved);
    feed(r.session, 4, 5, 8, packet + half, half);
    counts(&r, 4, 3, old, saved);
    output(1);
    feed(r.session, 5, 6, 16, packet, half);
    counts(&r, 5, 3, old, saved);
    feed(r.session, 5, 7, 24, packet, sizeof(packet));
    counts(&r, 6, 4, old, saved);
    output(1);
    /* The finishing bit decides the mode. Its transition is retained, and
     * following delta bytes must not reach FFmpeg before the actor resets. */
    feed(r.session, 6, 8, 16, packet, half);
    modeCounts(&r, 7, 4, 1, old, saved);
    feed(r.session, 6, 9, 72, packet + half, half);
    modeCounts(&r, 7, 4, 1, old, saved);
    feed(r.session, 7, 10, 72, packet, sizeof(packet));
    modeCounts(&r, 7, 4, 1, old, saved);
    reset(&r);
    modeCounts(&r, 8, 4, 2, old, saved);
    feed(r.session, 8, 11, 72, packet, sizeof(packet));
    modeCounts(&r, 8, 4, 2, old, saved); /* Strict wait after the reset. */
    feed(r.session, 9, 12, 88, packet, sizeof(packet));
    modeCounts(&r, 9, 5, 2, old, saved); /* Same mode survives the reset. */
    output(2);
    feed(r.session, 10, 13, 24, packet, sizeof(packet));
    modeCounts(&r, 10, 5, 2, old, saved); /* Reverse transition also gates. */
    reset(&r);
    modeCounts(&r, 11, 5, 3, old, saved);
    feed(r.session, 11, 14, 24, packet, sizeof(packet));
    modeCounts(&r, 12, 6, 3, old, saved);
    output(3);
    CStopVideoDataMsg stop = CSTOP_VIDEO_DATA_MSG__INIT;
    control(r.session, k_EStreamControlStopVideoData, &stop.base);
    assert(atomic_load(&flushes) == 13);
    IHS_SessionDestroy(r.session);
    IHS_Quit();
    assert(!sl_media_video_clean());
    uint8_t final[16];
    hash(old, final);
    assert(!memcmp(final, saved, 16));
    sl_resource_release(&old->ref);
    assert(!sl_media_video_clean());
    sl_video_release_mapping(mapping);
    assert(sl_media_video_clean());
    pthread_mutex_destroy(&r.lock);
    stream_media_shutdown();
    return 0;
}
