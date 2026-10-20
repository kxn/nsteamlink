/* Stop with a nonempty video FIFO: real runtime/worker/FFmpeg, no Steam/GPU.
 * Source §102/103/166: active FIFO batches reach OnThink/FinalDecode; cancelling
 * deferred format selection can report DataLost. Explicit local freeze retains
 * its benign cancellation semantics. The get_format observer forwards the
 * installed callback without changing formats/results; it is a Native fixture. */
#include "../platforms/common/runtime.c"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "session/channels/ch_control.h"
#include "session/channels/ch_data.h"
#include "session/channels/video/ch_data_video.h"
#include "session/frame_tracker.h"
#include "test_session.h"
#include <assert.h>
#include <libavcodec/avcodec.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
static atomic_bool watch, gated, resume_gate, joining;
static atomic_uint consumed, thoughts, submitted, losses;
static IHS_SessionChannelData *video_channel;
static unsigned submit_id, submit_result;
static bool submit_taken;
static const uint8_t *expected_body;
static enum AVPixelFormat (*original_format)(AVCodecContext *, const enum AVPixelFormat *);
static unsigned format_calls;
static int last_format, last_send, last_receive;
static enum AVPixelFormat observe_format(AVCodecContext *c, const enum AVPixelFormat *formats) {
    ++format_calls;
    last_format = original_format(c, formats);
    return last_format;
}
int __real_avcodec_open2(AVCodecContext *, const AVCodec *, AVDictionary **);
int __wrap_avcodec_open2(AVCodecContext *c, const AVCodec *codec, AVDictionary **options) {
    original_format = c->get_format;
    c->get_format = observe_format;
    return __real_avcodec_open2(c, codec, options);
}
int __real_avcodec_send_packet(AVCodecContext *, const AVPacket *);
int __wrap_avcodec_send_packet(AVCodecContext *c, const AVPacket *p) {
    last_send = __real_avcodec_send_packet(c, p);
    return last_send;
}
int __real_avcodec_receive_frame(AVCodecContext *, AVFrame *);
int __wrap_avcodec_receive_frame(AVCodecContext *c, AVFrame *f) {
    last_receive = __real_avcodec_receive_frame(c, f);
    return last_receive;
}
static void bounded_wait(atomic_bool *v) {
    for (unsigned i = 0; i < 15000 && !atomic_load(v); ++i)
        usleep(1000);
    assert(atomic_load(v));
}
void __real_IHS_SessionChannelDataReceiveFrame(IHS_SessionChannelData *, IHS_SessionFrame *);
void __wrap_IHS_SessionChannelDataReceiveFrame(IHS_SessionChannelData *c, IHS_SessionFrame *f) {
    if (atomic_exchange(&watch, false)) {
        atomic_store(&gated, true);
        bounded_wait(&resume_gate);
    }
    __real_IHS_SessionChannelDataReceiveFrame(c, f);
    atomic_fetch_add(&consumed, 1);
}
uint32_t __real_IHS_SessionChannelDataThink(IHS_SessionChannel *);
uint32_t __wrap_IHS_SessionChannelDataThink(IHS_SessionChannel *c) {
    uint32_t result = __real_IHS_SessionChannelDataThink(c);
    atomic_fetch_add(&thoughts, 1);
    return result;
}
void __real_IHS_ThreadJoin(IHS_Thread *);
void __wrap_IHS_ThreadJoin(IHS_Thread *t) {
    if (video_channel && t == video_channel->worker)
        atomic_store(&joining, true);
    __real_IHS_ThreadJoin(t);
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
    assert(expected_body && b->size == 2204 && !memcmp(IHS_BufferPointer(b), expected_body, 2204));
    IHS_StreamVideoSubmitResult result =
        __real_sl_media_video_submit_tracked(s, e, id, t, b, f, taken);
    submit_id = id;
    submit_result = result;
    submit_taken = *taken;
    atomic_fetch_add(&submitted, 1);
    return result;
}
void __real_IHS_SessionChannelDataLost(IHS_SessionChannel *);
void __wrap_IHS_SessionChannelDataLost(IHS_SessionChannel *c) {
    atomic_fetch_add(&losses, 1);
    __real_IHS_SessionChannelDataLost(c);
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
static void control(IHS_Session *s, EStreamControlMessage type, const ProtobufCMessage *m) {
    IHS_Buffer b = IHS_BUFFER_INIT(64, 4096);
    IHS_BufferAppendMessage(&b, m);
    IHS_SessionPacketHeader h = {.type = IHS_SessionPacketTypeReliable, .channelId = 1};
    IHS_SessionChannelControlHandoff(s->channels[1], type, &b, &h);
    IHS_SessionChannelControlDrainIncoming(s->channels[1]);
    IHS_BufferClear(&b, true);
}
static void feed(IHS_Session *s, unsigned id, const uint8_t *bytes, size_t n) {
    IHS_SessionFrame f = {.header = {.type = IHS_SessionPacketTypeReliable,
                                     .channelId = 3,
                                     .sendTimestamp = 1000000,
                                     .receiveTimestamp = 1000000}};
    IHS_BufferInit(&f.body, 4096, 65536);
    IHS_BufferAppendUInt8(&f.body, k_EStreamDataPacket);
    IHS_BufferAppendUInt16LE(&f.body, id);
    IHS_BufferAppendUInt32LE(&f.body, 1000000);
    IHS_BufferAppendUInt16LE(&f.body, 0);
    IHS_BufferAppendUInt32LE(&f.body, 0);
    IHS_BufferAppendUInt16LE(&f.body, id);
    IHS_BufferAppendUInt8(&f.body, VideoFrameFlagKeyFrame | VideoFrameFlagFrameFinish);
    IHS_BufferAppendUInt16LE(&f.body, 0);
    IHS_BufferAppendUInt16LE(&f.body, 0);
    IHS_BufferAppendMem(&f.body, bytes, n);
    assert(IHS_SessionDeliverReliableFrame(s, &f) == IHS_ReliableData);
    IHS_BufferClear(&f.body, true);
}
static void *remove_video(void *p) {
    IHS_SessionChannelRemove(p, 3);
    return NULL;
}
int main(int argc, char **argv) {
    assert(argc == 4);
    assert((!strcmp(argv[2], "0") || !strcmp(argv[2], "1")) &&
           (!strcmp(argv[3], "0") || !strcmp(argv[3], "1")));
    bool warm = atoi(argv[2]), freeze = atoi(argv[3]);
    assert(!setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    assert(stream_media_init(NULL));
    IHS_Init();
    sl_runtime r = {0};
    pthread_mutex_init(&r.lock, NULL);
    r.facts.session_id = 90;
    r.session = IHS_TestSessionCreate();
    IHS_TimerTaskStopImmediate(r.session->retransmission.timer);
    r.session->state.connectionState = IHS_SessionConnectionStateConnected;
    r.session->negotiatedVideoCodec = k_EStreamVideoCodecH264;
    assert(IHS_SessionSetVideoTrackingIdentity(r.session, 90));
    IHS_SessionSetVideoCallbacks(r.session, &video_cb, &r);
    CStartVideoDataMsg start = CSTART_VIDEO_DATA_MSG__INIT;
    start.channel = 3;
    start.has_width = start.has_height = true;
    start.width = 128;
    start.height = 72;
    control(r.session, k_EStreamControlStartVideoData, &start.base);
    video_channel = (void *)IHS_SessionChannelForType(r.session, IHS_SessionChannelTypeDataVideo);
    assert(video_channel);
    uint8_t bytes[2204];
    FILE *f = fopen(argv[1], "rb");
    assert(f && fread(bytes, 1, sizeof(bytes), f) == sizeof(bytes));
    fclose(f);
    expected_body = bytes;
    if (warm) {
        feed(r.session, 0, bytes, sizeof(bytes));
        for (unsigned i = 0; i < 15000 && atomic_load(&submitted) < 1; ++i) {
            IHS_SessionVideoHandleFormatRequests(r.session);
            usleep(1000);
        }
        assert(atomic_load(&submitted) == 1);
    }
    unsigned before = atomic_load(&submitted);
    atomic_store(&watch, true);
    feed(r.session, 1, bytes, sizeof(bytes));
    bounded_wait(&gated);
    feed(r.session, 2, bytes, sizeof(bytes));
    IHS_MutexLock(video_channel->windowLock);
    assert(video_channel->fecQueuedCount == 1);
    IHS_MutexUnlock(video_channel->windowLock);
    if (freeze)
        sl_media_close_video();
    pthread_t remover;
    assert(!pthread_create(&remover, NULL, remove_video, r.session));
    bounded_wait(&joining);
    atomic_store(&resume_gate, true);
    assert(!pthread_join(remover, NULL));
    video_channel = NULL;
    stream_media_snapshot snap;
    stream_media_get_snapshot(&snap);
    printf("{\"warm\":%u,\"freeze\":%u,\"consumed\":%u,\"thoughts\":%u,\"new_submits\":%u,\"submit_"
           "id\":%u,\"result\":%u,\"taken\":%u,\"lost\":%u,\"interrupted\":%u,\"error\":%u}\n",
           warm, freeze, atomic_load(&consumed), atomic_load(&thoughts),
           atomic_load(&submitted) - before, submit_id, submit_result, submit_taken,
           atomic_load(&losses), r.session->base.interrupted, !!snap.last_error[0]);
    assert(atomic_load(&consumed) == (warm ? 3U : 2U));
    assert(atomic_load(&submitted) == before + 1 && submit_id == 2 && !submit_result);
    assert(!r.session->base.interrupted && !snap.last_error[0]);
    assert(submit_taken == !freeze);
    if (freeze) {
        assert(!atomic_load(&losses) && format_calls == (warm ? 1U : 0U));
    } else if (warm) {
        assert(format_calls == 1 && last_format == AV_PIX_FMT_YUV420P && !last_send);
        assert(!atomic_load(&losses));
    } else {
        /* Observed actual SDK values, not invented driver/error translations. */
        assert(format_calls == 1 && last_format == AV_PIX_FMT_NONE);
        assert(last_send == AVERROR_INVALIDDATA && last_receive == AVERROR(EAGAIN));
        assert(atomic_load(&losses) == 1);
    }
    IHS_SessionDestroy(r.session);
    r.session = NULL;
    IHS_Quit();
    pthread_mutex_destroy(&r.lock);
    stream_media_shutdown();
    return 0;
}
