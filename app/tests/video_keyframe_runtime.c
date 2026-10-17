/* Production runtime callback table + control parser + real IHS worker/FFmpeg.
 * Split/replaced/repeated marks purge protocol partials immediately and exactly once
 * per wire mark, preserve the player/epoch and keep old pixels/map leases valid.
 * Bit6 transitions use the real actor; pending requests suppress SDK submission.
 * SDL dummy/software output is used; no physical GPU/Steam/loader claim. */
#include "../platforms/common/runtime.c"
#include "ihs_buffer.h"
#include "crypto.h"
#include "ihs_buffer_ext.h"
#include "session/channels/ch_control.h"
#include "session/channels/video/ch_data_video.h"
#include "session/session_pri.h"
#include "session/frame_tracker.h"
#include "test_session.h"
#include <assert.h>
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libavutil/md5.h>
#include <unistd.h>
static sl_video_pipeline *pipeline;
static atomic_uint processed, flushes, protocolFlushes, sends, losses;
static unsigned extraLosses;
static unsigned target, opens;
static unsigned expectedPacketSize = 2204;
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
void __real_sl_video_discard_buffers(sl_video_pipeline *,sl_video_key);
void __wrap_sl_video_discard_buffers(sl_video_pipeline *p,sl_video_key key) {
    atomic_fetch_add(&protocolFlushes,1);__real_sl_video_discard_buffers(p,key);
}
int __real_avcodec_send_packet(AVCodecContext *, const AVPacket *);
int __wrap_avcodec_send_packet(AVCodecContext *c, const AVPacket *p) {
    assert(p && p->size == (int)expectedPacketSize);
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
bool __real_IHS_FrameTicketComplete(IHS_FrameTicket *, const IHS_FrameOutcome *);
bool __wrap_IHS_FrameTicketComplete(IHS_FrameTicket *t, const IHS_FrameOutcome *o) {
    uint16_t id = IHS_FrameTicketIdentity(t).frameId;
    bool done=__real_IHS_FrameTicketComplete(t,o);
    if(done && (id==22 || id==23)) assert(o->result==IHS_VideoFrameResultDroppedDecodeCorrupt);
    return done;
}
static void control(IHS_Session *s, EStreamControlMessage t, const ProtobufCMessage *m) {
    IHS_Buffer b = IHS_BUFFER_INIT(64, 4096);
    IHS_BufferAppendMessage(&b, m);
    IHS_SessionPacketHeader h = {.type = IHS_SessionPacketTypeReliable, .channelId = 1};
    IHS_SessionChannelControlHandoff(s->channels[1], t, &b, &h);
    IHS_SessionChannelControlDrainIncoming(s->channels[1]);
    IHS_BufferClear(&b, true);
}
static void feedRange(IHS_Session *s, uint16_t fid, uint16_t seq, uint8_t flags,
                      uint16_t startRange, uint16_t endRange, const uint8_t *bytes, size_t len) {
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
    IHS_BufferAppendUInt16LE(&f.body, startRange);
    IHS_BufferAppendUInt16LE(&f.body, endRange);
    IHS_BufferAppendMem(&f.body, bytes, len);
    IHS_SessionDeliverReliableFrame(s, &f);
    IHS_SessionFrameClear(&f, true);
    ++target;
    for (unsigned n = 0; n < 5000 && atomic_load(&processed) < target; ++n)
        usleep(1000);
    assert(atomic_load(&processed) == target);
}
static void feed(IHS_Session *s, uint16_t fid, uint16_t seq, uint8_t flags, const uint8_t *bytes,
                 size_t len) {
    feedRange(s, fid, seq, flags, 0, 0, bytes, len);
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
    assert(atomic_load(&protocolFlushes) == fs && atomic_load(&flushes)==0 && atomic_load(&sends) == ss && opens == 1);
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
    assert(atomic_load(&protocolFlushes) == fs && atomic_load(&flushes)==0 && atomic_load(&sends) == ss && opens == epoch);
    assert(r->facts.epoch == epoch && !r->facts.paused && !r->session->base.interrupted &&
           sl_video_is_current(pipeline, (sl_video_key){90, epoch}));
    assert(atomic_load(&losses) == epoch - 1 + extraLosses);
    uint8_t actual[16];
    hash(old, actual);
    assert(!memcmp(actual, saved, 16));
}
static size_t marker(const uint8_t *p, size_t len, size_t at, size_t *width) {
    for (size_t n = at; n + 2 < len; ++n) {
        if (p[n] || p[n+1]) continue;
        if (n+3 < len && !p[n+2] && p[n+3] == 1) { *width = 4; return n; }
        if (p[n+2] == 1) { *width = 3; return n; }
    }
    return len;
}
static unsigned nalFrame(sl_runtime *r, const uint8_t *packet, size_t len,
                          uint16_t id, unsigned sequence, bool encrypted, const uint8_t saved[16]) {
    uint8_t raw[2204], cipher[2224];
    const uint8_t iv[16] = {0};
    size_t width, begin = marker(packet,len,0,&width);
    bool first = true;
    unsigned boundaries = 0;
    while (begin < len) {
        size_t nextWidth = 0, start = begin + width;
        size_t end = marker(packet,len,start,&nextWidth);
        size_t count = 0;
        unsigned zeros = 0;
        for (size_t n = start; n < end; ++n) {
            uint8_t value = packet[n];
            if (zeros == 2 && value == 3) { zeros = 0; continue; }
            raw[count++] = value;
            zeros = value ? 0 : zeros + 1;
        }
        size_t cut = 0;
        for (size_t n = 3; n < count; ++n)
            if (!raw[n-2] && !raw[n-1] && raw[n] <= 3) { cut = n; ++boundaries; break; }
        if (!cut) cut = count > 1 ? count / 2 : count;
        for (unsigned part = 0; part < 2; ++part) {
            size_t offset = part ? cut : 0, size = part ? count-cut : cut;
            if (!size) continue;
            uint8_t flags = 2 | (!part ? 1 : 0) | (first ? 16 : 0);
            if (end == len && (part || cut == count)) flags |= 8;
            const uint8_t *bytes = raw + offset;
            if (encrypted) {
                size_t cipherSize = sizeof(cipher);
                assert(!IHS_CryptoSymmetricEncryptWithIV(bytes,size,iv,sizeof(iv),
                           r->session->info.sessionKey,16,false,cipher,&cipherSize));
                flags |= 32; bytes = cipher; size = cipherSize;
            }
            feed(r->session,id,sequence++,flags,bytes,size);
            first = false;
        }
        begin = end; width = nextWidth;
    }
    assert(boundaries > 0);
    sl_video_frame *frame = sl_video_take(pipeline);
    assert(frame && frame->key.epoch == 3);
    uint8_t decoded[16];
    hash(frame, decoded);
    /* The same first-AU fixture was already decoded before packetization. */
    assert(frame->pixels->width == 128 && frame->pixels->height == 72);
    assert(!memcmp(decoded, saved, 16));
    sl_resource_release(&frame->ref);
    return sequence;
}
static unsigned rangeFrame(sl_runtime *r, const uint8_t *packet, uint16_t firstId,
                           unsigned sequence, bool encrypted, const uint8_t saved[16]) {
    uint8_t cipher[576];
    const uint8_t iv[16] = {0};
    for (unsigned n = 0; n < 4; ++n) {
        const uint8_t *bytes = packet + n * 551;
        size_t size = 551;
        uint8_t flags = 4 | (!n ? 16 : 0) | (n == 3 ? 8 : 0);
        if (encrypted) {
            size = sizeof(cipher);
            assert(!IHS_CryptoSymmetricEncryptWithIV(bytes,551,iv,sizeof(iv),
                       r->session->info.sessionKey,16,false,cipher,&size));
            bytes = cipher; flags |= 32;
        }
        feedRange(r->session, firstId + (n >= 2), sequence++, flags, n*2, n*2+1, bytes, size);
    }
    sl_video_frame *frame = sl_video_take(pipeline);
    assert(frame && frame->key.epoch == 3);
    IHS_FrameIdentity identity = IHS_FrameTicketIdentity(frame->ticket);
    assert(identity.frameId == firstId + 1 && identity.epoch == 3);
    uint8_t decoded[16];
    hash(frame, decoded);
    assert(!memcmp(decoded, saved, 16));
    IHS_TrackedFrame stats[IHS_FRAME_TRACKER_CAPACITY];
    size_t count = IHS_FrameTrackerCopyStats(r->session->frameTracker, stats, IHS_FRAME_TRACKER_CAPACITY);
    bool foundContributor = false, foundFinish = false;
    for (size_t n = 0; n < count; ++n) {
        if (stats[n].identity.frameId == firstId) {
            assert(!stats[n].statsComplete && !stats[n].hasDecodeBegin && !stats[n].hasDecodeEnd);
            foundContributor = true;
        }
        if (stats[n].identity.frameId == firstId + 1) {
            assert(!stats[n].statsComplete && stats[n].hasDecodeBegin && stats[n].hasDecodeEnd);
            foundFinish = true;
        }
    }
    assert(foundContributor && foundFinish);
    sl_resource_release(&frame->ref);
    return sequence;
}
static void emptyFailed(sl_runtime *r, uint16_t id) {
    IHS_TrackedFrame stats[IHS_FRAME_TRACKER_CAPACITY];
    size_t n = IHS_FrameTrackerCopyStats(r->session->frameTracker, stats, IHS_FRAME_TRACKER_CAPACITY);
    bool found = false;
    for (size_t j = 0; j < n; ++j)
        if (stats[j].identity.frameId == id) {
            assert(stats[j].statsComplete && stats[j].outcome.result == IHS_VideoFrameResultDroppedDecodeCorrupt);
            assert(stats[j].hasDecodeBegin && stats[j].hasDecodeEnd);
            found = true;
        }
    assert(found);
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
    /* Real per-fragment AES-CBC before packetization and empty AU coverage. */
    uint8_t encrypted[2224];
    for (unsigned n = 0; n < 16; ++n) r.session->info.sessionKey[n] = n;
    r.session->info.sessionKeyLen = 16;
    const uint8_t iv[16] = {0};
    size_t encryptedSize = sizeof(encrypted);
    assert(!IHS_CryptoSymmetricEncryptWithIV(packet, sizeof(packet), iv, sizeof(iv),
              r.session->info.sessionKey, 16, false, encrypted, &encryptedSize));
    assert(encryptedSize == 2208);
    feed(r.session, 12, 15, 56, encrypted, encryptedSize);
    modeCounts(&r, 13, 7, 3, old, saved);
    output(3);
    /* Rebuild all four NALs from RBSP, split at zero sequences, and require
     * the normalized original AU bytes/decoded image to survive each path. */
    expectedPacketSize = 2206;
    unsigned sequence = nalFrame(&r, packet, sizeof(packet), 16, 19, false, saved);
    modeCounts(&r, 14, 8, 3, old, saved);
    sequence = nalFrame(&r, packet, sizeof(packet), 17, sequence, true, saved);
    modeCounts(&r, 15, 9, 3, old, saved);
    expectedPacketSize = 2204;
    sequence = rangeFrame(&r, packet, 18, sequence, false, saved);
    modeCounts(&r, 16, 10, 3, old, saved);
    sequence=rangeFrame(&r, packet, 20, sequence, true, saved);
    modeCounts(&r, 17, 11, 3, old, saved);
    /* Linux original parser sends NULL/zero output to AVCodec. The actual
     * Native SDK reaches EOF; original common error semantics apply. No key
     * mark flushes AVCodec to conceal that status. The second send requests an
     * actor rebuild; old AVFrame/map ownership must survive it. */
    expectedPacketSize=0;
    encryptedSize=sizeof(encrypted);
    assert(!IHS_CryptoSymmetricEncryptWithIV(packet,0,iv,sizeof(iv),
              r.session->info.sessionKey,16,false,encrypted,&encryptedSize));
    feed(r.session,22,sequence++,56,encrypted,encryptedSize);extraLosses=1;
    modeCounts(&r,18,12,3,old,saved);emptyFailed(&r,22);assert(!sl_video_take(pipeline));
    feed(r.session,23,sequence++,58,encrypted,encryptedSize);extraLosses=2;
    modeCounts(&r,19,13,3,old,saved);emptyFailed(&r,23);
    reset(&r);modeCounts(&r,20,13,4,old,saved);
    expectedPacketSize=2204;
    feed(r.session,24,sequence++,24,packet,sizeof(packet));
    modeCounts(&r,21,14,4,old,saved);output(4);
    CStopVideoDataMsg stop = CSTOP_VIDEO_DATA_MSG__INIT;
    control(r.session, k_EStreamControlStopVideoData, &stop.base);
    assert(atomic_load(&protocolFlushes)==22 && atomic_load(&flushes)==0);
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
