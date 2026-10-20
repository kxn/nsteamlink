/* Real CRC receive -> assembly/FIFO -> OS video worker -> tracked software
 * decoder -> pixel checksum. Socket send is an explicit success adapter.
 * No Steam peer, Switch hardware, physical display or peak-memory claim. */
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "session/channels/video/ch_data_video.h"
#include "session/reliable.h"
#include "test_session.h"
#include "video_pipeline.h"
#include <assert.h>
#include <libavutil/md5.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MIB2 (2u * 1024u * 1024u)
static sl_video_pipeline *pipeline;
static sl_video_key key;
static atomic_uint submitted, received, lost, tick;
static unsigned stops;
static const unsigned offsets[] = {0, 25334, 37641};
static const unsigned sizes[] = {25334, 12307, 13619};
static const char *hashes[] = {"c56217f3899351b7cea50f9402892c8d",
                               "158dbb985eae46ffe84efae8d8c45754",
                               "1d3b05f4b06f881624de075283c9eac9"};
uint32_t __wrap_IHS_SessionPacketTimestamp(void) {
    return atomic_load(&tick);
}
bool __wrap_IHS_BaseSend(IHS_Base *b, IHS_SocketAddress a, const IHS_Buffer *p) {
    (void)b;
    (void)a;
    (void)p;
    return true;
}
void __real_IHS_SessionChannelDataReceiveFrame(IHS_SessionChannelData *, IHS_SessionFrame *);
void __wrap_IHS_SessionChannelDataReceiveFrame(IHS_SessionChannelData *c, IHS_SessionFrame *f) {
    __real_IHS_SessionChannelDataReceiveFrame(c, f);
    atomic_fetch_add(&received, 1);
}
void __real_IHS_SessionChannelDataLost(IHS_SessionChannel *);
void __wrap_IHS_SessionChannelDataLost(IHS_SessionChannel *c) {
    __real_IHS_SessionChannelDataLost(c);
    atomic_fetch_add(&lost, 1);
}
static int start(IHS_Session *s, const IHS_VideoEpochInfo *e, const IHS_StreamVideoConfig *c,
                 void *ctx) {
    (void)s;
    (void)ctx;
    key = (sl_video_key){e->session_id, e->video_epoch};
    sl_video_config config = {.width = c->width, .height = c->height};
    assert(sl_video_open(pipeline, key, &config));
    return 0;
}
static IHS_StreamVideoSubmitResult submit(IHS_Session *s, const IHS_VideoEpochInfo *e, uint16_t id,
                                          IHS_FrameTicket *t, IHS_Buffer *b,
                                          IHS_StreamVideoFrameFlag flags, bool *taken, void *ctx) {
    (void)s;
    (void)ctx;
    assert(e->session_id == key.session && e->video_epoch == key.epoch);
    assert(IHS_FrameTicketIdentity(t).frameId == id && b->size <= MIB2);
    assert(sl_video_submit(pipeline, key, IHS_BufferPointer(b), b->size, t, taken,
                           (flags & IHS_StreamVideoFrameKeyFrame) != 0, NULL, NULL,
                           NULL) == SL_VIDEO_SUBMIT_OK);
    assert(*taken);
    atomic_fetch_add(&submitted, 1);
    return IHS_StreamVideoSubmitOK;
}
static void flush(IHS_Session *s, const IHS_VideoEpochInfo *e, IHS_StreamVideoFlushPhase phase,
                  void *ctx) {
    (void)s;
    (void)e;
    (void)ctx;
    if (phase == IHS_StreamVideoFlushDecoder)
        sl_video_discard_buffers(pipeline, key);
}
static void stop(IHS_Session *s, const IHS_VideoEpochInfo *e, void *ctx) {
    (void)s;
    (void)e;
    (void)ctx;
    sl_video_stop(pipeline, key);
    ++stops;
}
static void wait_count(atomic_uint *counter, unsigned want) {
    uint64_t end = IHS_TimerNow() + 3000;
    while (atomic_load(counter) < want && IHS_TimerNow() < end)
        usleep(1000);
    assert(atomic_load(counter) == want);
}
static void pixels(unsigned id, unsigned au) {
    sl_video_selection selection = {0};
    assert(sl_video_select(pipeline, &selection) && selection.frame);
    assert(IHS_FrameTicketIdentity(selection.ticket).frameId == id);
    assert(IHS_FrameTicketIdentity(selection.frame->ticket).frameId == id);
    AVFrame *f = selection.frame->pixels;
    assert(f->format == AV_PIX_FMT_YUV420P && f->width == 1280 && f->height == 720);
    struct AVMD5 *md5 = av_md5_alloc();
    assert(md5);
    av_md5_init(md5);
    for (unsigned plane = 0; plane < 3; ++plane)
        for (unsigned y = 0; y < (plane ? 360u : 720u); ++y)
            av_md5_update(md5, f->data[plane] + (ptrdiff_t)y * f->linesize[plane],
                          plane ? 640 : 1280);
    unsigned char digest[16];
    av_md5_final(md5, digest);
    av_free(md5);
    char text[33];
    for (unsigned n = 0; n < 16; ++n)
        sprintf(text + 2 * n, "%02x", digest[n]);
    assert(!strcmp(text, hashes[au]));
    IHS_FrameOutcome outcome = {.result = IHS_VideoFrameResultDroppedReset,
                                .completionUs = IHS_TimerNow() * 1000};
    sl_video_selection_complete(&selection, &outcome); /* checksum, not displayed */
    sl_video_selection_release(&selection);
}
static IHS_Buffer payload(const unsigned char *fixture, unsigned au, size_t encoded, unsigned id,
                          unsigned seq) {
    assert(encoded >= sizes[au] + 6);
    IHS_Buffer b = IHS_BUFFER_INIT(1024, 0);
    IHS_BufferAppendUInt8(&b, k_EStreamDataPacket);
    IHS_BufferAppendUInt16LE(&b, id);
    IHS_BufferAppendUInt32LE(&b, atomic_load(&tick));
    IHS_BufferAppendUInt16LE(&b, 0);
    IHS_BufferAppendUInt32LE(&b, 0);
    IHS_BufferAppendUInt16LE(&b, seq);
    IHS_BufferAppendUInt8(&b, VideoFrameFlagFrameFinish | (au ? 0 : VideoFrameFlagKeyFrame));
    IHS_BufferAppendUInt16LE(&b, 0);
    IHS_BufferAppendUInt16LE(&b, 0);
    IHS_BufferAppendMem(&b, fixture + offsets[au], sizes[au]);
    static const unsigned char filler[] = {0, 0, 0, 1, 12};
    IHS_BufferAppendMem(&b, filler, sizeof(filler));
    for (size_t n = sizes[au] + 5; n + 1 < encoded; ++n)
        IHS_BufferAppendUInt8(&b, 255);
    IHS_BufferAppendUInt8(&b, 128);
    assert(b.size == encoded + 20);
    return b;
}
static void receive(IHS_Session *s, unsigned type, unsigned packet_id, unsigned fragment,
                    const unsigned char *bytes, size_t size) {
    IHS_SessionPacket p = {.header = {.type = type,
                                      .hasCrc = true,
                                      .channelId = 9,
                                      .srcConnectionId = 34,
                                      .dstConnectionId = 12,
                                      .packetId = packet_id,
                                      .fragmentId = (int16_t)fragment,
                                      .sendTimestamp = atomic_load(&tick)}};
    IHS_SessionPacketBodyInitialize(&p.body, true);
    IHS_BufferAppendMem(&p.body, bytes, size);
    IHS_SessionPacketPopulateBuffer(&p);
    IHS_Buffer wire = IHS_BUFFER_INIT(2048, 2048);
    IHS_BufferAppendMem(&wire, p.body.data, IHS_SessionPacketSize(&p));
    s->base.callbacks.received(&s->base, &s->info.address, &wire);
    IHS_BufferClear(&wire, true);
    IHS_SessionPacketClear(&p, true);
}
/* Independent test encoder, polynomial 0x11d. Existing official FEC vectors
 * establish the wire coefficients; the checksum here tests the whole consumer. */
static uint8_t multiply(unsigned a, unsigned b) {
    unsigned out = 0;
    for (; b; b >>= 1, a = (a << 1) ^ (a & 128 ? 0x11d : 0))
        if (b & 1)
            out ^= a;
    return (uint8_t)out;
}
static uint8_t inverse(unsigned a) {
    unsigned out = 1;
    for (unsigned n = 0; n < 254; ++n)
        out = multiply(out, a);
    return (uint8_t)out;
}
static void send_frame(IHS_Session *s, const IHS_Buffer *body, unsigned mode, unsigned *packet_id,
                       unsigned group) {
    const size_t chunk = mode == 3 ? 1440 : 1200;
    unsigned count = (body->size + chunk - 1) / chunk;
    if (mode < 2) {
        for (unsigned i = 0; i < count; ++i) {
            size_t off = i * chunk, n = body->size - off;
            if (n > chunk)
                n = chunk;
            receive(
                s,
                mode ? (i ? IHS_SessionPacketTypeReliableFrag : IHS_SessionPacketTypeReliable)
                     : (i ? IHS_SessionPacketTypeUnreliableFrag : IHS_SessionPacketTypeUnreliable),
                (*packet_id)++, i ? i - 1 : count - 1, body->data + off, n);
        }
        if (mode)
            IHS_SessionReliableUpdateChannelAt(s, 9, atomic_load(&tick));
        else
            IHS_SessionUnreliableUpdateAt(s, 9, atomic_load(&tick));
        return;
    }
    unsigned parity_count = mode == 2 ? 3 : 0;
    assert(!parity_count || count + parity_count <= 255);
    unsigned char parity[1440] = {0};
    if (parity_count) {
        for (unsigned col = 0; col < count; ++col) {
            uint8_t coefficient = inverse(parity_count + col);
            for (unsigned j = 0; j < chunk && col * chunk + j < body->size; ++j)
                parity[j] ^= multiply(body->data[col * chunk + j], coefficient);
        }
    }
    unsigned sent = count + (parity_count ? 1 : 0);
    for (unsigned i = 0; i < sent; ++i) {
        if (parity_count && i == 1)
            continue; /* one real data erasure, recovered by parity row0 */
        IHS_Buffer shard = IHS_BUFFER_INIT(chunk + 8, chunk + 8);
        IHS_BufferAppendUInt32LE(&shard, body->size);
        IHS_BufferAppendUInt16LE(&shard, chunk);
        IHS_BufferAppendUInt16LE(&shard, parity_count);
        for (unsigned j = 0; j < chunk; ++j)
            IHS_BufferAppendUInt8(
                &shard, i == count ? parity[j]
                                   : (i * chunk + j < body->size ? body->data[i * chunk + j] : 0));
        receive(s, IHS_SessionPacketTypeUnreliableFEC, group, i, shard.data, shard.size);
        IHS_BufferClear(&shard, true);
    }
}
int main(int argc, char **argv) {
    assert(argc == 2);
    unsigned char fixture[97067];
    FILE *f = fopen(argv[1], "rb");
    assert(f && fread(fixture, 1, sizeof(fixture), f) == sizeof(fixture) && fgetc(f) == EOF);
    assert(!fclose(f));
    IHS_Init();
    for (unsigned mode = 0; mode < 4; ++mode) {
        atomic_store(&submitted, 0);
        atomic_store(&received, 0);
        atomic_store(&lost, 0);
        atomic_store(&tick, 1000000);
        pipeline = sl_video_create();
        assert(pipeline);
        IHS_Session *s = IHS_TestSessionCreate();
        assert(s && IHS_SessionSetVideoTrackingIdentity(s, mode + 1));
        IHS_TimerTaskStopImmediate(s->retransmission.timer);
        s->state.connectionState = IHS_SessionConnectionStateConnected;
        s->state.connectionId = 12;
        s->state.hostConnectionId = 34;
        s->state.crcRequired = true;
        const IHS_StreamVideoCallbacks cb = {.startTracked = start,
                                             .submitTracked = submit,
                                             .stopTracked = stop,
                                             .flushTracked = flush};
        IHS_SessionSetVideoCallbacks(s, &cb, NULL);
        CStartVideoDataMsg config = CSTART_VIDEO_DATA_MSG__INIT;
        config.channel = 9;
        config.width = 1280;
        config.height = 720;
        config.codec = k_EStreamVideoCodecH264;
        IHS_SessionChannel *c = IHS_SessionChannelDataVideoCreate(s, &config);
        assert(c && !c->initFailed && ((IHS_SessionChannelData *)c)->worker);
        IHS_SessionChannelAdd(s, c);
        unsigned packet_id = 0;
        for (unsigned au = 0; au < 3; ++au) {
            size_t encoded = mode == 2 ? 65516 : MIB2 - 21 + au;
            IHS_Buffer b = payload(fixture, au, encoded, 100 + au, au);
            send_frame(s, &b, mode, &packet_id, au);
            IHS_BufferClear(&b, true);
            wait_count(&submitted, au + 1);
            pixels(100 + au, au);
        }
        if (mode != 2) {
            /* Encoded limit itself is a different unit from transport body.
             * Its 20B envelope must fit ordinary/reliable and zero-parity FEC. */
            for (unsigned au = 0; au < 2; ++au) {
                IHS_Buffer b = payload(fixture, au, MIB2, 103 + au, 3 + au);
                send_frame(s, &b, mode, &packet_id, 3 + au);
                IHS_BufferClear(&b, true);
                wait_count(&submitted, 4 + au);
                pixels(103 + au, au);
            }
            for (unsigned n = 0; n < 4; ++n) {
                unsigned au = n & 1, id = 105 + n;
                size_t encoded = n ? sizes[au] + 6 : MIB2 + 1;
                IHS_Buffer b = payload(fixture, au, encoded, id, 5 + n);
                send_frame(s, &b, mode, &packet_id, 5 + n);
                IHS_BufferClear(&b, true);
                wait_count(&received, 6 + n);
                if (n < 2) {
                    assert(atomic_load(&submitted) == 5 && atomic_load(&lost) == 1);
                    sl_video_selection selection = {0};
                    assert(!sl_video_select(pipeline, &selection));
                } else {
                    wait_count(&submitted, 4 + n);
                    pixels(id, au);
                }
            }
        }
        assert(!atomic_load(&s->transport.closeRequested) && !s->base.interrupted);
        IHS_SessionDestroy(s); /* stop/join video worker before pipeline destruction */
        sl_video_reap(pipeline);
        assert(stops == mode + 1 && sl_video_destroy(pipeline));
    }
    IHS_Quit();
    puts("Media decode boundary: ordinary/reliable/FEC-m0 2MiB+-1 bodies, encoded2MiB, "
         "guarded excess, key/P recovery; FEC64KiB one erasure; software pixels verified");
    return 0;
}
