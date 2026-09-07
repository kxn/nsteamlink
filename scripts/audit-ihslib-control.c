/* Offline audit probes. No network workers are started.
 * See docs/STEAMLINK_PROTOCOL_RE.md section 14 for the independent wire oracle.
 * The extra canary allocation contains the known diagnostic overflow safely. */
#include "common/test_session.h"
#include "ihs_buffer_ext.h"
#include "ihslib.h"
#include "session/channels/ch_control.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Same queue item layout as session.c; no worker/socket is started. */
struct IHS_QueueItem {
    IHS_SessionPacket packet;
    bool reliable;
};

static unsigned violations;

static void init_packet(IHS_SessionPacket *p, int type, unsigned id) {
    memset(p, 0, sizeof(*p));
    p->header.type = type;
    p->header.channelId = IHS_SessionChannelIdControl;
    p->header.packetId = id;
    IHS_SessionPacketBodyInitialize(&p->body, false);
}
static IHS_Session *session_new(void) {
    IHS_Session *s = IHS_TestSessionCreate();
    IHS_TimerTaskStopImmediate(s->retransmission.timer);
    IHS_SessionChannelControl *c = (void *) IHS_SessionChannelFor(s, 1);
    IHS_TimerTaskStopImmediate(c->feedbackTimer);
    return s;
}
static void nack_receive(void) {
    IHS_Session *s = session_new();
    IHS_SessionChannel *c = IHS_SessionChannelFor(s, 1);
    for (unsigned id = 100; id <= 102; ++id) {
        IHS_SessionPacket p;
        init_packet(&p, IHS_SessionPacketTypeReliable, id);
        IHS_BufferAppendUInt8(&p.body, 0);
        assert(IHS_RetransmissionTrack(&s->retransmission, &p, 1));
        IHS_SessionPacketClear(&p, true);
    }
    IHS_SessionPacket nack;
    init_packet(&nack, IHS_SessionPacketTypeNACK, 101);
    /* Official layout: timestamp, last contiguous ID, presence bitmap
     * based at header.packetId. Peer has 100 and 102, needs 101. */
    IHS_BufferAppendUInt32LE(&nack.body, 200);
    IHS_BufferAppendUInt16LE(&nack.body, 100);
    IHS_BufferAppendUInt8(&nack.body, 2);
    c->cls->received(c, &nack);
    printf("RX NACK: missing packet 101 retained=%d (required 1); outstanding=%u (required 1)\n",
           IHS_RetransmissionIsTracked(&s->retransmission, 1, 101, 0),
           s->retransmission.stats.outstanding);
    violations += !IHS_RetransmissionIsTracked(&s->retransmission, 1, 101, 0);
    IHS_SessionPacketClear(&nack, true);
    IHS_SessionDestroy(s);
}
static void drain(IHS_Session *s, const char *phase) {
    IHS_QueueItem *q;
    while ((q = IHS_QueuePoll(s->sendQueue))) {
        IHS_SessionPacket *p = &q->packet;
        if (p->header.type == IHS_SessionPacketTypeNACK) {
            const uint8_t *b = IHS_BufferPointer(&p->body);
            printf("%s: NACK base=%u contiguous=%u (required 100), mask=%02x\n", phase,
                   p->header.packetId, b[4] | (b[5] << 8), b[6]);
            violations += (b[4] | (b[5] << 8)) != 100;
        }
        if (p->header.type == IHS_SessionPacketTypeACK) {
            const uint8_t *b = IHS_BufferPointer(&p->body);
            unsigned echo = b[0] | (b[1] << 8) | (b[2] << 16) | ((unsigned)b[3] << 24);
            printf("%s: ACK id=%u echo=%u (peer timestamp=123456)\n", phase, p->header.packetId,
                   echo);
        }
        IHS_SessionPacketClear(p, true);
        IHS_QueueItemFree(q);
    }
}
static void nack_send(void) {
    IHS_Session *s = session_new();
    IHS_SessionChannel *c = IHS_SessionChannelFor(s, 1);
    IHS_SessionChannelControl *control = (void *) c;
    IHS_SessionPacketsWindowDestroy(control->framePacketWindow);
    control->framePacketWindow = IHS_SessionPacketsWindowCreateReliable(320, 100);
    for (unsigned id = 100; id <= 102; id += 2) {
        IHS_SessionPacket p;
        init_packet(&p, IHS_SessionPacketTypeReliable, id);
        p.header.sendTimestamp = 123456;
        /* ClientHandshake is plaintext and has no incoming client handler. */
        IHS_BufferAppendUInt8(&p.body, k_EStreamControlClientHandshake);
        c->cls->received(c, &p);
        drain(s, id == 100 ? "TX feedback after 100" : "TX feedback after 102 (101 missing)");
        IHS_SessionPacketClear(&p, true);
    }
    IHS_SessionDestroy(s);
}
static void diagnostics_capacity(void) {
    IHS_Session *s = session_new();
    IHS_SessionChannel *c = IHS_SessionChannelFor(s, 1);
    uint8_t payload[96] = {0};
    for (int i = 0; i < 25; ++i)
        assert(IHS_SessionChannelControlSubmitHIDReport(c, payload, i == 17 ? 70 : sizeof(payload),
                                                        true));
    unsigned char out[4096 + 512];
    memset(out, 0xa5, sizeof(out));
    size_t written = IHS_SessionChannelControlDrainPendingHIDReports((char *)out, 4096);
    unsigned changed = 0;
    for (size_t i = 4096; i < sizeof(out); ++i)
        changed += out[i] != 0xa5;
    printf("HID diagnostic drain: capacity=4096 returned=%zu; canary bytes overwritten=%u "
           "(required 0)\n",
           written, changed);
    violations += written > 4096 || changed != 0;
    IHS_SessionDestroy(s);
}
int main(void) {
    IHS_Init();
    nack_receive();
    nack_send();
    diagnostics_capacity();
    IHS_Quit();
    printf("Wire/memory invariant violations: %u\n", violations);
    return violations ? 1 : 0;
}
