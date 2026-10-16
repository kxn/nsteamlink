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

static unsigned violations;
static unsigned feedbackCount;
static uint32_t now = 1000000;
static const char *phase;
uint32_t __wrap_IHS_SessionPacketTimestamp(void) { return now; }
bool __wrap_IHS_BaseSend(IHS_Base *base, IHS_SocketAddress address, const IHS_Buffer *wire) {
    (void)base; (void)address;
    IHS_Buffer copy = IHS_BUFFER_INIT(2048, 2048);
    IHS_BufferAppendMem(&copy, IHS_BufferPointer(wire), wire->size);
    IHS_SessionPacket p;
    assert(IHS_SessionPacketParse(&p, &copy) == IHS_SessionPacketResultOK);
    const uint8_t *b = IHS_BufferPointer(&p.body);
    if (p.header.type == IHS_SessionPacketTypeNACK) {
        assert(p.body.size >= 7);
        printf("%s: NACK base=%u contiguous=%u (required 100), mask=%02x\n", phase,
               p.header.packetId, b[4] | (b[5] << 8), b[6]);
        violations += (b[4] | (b[5] << 8)) != 100 || p.header.packetId != 102 || b[6] != 1;
        ++feedbackCount;
    } else if (p.header.type == IHS_SessionPacketTypeACK) {
        unsigned echo = b[0] | (unsigned)b[1]<<8 | (unsigned)b[2]<<16 | (unsigned)b[3]<<24;
        printf("%s: ACK id=%u echo=%u (peer timestamp=123456)\n", phase, p.header.packetId, echo);
        violations += echo != 123456;
    }
    IHS_SessionPacketClear(&p, true);
    IHS_BufferClear(&copy, true);
    return true;
}

static void init_packet(IHS_SessionPacket *p, int type, unsigned id) {
    memset(p, 0, sizeof(*p));
    p->header.type = type;
    p->header.channelId = IHS_SessionChannelIdControl;
    p->header.packetId = id;
    IHS_SessionPacketBodyInitialize(&p->body, false);
}
static IHS_Session *session_new(void) {
    IHS_Session *s = IHS_TestSessionCreate();
    s->state.connectionState = IHS_SessionConnectionStateHandshaking;
    IHS_TimerTaskStopImmediate(s->retransmission.timer);
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
    IHS_RetransmissionActivate(&s->retransmission, 1, 100, 3);
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
    violations += !IHS_RetransmissionIsTracked(&s->retransmission, 1, 101, 0) || s->retransmission.stats.outstanding != 1;
    IHS_SessionPacketClear(&nack, true);
    IHS_SessionDestroy(s);
}
static void nack_send(void) {
    IHS_Session *s = session_new();
    IHS_SessionChannel *c = IHS_SessionChannelFor(s, 1);
    IHS_ReliableChannel *control = IHS_SessionReliableGet(s, c->id);
    if (control->framePacketWindow) IHS_SessionPacketsWindowDestroy(control->framePacketWindow);
    control->framePacketWindow = IHS_SessionPacketsWindowCreateReliable(320, 100);
    for (unsigned id = 100; id <= 102; id += 2) {
        IHS_SessionPacket p;
        init_packet(&p, IHS_SessionPacketTypeReliable, id);
        p.header.sendTimestamp = 123456;
        p.header.receiveTimestamp = now;
        /* ClientHandshake is plaintext and has no incoming client handler. */
        IHS_BufferAppendUInt8(&p.body, k_EStreamControlClientHandshake);
        phase = id == 100 ? "TX feedback after 100" : "TX feedback after 102 (101 missing)";
        c->cls->received(c, &p);
        IHS_SessionReliableUpdateChannel(s, 1);
        now += 66;
        IHS_SessionReliableUpdateChannel(s, 1);
        IHS_SessionPacketClear(&p, true);
    }
    violations += feedbackCount != 1;
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
