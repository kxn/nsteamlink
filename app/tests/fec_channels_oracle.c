/* Real Base CRC/RX -> connection-owned per-channel FEC/RS and ordinary window.
 * Connected state/time, final send and final complete-frame delegate are explicit
 * adapters. No OS UDP, decoder worker, audio/video role or hardware runs. */
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "ihslib.h"
#include "session/unreliable.h"
#include "test_session.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static IHS_Session *session;
static unsigned action, tick = 1000000, parsed, fec_calls;
static bool receiving;
static const IHS_FECReceiver *receivers[32];
uint32_t __wrap_IHS_SessionPacketTimestamp(void) {
    return tick;
}
bool __wrap_IHS_BaseSend(IHS_Base *b, IHS_SocketAddress address, const IHS_Buffer *wire) {
    (void)b;
    (void)address;
    (void)wire;
    errno = EAGAIN;
    return false;
}
IHS_SessionPacketReturn __real_IHS_SessionPacketParse(IHS_SessionPacket *, IHS_Buffer *);
IHS_SessionPacketReturn __wrap_IHS_SessionPacketParse(IHS_SessionPacket *p, IHS_Buffer *wire) {
    IHS_SessionPacketReturn result = __real_IHS_SessionPacketParse(p, wire);
    if (receiving) {
        assert(result == IHS_SessionPacketResultOK);
        ++parsed;
    }
    return result;
}
bool __real_IHS_FECReceiverAdd(IHS_FECReceiver *, const IHS_SessionPacket *, IHS_SessionFrame *);
bool __wrap_IHS_FECReceiverAdd(IHS_FECReceiver *r, const IHS_SessionPacket *p,
                               IHS_SessionFrame *f) {
    unsigned ch = p->header.channelId;
    assert(ch == 3 || ch == 4);
    assert(!receivers[ch] || receivers[ch] == r);
    receivers[ch] = r;
    ++fec_calls;
    return __real_IHS_FECReceiverAdd(r, p, f);
}
IHS_ReliableDisposition __wrap_IHS_SessionDeliverReliableFrame(IHS_Session *s,
                                                               IHS_SessionFrame *f) {
    assert(s == session && f->body.size <= 256);
    printf("{\"action\":%u,\"channel\":%u,\"group\":%u,\"body\":\"", action, f->header.channelId,
           f->header.packetId);
    for (size_t i = 0; i < f->body.size; ++i)
        printf("%02x", IHS_BufferPointer(&f->body)[i]);
    puts("\"}");
    return IHS_ReliableData;
}
int main(int argc, char **argv) {
    assert(argc == 2 && (!strcmp(argv[1], "0") || !strcmp(argv[1], "1")));
    alarm(10);
    IHS_Init();
    session = IHS_TestSessionCreate();
    assert(session);
    IHS_TimerTaskStopImmediate(session->retransmission.timer);
    session->state.connectionState = IHS_SessionConnectionStateConnected;
    session->state.connectionId = 12;
    session->state.hostConnectionId = 34;
    session->state.crcRequired = atoi(argv[1]);
    session->outgoing.rate[0] = session->outgoing.rate[1] = 0;
    char line[1024], hex[513];
    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == 'W') {
            assert(sscanf(line, "W %u %u %512s", &action, &tick, hex) == 3);
            size_t len = strlen(hex);
            assert(len && !(len & 1));
            IHS_Buffer wire = IHS_BUFFER_INIT(256, 256);
            for (size_t i = 0; i < len; i += 2) {
                unsigned byte;
                assert(sscanf(hex + i, "%2x", &byte) == 1);
                IHS_BufferAppendUInt8(&wire, (uint8_t)byte);
            }
            receiving = true;
            session->base.callbacks.received(&session->base, &session->info.address, &wire);
            receiving = false;
            IHS_BufferClear(&wire, true);
        } else {
            unsigned ch;
            assert(line[0] == 'U' && sscanf(line, "U %u %u %u", &action, &tick, &ch) == 3);
            assert(ch == 3 || ch == 4);
            IHS_SessionUnreliableUpdateAt(session, ch, tick);
        }
    }
    assert(receivers[3] && receivers[4] && receivers[3] != receivers[4]);
    IHS_SessionDestroy(session);
    IHS_Quit();
    alarm(0);
    printf("{\"done\":true,\"distinct\":true,\"parsed\":%u,\"fec_calls\":%u}\n", parsed, fec_calls);
    return 0;
}
