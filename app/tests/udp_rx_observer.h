/* Bounded read-only observation of real OS UDP receive cycles. No logging,
 * allocation, scheduling gates, packet edits or substituted IO returns. */
#include "ihs_udp.h"
#include "session/unreliable.h"

static bool udpRXObserve;
static struct {
    uint8_t wire[2048];
    size_t size;
    uint32_t tick;
} rxPackets[256];
static struct {
    unsigned begin, end;
    uint32_t tick, minimum, smooth, budget;
    float mean;
} rxBatches[256];
static struct {
    uint32_t echo, peer, now;
} rxClockInputs[16];
static unsigned rxPacketCount, rxBatchCount, rxBatchBegin, rxClockCount;
static bool rxBatchPending;

int __real_IHS_UDPSocketReceive(IHS_UDPSocket *, IHS_UDPPacket *);
int __wrap_IHS_UDPSocketReceive(IHS_UDPSocket *socket, IHS_UDPPacket *packet) {
    int result = __real_IHS_UDPSocketReceive(socket, packet);
    if (!udpRXObserve)
        return result;
    if (result > 0) {
        assert(rxPacketCount < 256 && packet->buffer.size <= 2048);
        rxPackets[rxPacketCount].size = packet->buffer.size;
        memcpy(rxPackets[rxPacketCount++].wire, IHS_BufferPointer(&packet->buffer),
               packet->buffer.size);
    } else if (rxPacketCount > rxBatchBegin) {
        assert(result == 0 && rxBatchCount < 256 && !rxBatchPending);
        rxBatches[rxBatchCount].begin = rxBatchBegin;
        rxBatches[rxBatchCount].end = rxPacketCount;
        rxBatchBegin = rxPacketCount;
        rxBatchPending = true;
    }
    return result;
}

void __real_IHS_StreamClockFeedback(IHS_StreamClock *, uint32_t, uint32_t, uint32_t);
void __wrap_IHS_StreamClockFeedback(IHS_StreamClock *clock, uint32_t echo, uint32_t peer,
                                    uint32_t now) {
    if (udpRXObserve) {
        assert(rxClockCount < 16);
        rxClockInputs[rxClockCount].echo = echo;
        rxClockInputs[rxClockCount].peer = peer;
        rxClockInputs[rxClockCount++].now = now;
        assert(rxPacketCount);
        rxPackets[rxPacketCount - 1].tick = now;
    }
    __real_IHS_StreamClockFeedback(clock, echo, peer, now);
}

void __real_IHS_SessionUnreliableReceived(IHS_Session *, IHS_SessionPacket *);
void __wrap_IHS_SessionUnreliableReceived(IHS_Session *session, IHS_SessionPacket *packet) {
    udpLoadObserveFEC(packet);
    if (udpRXObserve) {
        assert(rxPacketCount && packet->header.channelId == 3);
        rxPackets[rxPacketCount - 1].tick = packet->header.receiveTimestamp;
    }
    __real_IHS_SessionUnreliableReceived(session, packet);
}

void __real_IHS_SessionUnreliableUpdateAt(IHS_Session *, uint8_t, uint32_t);
void __wrap_IHS_SessionUnreliableUpdateAt(IHS_Session *session, uint8_t id, uint32_t tick) {
    /* Complete the read batch at the first channel visit, including before
     * StartAudio. Every real network cycle calls this once per channel. */
    if (udpRXObserve && rxBatchPending) {
        rxBatches[rxBatchCount].tick = tick;
        rxBatches[rxBatchCount].minimum = session->clock.minRTT;
        rxBatches[rxBatchCount].smooth = session->clock.smoothedRTT;
        rxBatches[rxBatchCount].mean = IHS_StreamClockRTTMilliseconds(&session->clock);
        rxBatches[rxBatchCount].budget = IHS_StreamClockReceiveDelayTicks(&session->clock, 6553);
        ++rxBatchCount;
        rxBatchPending = false;
    }
    __real_IHS_SessionUnreliableUpdateAt(session, id, tick);
}

static void rxReport(void) {
    assert(rxClockCount == 1 && rxBatchCount && !rxBatchPending && rxPacketCount == rxBatchBegin);
    printf(",\"rx_clock\":[");
    for (unsigned n = 0; n < rxClockCount; ++n)
        printf("%s{\"echo\":%u,\"peer\":%u,\"now\":%u}", n ? "," : "", rxClockInputs[n].echo,
               rxClockInputs[n].peer, rxClockInputs[n].now);
    printf("],\"rx_batches\":[");
    for (unsigned n = 0; n < rxBatchCount; ++n) {
        printf(
            "%s{\"tick\":%u,\"minimum\":%u,\"smooth\":%u,\"mean\":%.9g,\"budget\":%u,\"packets\":[",
            n ? "," : "", rxBatches[n].tick, rxBatches[n].minimum, rxBatches[n].smooth,
            rxBatches[n].mean, rxBatches[n].budget);
        for (unsigned p = rxBatches[n].begin; p < rxBatches[n].end; ++p) {
            printf("%s{\"tick\":%u,\"wire\":\"", p > rxBatches[n].begin ? "," : "",
                   rxPackets[p].tick);
            for (size_t i = 0; i < rxPackets[p].size; ++i)
                printf("%02x", rxPackets[p].wire[i]);
            printf("\"}");
        }
        printf("]}");
    }
    printf("]");
}
