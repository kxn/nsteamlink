/* Real IHS Socket caller: CRC, timestamp, BaseSend errno and shaper/collectors.
 * No workers or network. SDK return policy is supplied by the C++ oracle. */
#include "ihslib.h"
#include "session/session_pri.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static uint32_t now;
uint32_t __wrap_IHS_SessionPacketTimestamp(void) { return now; }

void *sns_io_session(bool crc, bool (*send)(void *, const uint8_t *, size_t), void *ctx) {
    uint8_t secret[32] = {0};
    IHS_ClientConfig config = {.deviceId = 42, .secretKey = secret};
    IHS_SessionInfo info = {.sessionKeyLen = 32};
    IHS_Session *s = IHS_SessionCreate(&config, &info);
    assert(s);
    s->base.transport.send = send;
    s->base.transportContext = ctx;
    s->base.transportActive = true;
    s->state.crcRequired = crc;
    s->outgoing.rate[0] = s->outgoing.rate[1] = 0;
    s->outgoing.deadline[0] = s->outgoing.deadline[1] = 0;
    return s;
}
int sns_io_send(void *p, uint32_t stamp, unsigned kind, unsigned size,
                uint64_t *bytes, uint32_t *deadlines) {
    IHS_Session *s = p;
    now = stamp;
    IHS_SessionPacket packet = {.header = {.type = kind, .srcConnectionId = 12,
        .dstConnectionId = 34, .channelId = 1}};
    IHS_SessionPacketBodyInitialize(&packet.body, false);
    IHS_BufferFillMem(&packet.body, 0, 0, size);
    int result = IHS_SessionSendPacketResult(s, &packet);
    *bytes = s->networkRates[0].bytes;
    memcpy(deadlines, s->outgoing.deadline, sizeof(s->outgoing.deadline));
    IHS_SessionPacketClear(&packet, true);
    return result;
}
void sns_io_destroy(void *p) {
    IHS_Session *s = p;
    s->base.transportActive = false;
    IHS_SessionDestroy(s);
}
