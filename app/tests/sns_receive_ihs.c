/* Actual IHS receiveCycle; final packet parsing and Connection Update are
 * observers, matching the original audit's final consumer boundaries. */
#include "ihslib.h"
#include "session/session_pri.h"
#include <assert.h>

static uint32_t now;
void sns_receive_packet(const uint8_t *, size_t);
void sns_receive_update(uint32_t);
uint32_t __wrap_IHS_SessionPacketTimestamp(void) { return now; }
IHS_SessionPacketReturn __wrap_IHS_SessionPacketParse(IHS_SessionPacket *p, IHS_Buffer *b) {
    (void)p;
    sns_receive_packet(IHS_BufferPointer(b), b->size);
    return IHS_SessionPacketResultBadHeader; /* Final consumer is deliberately excluded. */
}
void __wrap_IHS_SessionTransportPrepareUpdate(IHS_Session *s, uint32_t stamp) {
    sns_receive_update(stamp);
    s->transport.detached = true; /* Exclude subsequent connection/client internals. */
}
void *sns_receive_session(const IHS_DatagramTransport *transport, void *context) {
    uint8_t secret[32] = {0};
    IHS_ClientConfig config = {.deviceId=42, .secretKey=secret};
    IHS_SessionInfo info = {.sessionKeyLen=32};
    IHS_Session *s = IHS_SessionCreate(&config, &info);
    assert(s && IHS_SessionSetDatagramTransport(s, transport, context));
    s->base.transportActive = true;
    return s;
}
bool sns_receive_cycle(void *session, uint32_t stamp, unsigned wait) {
    IHS_Session *s = session;
    now = stamp;
    s->outgoing.blocked = wait == 0;
    s->transport.detached = false;
    IHS_UDPPacket packet = {0};
    IHS_BufferInit(&packet.buffer, 1, s->base.transport.receiveCapacity);
    bool result = s->base.callbacks.run->receiveCycle(&s->base, NULL, &packet);
    IHS_BufferClear(&packet.buffer, true);
    return result;
}
void sns_receive_destroy(void *session) {
    IHS_Session *s = session;
    s->base.transportActive = false;
    IHS_SessionDestroy(s);
}
