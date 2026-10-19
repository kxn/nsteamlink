/* Diagnostic observer transparency only: terminals deliberately do no network
 * I/O. This is not an official-client, protocol or real-host test. */
#define main live_media_probe_main
#include "live_media_probe.c"
#undef main
#include <assert.h>

static IHS_Session *expected_session;
static IHS_SessionPacket *expected_packet;
static IHS_SessionChannel *expected_channel;
static IHS_SessionFrame *expected_frame;
static IHS_UDPSocket *expected_socket;
static const IHS_UDPPacket *expected_udp;
static unsigned incoming_calls, fec_calls, complete_calls, lost_calls, socket_calls;
static bool socket_result = true;
void __real_IHS_SessionUnreliableReceived(IHS_Session *s, IHS_SessionPacket *p) {
    assert(s == expected_session && p == expected_packet);
    ++incoming_calls;
    if (p->header.type == IHS_SessionPacketTypeUnreliableFEC) {
        IHS_SessionFrame frame = {0};
        assert(__wrap_IHS_FECReceiverAdd(NULL, p, &frame));
    }
}
bool __real_IHS_FECReceiverAdd(IHS_FECReceiver *r, const IHS_SessionPacket *p,
                               IHS_SessionFrame *f) {
    assert(!r && p == expected_packet && f);
    ++fec_calls;
    return true;
}
void __real_IHS_SessionChannelDataReceiveReliableFrame(IHS_SessionChannel *c, IHS_SessionFrame *f) {
    assert(c == expected_channel && f == expected_frame);
    ++complete_calls;
}
void __real_IHS_SessionChannelDataLost(IHS_SessionChannel *c) {
    assert(c == expected_channel);
    ++lost_calls;
}
bool __real_IHS_UDPSocketSend(IHS_UDPSocket *s, const IHS_UDPPacket *p) {
    assert(s == expected_socket && p == expected_udp);
    ++socket_calls;
    return socket_result;
}
int main(void) {
    IHS_Session normal = {0}, test = {0};
    unsigned socket_token, test_socket_token;
    normal.base.socket = (void *)&socket_token;
    test.base.socket = (void *)&test_socket_token;
    test.networkTest.mode = IHS_NetworkTestBandwidth;
    uint8_t body[12] = {8, 0, 0, 0, 4, 0, 1, 0}; /* k2/m1, parity index2 */
    IHS_SessionPacket packet = {
        .header = {.channelId = 3, .type = IHS_SessionPacketTypeUnreliableFEC, .fragmentId = 2},
        .body = {.data = body, .size = sizeof(body)}};
    expected_packet = &packet;
    expected_session = &test;
    __wrap_IHS_SessionUnreliableReceived(&test, &packet);
    assert(!atomic_load(&fec) && !atomic_load(&fec_complete));
    expected_session = &normal;
    __wrap_IHS_SessionUnreliableReceived(&normal, &packet);
    assert(atomic_load(&fec) == 1 && atomic_load(&fec_complete) == 1);
    assert(atomic_load(&fec_parity_enabled) == 1 && atomic_load(&fec_parity_shards) == 1);
    body[6] = 0; /* m0 must remain distinct from parity-bearing input. */
    packet.header.fragmentId = 0;
    __wrap_IHS_SessionUnreliableReceived(&normal, &packet);
    assert(atomic_load(&fec) == 2 && atomic_load(&fec_complete) == 2);
    assert(atomic_load(&fec_parity_enabled) == 1 && atomic_load(&fec_parity_shards) == 1);
    IHS_SessionFrame frame = {0};
    assert(__wrap_IHS_FECReceiverAdd(NULL, &packet, &frame));
    assert(atomic_load(&fec_complete) == 2); /* RX context was restored. */
    packet.header.type = IHS_SessionPacketTypeUnreliable;
    __wrap_IHS_SessionUnreliableReceived(&normal, &packet);
    packet.header.channelId = 1;
    __wrap_IHS_SessionUnreliableReceived(&normal, &packet);
    assert(atomic_load(&ordinary) == 1 && incoming_calls == 5 && fec_calls == 4);
    IHS_SessionChannel channel = {.id = 3, .session = &test};
    expected_channel = &channel;
    expected_frame = &frame;
    __wrap_IHS_SessionChannelDataReceiveReliableFrame(&channel, &frame);
    __wrap_IHS_SessionChannelDataLost(&channel);
    channel.session = &normal;
    __wrap_IHS_SessionChannelDataReceiveReliableFrame(&channel, &frame);
    __wrap_IHS_SessionChannelDataLost(&channel);
    assert(atomic_load(&complete) == 1 && atomic_load(&recovery) == 1);
    assert(complete_calls == 2 && lost_calls == 2);
    uint8_t wire[13] = {10, 0, 0, 0, 3};
    IHS_UDPPacket udp = {.buffer = {.data = wire, .size = sizeof(wire)}};
    expected_udp = &udp;
    expected_socket = test.base.socket;
    assert(__wrap_IHS_UDPSocketSend(expected_socket, &udp));
    expected_socket = normal.base.socket;
    assert(__wrap_IHS_UDPSocketSend(expected_socket, &udp));
    socket_result = false;
    assert(!__wrap_IHS_UDPSocketSend(expected_socket, &udp));
    wire[4] = 1;
    assert(!__wrap_IHS_UDPSocketSend(expected_socket, &udp));
    assert(socket_calls == 4 && atomic_load(&feedback) == 1 && atomic_load(&send_fail) == 1);
    puts("Observer forwarding, network-test exclusion, m0/parity and actual socket outcomes "
         "passed.");
    return 0;
}
