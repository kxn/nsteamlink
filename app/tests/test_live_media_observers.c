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
static bool fec_result = true;
static unsigned pointer_calls;
uint8_t *__real_IHS_BufferPointer(const IHS_Buffer *);
uint8_t *__wrap_IHS_BufferPointer(const IHS_Buffer *b) {
    /* Enforce the real helper's Debug preconditions even if the SDK library
     * was compiled with NDEBUG; observers must not rely on that flag. */
    assert(b->data && b->offset <= b->capacity && b->suffix <= b->capacity - b->offset);
    assert(b->capacity - b->offset - b->suffix > 0);
    ++pointer_calls;
    return __real_IHS_BufferPointer(b);
}
void __real_IHS_SessionUnreliableReceived(IHS_Session *s, IHS_SessionPacket *p) {
    assert(s == expected_session && p == expected_packet);
    ++incoming_calls;
    if (p->header.type == IHS_SessionPacketTypeUnreliableFEC) {
        IHS_SessionFrame frame = {0};
        assert(__wrap_IHS_FECReceiverAdd(NULL, p, &frame) == fec_result);
    }
}
bool __real_IHS_FECReceiverAdd(IHS_FECReceiver *r, const IHS_SessionPacket *p,
                               IHS_SessionFrame *f) {
    assert(!r && p == expected_packet && f);
    ++fec_calls;
    return fec_result;
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
        .body = IHS_BUFFER_WRAP(body, sizeof(body))};
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
    IHS_UDPPacket udp = {.buffer = IHS_BUFFER_WRAP(wire, sizeof(wire))};
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
    /* PacketParse preserves an exact-size 13B datagram as offset==capacity.
     * Requesting the empty body's pointer violates the helper's contract. */
    uint8_t *empty_wire = calloc(13, 1);
    assert(empty_wire);
    empty_wire[0] = 11;
    empty_wire[2] = 7;
    empty_wire[3] = 1;
    empty_wire[4] = 3;
    empty_wire[7] = 1;
    IHS_Buffer raw = IHS_BUFFER_WRAP(empty_wire, 13);
    IHS_SessionPacket empty_packet;
    assert(IHS_SessionPacketParse(&empty_packet, &raw) == IHS_SessionPacketResultOK);
    assert(!empty_packet.body.size && empty_packet.body.offset == empty_packet.body.capacity);
    expected_session = &normal;
    expected_packet = &empty_packet;
    fec_result = false;
    unsigned reads = pointer_calls;
    __wrap_IHS_SessionUnreliableReceived(&normal, &empty_packet);
    assert(pointer_calls == reads && incoming_calls == 6 && fec_calls == 5);
    IHS_SessionPacketClear(&empty_packet, true);
    for (size_t size = 0; size < 8; ++size) {
        uint8_t short_body[8] = {0};
        IHS_SessionPacket short_packet = {
            .header = {.channelId = 3, .type = IHS_SessionPacketTypeUnreliableFEC},
            .body = IHS_BUFFER_WRAP(short_body, size)};
        expected_packet = &short_packet;
        __wrap_IHS_SessionUnreliableReceived(&normal, &short_packet);
        assert(pointer_calls == reads);
    }
    IHS_SessionPacket null_packet = {
        .header = {.channelId = 3, .type = IHS_SessionPacketTypeUnreliableFEC}};
    expected_packet = &null_packet;
    __wrap_IHS_SessionUnreliableReceived(&normal, &null_packet);
    assert(pointer_calls == reads && incoming_calls == 15 && fec_calls == 14);
    assert(atomic_load(&fec_parity_enabled) == 1 && atomic_load(&fec_parity_shards) == 1);
    assert(atomic_load(&fec_complete) == 2);
    for (size_t size = 0; size < 13; ++size) {
        IHS_UDPPacket short_udp = {.buffer = IHS_BUFFER_WRAP(wire, size)};
        expected_udp = &short_udp;
        assert(!__wrap_IHS_UDPSocketSend(expected_socket, &short_udp));
        assert(pointer_calls == reads);
    }
    IHS_UDPPacket null_udp = {0};
    expected_udp = &null_udp;
    assert(!__wrap_IHS_UDPSocketSend(expected_socket, &null_udp));
    assert(pointer_calls == reads && socket_calls == 18);
    assert(atomic_load(&feedback) == 1 && atomic_load(&send_fail) == 1);
    puts("Observer forwarding, network-test exclusion, m0/parity and actual socket outcomes "
         "passed.");
    return 0;
}
