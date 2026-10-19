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
static unsigned worker_calls, submitted_calls, decode_feedback_calls;
static const IHS_VideoEpochInfo *expected_epoch;
static IHS_FrameTicket *expected_ticket;
static IHS_Buffer *expected_data;
static IHS_StreamVideoFrameFlag expected_flags;
static IHS_StreamVideoSubmitResult submitted_result, expected_feedback;
static uint16_t expected_id;
static bool expected_taken, decode_accepted;
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
void __real_IHS_SessionChannelDataReceiveFrame(IHS_SessionChannelData *c, IHS_SessionFrame *f) {
    assert(&c->base == expected_channel && f == expected_frame);
    ++worker_calls;
}
IHS_StreamVideoSubmitResult
__real_sl_media_video_submit_tracked(IHS_Session *session, const IHS_VideoEpochInfo *epoch,
                                     uint16_t id, IHS_FrameTicket *ticket, IHS_Buffer *data,
                                     IHS_StreamVideoFrameFlag flags, bool *taken) {
    assert(session == expected_session && epoch == expected_epoch && id == expected_id &&
           ticket == expected_ticket && data == expected_data && flags == expected_flags);
    assert(*taken == expected_taken);
    *taken = !expected_taken;
    ++submitted_calls;
    return submitted_result;
}
bool __real_IHS_SessionVideoDecodeFeedback(IHS_Session *session, const IHS_VideoEpochInfo *epoch,
                                           IHS_StreamVideoSubmitResult result) {
    assert(session == expected_session && epoch == expected_epoch && result == expected_feedback);
    ++decode_feedback_calls;
    return decode_accepted;
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
    /* Video roles come from the actual channel type, not an assumed ID4.
     * Metadata must be sampled before the real consumer mutates/owns the body. */
    IHS_SessionChannelData data_channel = {
        .base = {.id = 9, .type = IHS_SessionChannelTypeDataVideo, .session = &normal}};
    expected_channel = &data_channel.base;
    expected_frame = &frame;
    uint8_t padded[27] = {0};
    padded[7] = k_EStreamDataPacket;
    padded[8] = 0xff;
    padded[9] = 0xff; /* frame65535 / sequence0 */
    padded[22] = VideoFrameFlagKeyFrame | VideoFrameFlagFrameFinish;
    frame.body = (IHS_Buffer)IHS_BUFFER_WRAP(padded, sizeof(padded));
    IHS_BufferOffsetBy(&frame.body, 7);
    IHS_Buffer saved = frame.body;
    __wrap_IHS_SessionChannelDataReceiveReliableFrame(expected_channel, &frame);
    __wrap_IHS_SessionChannelDataReceiveFrame(&data_channel, &frame);
    assert(!memcmp(&saved, &frame.body, sizeof(saved)));
    uint64_t packed = (UINT64_C(1) << 40) | (uint64_t)padded[22] << 32 | 65535;
    assert(atomic_load(&video_channel) == 9 && atomic_load(&video_complete) == 1);
    assert(atomic_load(&video_key) == 1 && atomic_load(&video_finish) == 1);
    assert(atomic_load(&video_worker) == 1 && atomic_load(&worker_key) == 1);
    assert(atomic_load(&video_last) == packed && atomic_load(&worker_last) == packed);
    reads = pointer_calls;
    for (size_t size = 0; size < 20; ++size) {
        frame.body.size = size;
        __wrap_IHS_SessionChannelDataReceiveFrame(&data_channel, &frame);
        assert(pointer_calls == reads);
    }
    frame.body = (IHS_Buffer){0};
    __wrap_IHS_SessionChannelDataReceiveFrame(&data_channel, &frame);
    assert(pointer_calls == reads && atomic_load(&worker_key) == 1);
    frame.body = saved;
    padded[7] = k_EStreamDataLost;
    __wrap_IHS_SessionChannelDataReceiveFrame(&data_channel, &frame);
    assert(atomic_load(&worker_last) == packed); /* non-video message ignored */
    padded[7] = k_EStreamDataPacket;
    data_channel.base.session = &test;
    __wrap_IHS_SessionChannelDataReceiveReliableFrame(expected_channel, &frame);
    __wrap_IHS_SessionChannelDataReceiveFrame(&data_channel, &frame);
    __wrap_IHS_SessionChannelDataLost(expected_channel);
    data_channel.base.session = &normal;
    data_channel.base.type = IHS_SessionChannelTypeDataAudio;
    __wrap_IHS_SessionChannelDataReceiveReliableFrame(expected_channel, &frame);
    __wrap_IHS_SessionChannelDataReceiveFrame(&data_channel, &frame);
    assert(atomic_load(&video_complete) == 1 && atomic_load(&video_worker) == 23);
    data_channel.base.type = IHS_SessionChannelTypeDataVideo;
    __wrap_IHS_SessionChannelDataLost(expected_channel);
    assert(atomic_load(&video_requests) == 1);
    packet.header.channelId = 9;
    packet.header.retransmitCount = 2;
    packet.header.type = IHS_SessionPacketTypeUnreliableFrag;
    expected_packet = &packet;
    expected_session = &normal;
    __wrap_IHS_SessionUnreliableReceived(&normal, &packet);
    assert(atomic_load(&wire_ordinary[9]) == 1 && atomic_load(&wire_retry[9]) == 1);
    uint8_t lost_wire[14] = {3, 0, 0, 0, 9};
    lost_wire[13] = k_EStreamDataLost;
    IHS_UDPPacket lost_udp = {.buffer = IHS_BUFFER_WRAP(lost_wire, sizeof(lost_wire))};
    expected_udp = &lost_udp;
    expected_socket = normal.base.socket;
    socket_result = true;
    assert(__wrap_IHS_UDPSocketSend(expected_socket, &lost_udp));
    socket_result = false;
    assert(!__wrap_IHS_UDPSocketSend(expected_socket, &lost_udp));
    expected_socket = test.base.socket;
    assert(!__wrap_IHS_UDPSocketSend(expected_socket, &lost_udp));
    assert(atomic_load(&request_sent) == 1 && atomic_load(&request_failed) == 1);
    assert(atomic_load(&feedback) == 1 && atomic_load(&send_fail) == 1);
    IHS_VideoEpochInfo epoch = {.session_id = 7, .video_epoch = 8};
    expected_epoch = &epoch;
    unsigned ticket_token;
    expected_ticket = (void *)&ticket_token;
    expected_data = &frame.body;
    expected_id = 65535;
    expected_flags = IHS_StreamVideoFrameKeyFrame | IHS_StreamVideoFrameFlushHandled;
    for (unsigned trial = 0; trial < 3; ++trial) {
        expected_session = trial == 0 ? &test : &normal;
        expected_taken = trial == 1;
        bool taken = expected_taken;
        submitted_result = trial == 2 ? IHS_StreamVideoSubmitError : IHS_StreamVideoSubmitReset;
        assert(__wrap_sl_media_video_submit_tracked(expected_session, &epoch, expected_id,
                                                    expected_ticket, expected_data, expected_flags,
                                                    &taken) == submitted_result);
        assert(taken == !expected_taken);
        expected_feedback = trial == 2 ? IHS_StreamVideoSubmitError
                                       : IHS_StreamVideoSubmitResetAndReportLost |
                                             IHS_StreamVideoSubmitDisableHardware;
        decode_accepted = trial == 1;
        assert(__wrap_IHS_SessionVideoDecodeFeedback(expected_session, &epoch, expected_feedback) ==
               decode_accepted);
    }
    assert(submitted_calls == 3 && atomic_load(&submit_calls) == 2);
    assert(atomic_load(&submit_returns) == 2 && atomic_load(&submit_keys) == 2);
    assert(atomic_load(&submit_errors) == 1 &&
           atomic_load(&submit_last) ==
               ((UINT64_C(1) << 48) | (uint64_t)expected_flags << 16 | 65535));
    assert(decode_feedback_calls == 3 && atomic_load(&decode_feedback) == 2);
    assert(atomic_load(&feedback_accepted) == 1 && atomic_load(&reset_flags) == 1 &&
           atomic_load(&lost_flags) == 1 && atomic_load(&disable_flags) == 1);
    puts("Observer forwarding, network-test exclusion, m0/parity and actual socket outcomes "
         "passed.");
    return 0;
}
