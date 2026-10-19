/* Production config -> encryption -> frame queue/fragmentation -> packet send
 * -> CRC/window -> decryption -> protobuf. Initial transport/client states,
 * queue draining, retry invocation and final BaseSend are explicit adapters.
 * This does not authenticate to Steam or exercise a real socket/decoder. */
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "live_media_config_observer.h"
#include "session/session_queue.h"
#include "session/window.h"
#include "test_session.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

static IHS_Session *session;
static IHS_SessionPacketsWindow *window;
static bool first_failure, expected_fec, expected_crc;
static unsigned messages, fragments;
static uint64_t sequence;

bool __wrap_IHS_BaseSend(IHS_Base *base, IHS_SocketAddress address, const IHS_Buffer *wire) {
    (void)address;
    assert(base == &session->base);
    const uint8_t *b = IHS_BufferPointer(wire);
    if ((b[0] & 127) != IHS_SessionPacketTypeReliable &&
        (b[0] & 127) != IHS_SessionPacketTypeReliableFrag)
        return true;
    assert(b[4] == 1 && !!(b[0] & 128) == expected_crc);
    IHS_UDPPacket udp = {.buffer = *wire};
    bool sent = !first_failure;
    first_failure = false;
    probe_config_socket(base->socket, &udp, sent);
    if (!sent) {
        errno = EAGAIN;
        return false;
    }
    uint8_t *bytes = malloc(wire->size);
    assert(bytes);
    memcpy(bytes, b, wire->size);
    IHS_Buffer raw = IHS_BUFFER_WRAP(bytes, wire->size);
    IHS_SessionPacket packet = {0};
    assert(IHS_SessionPacketParse(&packet, &raw) == IHS_SessionPacketResultOK);
    assert(IHS_SessionPacketsWindowAdd(window, &packet));
    ++fragments;
    IHS_SessionPacketClear(&packet, true);
    IHS_SessionFrame frame = {.body = IHS_BUFFER_INIT(2048, 0)};
    if (IHS_SessionPacketsWindowPoll(window, &frame)) {
        unsigned tag = *IHS_BufferPointer(&frame.body);
        assert(tag == (messages ? 99 : 4));
        IHS_BufferOffsetBy(&frame.body, 1);
        IHS_Buffer plain = IHS_BUFFER_INIT(2048, 0);
        uint64_t actual;
        assert(IHS_SessionFrameDecrypt(session, &frame.body, &plain, sequence, &actual) ==
               IHS_SessionFrameDecryptOK);
        assert(actual == sequence++);
        CStreamingClientConfig *config;
        ProtobufCMessage *message;
        if (tag == 4) {
            CNegotiationSetConfigMsg *m =
                cnegotiation_set_config_msg__unpack(NULL, plain.size, IHS_BufferPointer(&plain));
            assert(m && m->config && m->streaming_client_caps &&
                   strlen(m->streaming_client_caps->system_info) == 1200);
            config = m->streaming_client_config;
            message = &m->base;
        } else {
            CSetStreamingClientConfig *m =
                cset_streaming_client_config__unpack(NULL, plain.size, IHS_BufferPointer(&plain));
            assert(m);
            config = m->config;
            message = &m->base;
        }
        assert(config && config->has_enable_unreliable_fec &&
               !!config->enable_unreliable_fec == expected_fec);
        protobuf_c_message_free_unpacked(message, NULL);
        IHS_BufferClear(&plain, true);
        ++messages;
    }
    IHS_BufferClear(&frame.body, true);
    return true;
}
static void drain(void) {
    QueuedPacket *q;
    while ((q = (void *)IHS_QueuePoll(session->sendQueue))) {
        int result = IHS_SessionSendPacketResult(session, &q->packet);
        if (result == 1) {
            ++q->packet.header.retransmitCount; /* explicit retry input */
            assert(IHS_SessionSendPacketResult(session, &q->packet) == 0);
        } else
            assert(result == 0);
        IHS_SessionPacketClear(&q->packet, true);
        IHS_QueueItemFree((void *)q);
    }
}
int main(void) {
    alarm(10);
    IHS_Init();
    for (unsigned c = 0; c < 2; ++c)
        for (unsigned fec = 0; fec < 2; ++fec) {
            expected_crc = c;
            expected_fec = fec;
            messages = fragments = 0;
            sequence = 0;
            session = IHS_TestSessionCreate();
            assert(session);
            IHS_TimerTaskStopImmediate(session->retransmission.timer);
            session->state.connectionState = IHS_SessionConnectionStateHandshaking;
            session->state.connectionId = 7;
            session->state.hostConnectionId = 34;
            session->state.crcRequired = c;
            session->state.mtu = 512;
            unsigned socket_token;
            session->base.socket = (void *)&socket_token;
            session->outgoing.rate[0] = session->outgoing.rate[1] = 0;
            window = IHS_SessionPacketsWindowCreateReliable(64, 0);
            assert(window);
            char text[1201];
            memset(text, 'x', sizeof(text) - 1);
            text[sizeof(text) - 1] = 0;
            CStreamingClientConfig config = CSTREAMING_CLIENT_CONFIG__INIT;
            config.has_enable_unreliable_fec = true;
            config.enable_unreliable_fec = fec;
            CStreamingClientCaps caps = CSTREAMING_CLIENT_CAPS__INIT;
            caps.system_info = text;
            CNegotiatedConfig negotiated = CNEGOTIATED_CONFIG__INIT;
            CNegotiationSetConfigMsg request = CNEGOTIATION_SET_CONFIG_MSG__INIT;
            request.config = &negotiated;
            request.streaming_client_config = &config;
            request.streaming_client_caps = &caps;
            first_failure = true;
            assert(IHS_SessionChannelControlSend(session->channels[1],
                                                 k_EStreamControlNegotiationSetConfig,
                                                 &request.base, IHS_PACKET_ID_NEXT));
            drain();
            assert(messages == 1 && fragments >= 3);
            /* Real negotiation parser at a declared post-decryption boundary.
             * The required config is present; an absent one must fail unpack. */
            uint8_t peer[64];
            CNegotiationSetConfigMsg response = CNEGOTIATION_SET_CONFIG_MSG__INIT;
            response.config = &negotiated;
            size_t n = cnegotiation_set_config_msg__pack(&response, peer);
            IHS_Buffer payload = IHS_BUFFER_WRAP(peer, n);
            IHS_SessionPacketHeader header = {0};
            session->state.connectionState = IHS_SessionConnectionStateNegotiating;
            IHS_SessionChannelControlOnNegotiation(
                session->channels[1], k_EStreamControlNegotiationSetConfig, &payload, &header);
            assert(session->state.connectionState == IHS_SessionConnectionStateStarting);
            session->state.connectionState = IHS_SessionConnectionStateConnected;
            uint8_t prefs[16];
            n = cstreaming_client_config__pack(&config, prefs);
            assert(IHS_SessionSetStreamingClientConfig(session, prefs, n, false));
            drain();
            assert(messages == 2 && !probe_config_current);
            session->base.socket = NULL;
            IHS_SessionPacketsWindowDestroy(window);
            IHS_SessionDestroy(session);
        }
    assert(atomic_load(&probe_config_used) == 8 && !atomic_load(&probe_config_overflow));
    assert(atomic_load(&probe_config_sent_fec[0]) == 12 &&
           atomic_load(&probe_config_sent_fec[1]) == 12);
    assert(atomic_load(&probe_config_calls[0]) == 4 &&
           atomic_load(&probe_config_admitted[0]) == 4 &&
           atomic_load(&probe_config_queued[0]) == 4 && atomic_load(&probe_config_sent[0]) == 4 &&
           atomic_load(&probe_config_failed[0]) == 4);
    assert(atomic_load(&probe_config_calls[1]) == 4 &&
           atomic_load(&probe_config_admitted[1]) == 4 &&
           atomic_load(&probe_config_queued[1]) == 4 && atomic_load(&probe_config_sent[1]) == 4 &&
           !atomic_load(&probe_config_failed[1]) && atomic_load(&probe_peer_config) == 4);
    IHS_Quit();
    alarm(0);
    return 0;
}
