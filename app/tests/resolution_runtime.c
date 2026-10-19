/* Real production request/callbacks and protobuf serialization. The local UDP
 * peer and operation-mode input are fixtures, not a Steam or Switch device. */
#include "../platforms/common/runtime.c"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "session/channels/ch_control.h"
#include "test_session.h"
#include <assert.h>
#include <poll.h>

static bool docked_input;
static uint16_t peer_port;
bool __wrap_sl_system_docked(void) {
    return docked_input;
}
bool __real_IHS_ClientStreamingRequest(IHS_Client *, const IHS_HostInfo *,
                                       const IHS_StreamingRequest *);
bool __wrap_IHS_ClientStreamingRequest(IHS_Client *c, const IHS_HostInfo *h,
                                       const IHS_StreamingRequest *request) {
    IHS_HostInfo peer = *h;
    peer.address.port = peer_port;
    return __real_IHS_ClientStreamingRequest(c, &peer, request);
}
typedef struct {
    IHS_SessionPacket packet;
    bool reliable;
} queued_packet;
static uint32_t le32(const uint8_t *p) {
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void negotiation(sl_runtime *r, unsigned expected) {
    IHS_Session *s = IHS_TestSessionCreate();
    assert(s);
    IHS_TimerTaskStopImmediate(s->retransmission.timer);
    assert(sl_stream_settings_apply_limited(&r->settings, s, &r->stream_limits));
    IHS_SessionSetSessionCallbacks(s, &session_cb, r);
    s->state.connectionState = IHS_SessionConnectionStateNegotiating;
    CNegotiationInitMsg init = CNEGOTIATION_INIT_MSG__INIT;
    EStreamVideoCodec codec = k_EStreamVideoCodecH264;
    init.n_supported_video_codecs = 1;
    init.supported_video_codecs = &codec;
    IHS_Buffer body = IHS_BUFFER_INIT(1024, 0);
    IHS_BufferAppendMessage(&body, (const ProtobufCMessage *)&init);
    IHS_SessionPacketHeader header = {0};
    IHS_SessionChannelControlOnNegotiation(s->channels[1], k_EStreamControlNegotiationInit, &body,
                                           &header);
    queued_packet *q = (void *)IHS_QueuePoll(s->sendQueue);
    assert(q && *IHS_BufferPointer(&q->packet.body) == k_EStreamControlNegotiationSetConfig);
    IHS_BufferOffsetBy(&q->packet.body, 1);
    IHS_Buffer plain = IHS_BUFFER_INIT(4096, 0);
    uint64_t sequence;
    assert(IHS_SessionFrameDecrypt(s, &q->packet.body, &plain, 0, &sequence) ==
           IHS_SessionFrameDecryptOK);
    CNegotiationSetConfigMsg *reply =
        cnegotiation_set_config_msg__unpack(NULL, plain.size, IHS_BufferPointer(&plain));
    assert(reply && reply->streaming_client_config);
    CStreamingClientConfig *config = reply->streaming_client_config;
    assert(config->desired_resolution_x == expected * 16 / 9 &&
           config->desired_resolution_y == expected);
    assert(config->desired_framerate_numerator == 60 && config->desired_framerate_denominator == 1);
    assert(!config->enable_video_hevc && config->desired_bitrate_kbps == 20000);
    cnegotiation_set_config_msg__free_unpacked(reply, NULL);
    IHS_BufferClear(&body, true);
    IHS_BufferClear(&plain, true);
    IHS_SessionPacketClear(&q->packet, true);
    IHS_QueueItemFree((void *)q);
    IHS_SessionDestroy(s);
}
static void request(sl_resolution mode, bool docked, unsigned expected) {
    if (NSL_TEST_FORCE_1080)
        expected = 1080;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(fd, (const void *)&peer, sizeof(peer)));
    socklen_t length = sizeof(peer);
    assert(!getsockname(fd, (void *)&peer, &length));
    peer_port = ntohs(peer.sin_port);
    sl_runtime r = {.resolution = mode};
    assert(!pthread_mutex_init(&r.lock, NULL));
    r.store = (sl_auth_store){.device_id = 1, .bitrate_kbps = 20000};
    sl_host_registry_init(&r.store.registry);
    assert(sl_stream_settings_init(&r.settings, &r.store));
    /* Reproduce a persisted 720p cap from an earlier session: it must not pin
     * Auto to handheld resolution forever or defeat an explicit 1080p edit. */
    r.settings.config->has_desired_resolution_x = r.settings.config->has_desired_resolution_y =
        true;
    r.settings.config->desired_resolution_x = 1280;
    r.settings.config->desired_resolution_y = 720;
    r.active.host = (sl_host){.id = 1, .client_id = 123, .instance_id = 1};
    strcpy(r.active.host.address, "127.0.0.1");
    r.config = (IHS_ClientConfig){
        .deviceId = 1, .secretKey = r.store.secret, .deviceName = "resolution test"};
    r.client = IHS_ClientCreate(&r.config);
    assert(r.client);
    docked_input = docked;
    assert(request_stream(&r, false));
    struct pollfd wait = {.fd = fd, .events = POLLIN};
    assert(poll(&wait, 1, 3000) == 1);
    uint8_t wire[4096];
    ssize_t bytes = recv(fd, wire, sizeof(wire), 0);
    assert(bytes > 16);
    size_t header_size = le32(wire + 8);
    assert(header_size < (size_t)bytes - 16);
    CMsgRemoteClientBroadcastHeader *header =
        cmsg_remote_client_broadcast_header__unpack(NULL, header_size, wire + 12);
    assert(header && header->msg_type == k_ERemoteDeviceStreamingRequest);
    size_t size = le32(wire + 12 + header_size);
    assert(size == (size_t)bytes - 16 - header_size);
    CMsgRemoteDeviceStreamingRequest *message =
        cmsg_remote_device_streaming_request__unpack(NULL, size, wire + 16 + header_size);
    assert(message && message->maximum_resolution_x == (int32_t)(expected * 16 / 9) &&
           message->maximum_resolution_y == (int32_t)expected);
    cmsg_remote_device_streaming_request__free_unpacked(message, NULL);
    cmsg_remote_client_broadcast_header__free_unpacked(header, NULL);
    /* A mode edge/edit after the ticket must not change negotiation halfway. */
    docked_input = !docked;
    r.resolution = expected == 720 ? SL_RESOLUTION_1080 : SL_RESOLUTION_720;
    negotiation(&r, expected);
    sl_stream_settings_drain(&r.settings);
    negotiation(&r, expected); /* Host config callbacks cannot unfreeze it. */
    IHS_ClientStop(r.client);
    IHS_ClientThreadedJoin(r.client);
    IHS_ClientDestroy(r.client);
    sl_stream_settings_destroy(&r.settings);
    pthread_mutex_destroy(&r.lock);
    close(fd);
}
int main(void) {
    IHS_Init();
    request(SL_RESOLUTION_AUTO, false, 720);
    request(SL_RESOLUTION_AUTO, true, 1080);
    request(SL_RESOLUTION_720, false, 720);
    request(SL_RESOLUTION_720, true, 720);
    request(SL_RESOLUTION_1080, false, 1080);
    request(SL_RESOLUTION_1080, true, 1080);
    IHS_Quit();
    puts("PASS six resolution/mode combinations: real UDP requests, encrypted SetConfig, frozen "
         "session and stale-cap recovery");
    return 0;
}
