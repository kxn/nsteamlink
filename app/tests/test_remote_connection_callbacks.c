/* Actual factory/adapters and protocol dispatch. WebSocket-ready and CM input
 * are explicit providers; no HTTP/TLS, Steam, media or Switch runs here. */
#include "../platforms/common/remote_connection.c"
#include "endianness.h"
#include "discovery.pb-c.h"
#include <ihslib.h>
#include <assert.h>

static unsigned failures;
#define EXPECT(c) do { if (!(c)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); ++failures; } } while (0)
typedef struct {
    unsigned magic, controls, begins, prepares, aborts, disconnected, streams;
    bool consume, begin_ok, prepare_ok;
    unsigned close_stage;
    sl_remote *protocol;
} application;
static application *app(void *ctx) {
    application *a = ctx;
    assert(a && a->magic == 0x4e534c);
    return a;
}
static void app_connected(bool ready, void *ctx) {
    application *a = app(ctx);
    if (!ready) { EXPECT(a->close_stage == 1); a->close_stage = 2; }
}
static void app_disconnecting(void *ctx) {
    application *a = app(ctx);
    EXPECT(sl_remote_ready(a->protocol));
    ++a->disconnected;
    a->close_stage = 1;
}
static bool app_control(const uint8_t *wire, size_t size, void *ctx) {
    application *a = app(ctx);
    EXPECT(size >= 16 && wire[0] == 255);
    ++a->controls;
    return a->consume;
}
static bool app_begin(void *ctx) { application *a = app(ctx); ++a->begins; return a->begin_ok; }
static bool app_prepare(IHS_SteamUniverse universe, const char *pin, uint8_t **body,
                        size_t *size, void *ctx) {
    application *a = app(ctx);
    EXPECT(universe == IHS_SteamUniversePublic && !strcmp(pin, "0042"));
    ++a->prepares;
    if (!a->prepare_ok) return false;
    *body = malloc(2); assert(*body);
    (*body)[0] = 8; (*body)[1] = 1; *size = 2; /* Prepared-body endpoint. */
    return true;
}
static void app_abort(void *ctx) { ++app(ctx)->aborts; }
static void app_stream(IHS_StreamingResult result, const sl_remote_material *m, void *ctx) {
    application *a = app(ctx);
    EXPECT(result == IHS_StreamingSuccess && m && m->transport == 4 && m->key_size == 16);
    ++a->streams;
}
static bool reply(sl_remote *p, unsigned kind, const void *body, size_t size) {
    uint8_t wire[2048]; sl_proto_writer w = {wire, 0, sizeof(wire), false};
    sl_proto_uint(&w, 1, 1); sl_proto_bytes(&w, kind, body, size);
    assert(!w.invalid);
    return sl_remote_receive(p, wire, w.size);
}
static void control_reply(sl_remote *p, unsigned result, uint32_t id, const uint8_t secret[32]) {
    uint8_t encrypted[64], plain[16] = {1}; size_t encrypted_size = sizeof(encrypted);
    assert(!IHS_CryptoSymmetricEncrypt(plain, sizeof(plain), secret, 32, encrypted, &encrypted_size));
    CMsgRemoteClientBroadcastHeader h = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    h.has_client_id = h.has_msg_type = true; h.client_id = 123; h.msg_type = k_ERemoteDeviceStreamingResponse;
    CMsgRemoteDeviceStreamingResponse r = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
    r.request_id = id; r.result = result; r.has_transport = r.has_encrypted_session_key = true;
    r.transport = k_EStreamTransportSDR;
    r.encrypted_session_key = (ProtobufCBinaryData){encrypted_size, encrypted};
    uint8_t packet[1024], cm[1100];
    size_t hs = protobuf_c_message_get_packed_size(&h.base), ms = protobuf_c_message_get_packed_size(&r.base);
    static const uint8_t magic[8] = {255,255,255,255,33,76,95,160};
    memcpy(packet, magic, 8); IHS_WriteUInt32LE(packet+8, hs);
    protobuf_c_message_pack(&h.base, packet+12); IHS_WriteUInt32LE(packet+12+hs, ms);
    protobuf_c_message_pack(&r.base, packet+16+hs);
    sl_proto_writer w = {cm, 0, sizeof(cm), false}; sl_proto_bytes(&w, 1, packet, 16+hs+ms);
    assert(!w.invalid && reply(p, 6, cm, w.size));
}
static sl_remote_connection *create(application *a, const uint8_t secret[32], bool shared) {
    IHS_ClientConfig cfg = {.deviceId=42, .secretKey=secret, .deviceName="adapter fixture"};
    sl_remote_callbacks cb = {.stream_result=app_stream};
    if (shared) cb = (sl_remote_callbacks){.connected=app_connected,
        .disconnecting=app_disconnecting, .control_packet=app_control, .begin_pairing=app_begin,
        .prepare_pairing=app_prepare, .abort_pairing=app_abort, .stream_result=app_stream};
    sl_remote_connection *c = sl_remote_connection_create(&cfg, &cb, a); assert(c);
    c->state = NET_WEBSOCKET; /* Explicit transport boundary, actual factory/table retained. */
    a->protocol = sl_remote_connection_protocol(c); assert(sl_remote_open(a->protocol));
    uint8_t body[32]; sl_proto_writer w = {body,0,sizeof(body),false};
    sl_proto_fixed64(&w,1,1001); sl_proto_uint(&w,2,IHS_SteamUniversePublic);
    assert(reply(a->protocol,2,body,w.size));
    return c;
}
int main(void) {
    IHS_Init(); uint8_t secret[32] = {0};
    application a = {.magic=0x4e534c,.consume=true,.begin_ok=true,.prepare_ok=true};
    sl_remote_connection *c = create(&a,secret,true);
    control_reply(a.protocol,k_ERemoteDeviceStreamingInProgress,17,secret);
    EXPECT(a.controls == 1 && a.streams == 0);
    EXPECT(sl_remote_pair(a.protocol)); EXPECT(a.begins == 1);
    uint8_t pin[16]; sl_proto_writer w = {pin,0,sizeof(pin),false}; sl_proto_uint(&w,1,42);
    assert(reply(a.protocol,3,pin,w.size)); EXPECT(a.prepares == 1);
    sl_remote_cancel(a.protocol); EXPECT(a.aborts == 1);
    a.begin_ok = false;
    EXPECT(!sl_remote_pair(a.protocol)); EXPECT(a.begins == 2);
    sl_remote_cancel(a.protocol);
    a.begin_ok = true; a.prepare_ok = false;
    EXPECT(sl_remote_pair(a.protocol)); assert(reply(a.protocol,3,pin,w.size));
    EXPECT(a.prepares == 2 && a.aborts >= 2);
    sl_remote_close(a.protocol); EXPECT(a.disconnected == 1 && a.close_stage == 2);
    sl_remote_connection_destroy(c);
    /* Callback absence must keep the standalone legacy strategy. Explicit
     * false from control_packet must also retain legacy fallback. */
    for (unsigned optional=0;optional<2;++optional) {
        application b = {.magic=0x4e534c,.consume=false,.begin_ok=true,.prepare_ok=true};
        c = create(&b,secret,optional != 0);
        sl_remote_peer peer = {.client_id=123,.steam_id=UINT64_C(76561198000000001)};
        memcpy(peer.secret,secret,32); assert(sl_remote_watch(b.protocol,&peer,1));
        IHS_StreamingRequest request = {0}; sl_remote_stream_options options = {.network_test=true,.sns=true};
        assert(sl_remote_stream_ex(b.protocol,123,&request,&options));
        /* The legacy ID is decoded from its actual first outgoing frame. */
        sl_remote_update(b.protocol,1000);
        struct outgoing *q = &c->fifo[(c->head+c->count-1)%FIFO_LIMIT];
        assert(q->size >= 6 && (q->data[1]&128));
        size_t pos=2, length=q->data[1]&127;
        if(length==126) { length=(size_t)q->data[2]*256+q->data[3]; pos=4; }
        assert(length<=4096 && pos+4+length==q->size);
        uint8_t payload[4096]; for(size_t i=0;i<length;++i)payload[i]=q->data[pos+4+i]^q->data[pos+i%4];
        sl_proto_reader outer={payload,length,0,false}; sl_proto_field f; assert(sl_proto_next(&outer,&f)&&f.number==7);
        sl_proto_reader notification={f.bytes,f.size,0,false}; uint32_t id=0;
        while(sl_proto_next(&notification,&f))if(f.number==4){
            uint32_t hs,ms; IHS_ReadUInt32LE(f.bytes+8,&hs); IHS_ReadUInt32LE(f.bytes+12+hs,&ms);
            CMsgRemoteDeviceStreamingRequest *r=cmsg_remote_device_streaming_request__unpack(NULL,ms,f.bytes+16+hs);
            assert(r); id=r->request_id; cmsg_remote_device_streaming_request__free_unpacked(r,NULL);
        }
        assert(id);
        if (optional) {
            b.consume = true;
            control_reply(b.protocol,k_ERemoteDeviceStreamingSuccess,id,secret);
            EXPECT(b.streams==0 && b.controls==1);
            b.consume = false;
        }
        control_reply(b.protocol,k_ERemoteDeviceStreamingSuccess,id,secret);
        EXPECT(b.streams==1 && b.controls==optional*2);
        if (!optional) {
            /* NULL prepare_pairing must still invoke the legacy producer,
             * rather than selecting a placeholder shared callback. */
            sl_remote_cancel(b.protocol);
            assert(sl_remote_pair(b.protocol) && reply(b.protocol,3,pin,w.size));
            EXPECT(b.prepares==0 && b.begins==0);
        }
        sl_remote_cancel(b.protocol); sl_remote_close(b.protocol); sl_remote_connection_destroy(c);
    }
    IHS_Quit(); printf("Factory callbacks: failures=%u\n",failures); return failures ? 1 : 0;
}
