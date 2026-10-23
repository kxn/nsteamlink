/* Real polled IHS parser/timer ownership across three ordinary handoffs, then
 * explicit authorization/service actions. Final sends are recorded providers. */
#include <ihslib/client.h>
#include "client_pri.h"
#include "endianness.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static IHS_HostInfo peer;
static unsigned sends, accepts, failures, statuses;
uint32_t __wrap_IHS_CryptoRandomUInt32(void) { return 17; }
bool __wrap_IHS_ClientSendControl(IHS_Client *c, const IHS_HostInfo *h,
    const IHS_SocketAddress *source, ERemoteClientBroadcastMsg tag, ProtobufCMessage *body) {
    (void)c; (void)h; (void)source; (void)tag; (void)body; ++sends; return true;
}
static bool host(IHS_Client *c, uint64_t id, IHS_HostInfo *out, void *ctx) {
    (void)c; (void)ctx;
    if (id != peer.clientId) return false;
    *out = peer; return true;
}
static void accepted(IHS_Client *c, const IHS_HostInfo *h,
    const IHS_StreamingConnection *ticket, void *ctx) {
    (void)c; (void)h; (void)ctx;
    assert(ticket->sessionKeyLen == 32);
    for (unsigned n = 0; n < 32; ++n) assert(ticket->sessionKey[n] == n);
    assert(!IHS_ClientStreamingHandoff(c)); /* Still inside the inbound batch. */
    ++accepts;
}
static void failed(IHS_Client *c, const IHS_HostInfo *h, IHS_StreamingResult r, void *ctx) {
    (void)c; (void)h; (void)r; (void)ctx; ++failures;
}
static void observed(IHS_Client *c, const IHS_HostInfo *h, void *ctx) {
    (void)c; (void)h; (void)ctx; ++statuses;
}
static void frame(IHS_Client *c, ERemoteClientBroadcastMsg type, ProtobufCMessage *body) {
    uint8_t wire[4096];
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_msg_type = true;
    header.client_id = 123; header.msg_type = type;
    size_t hs = cmsg_remote_client_broadcast_header__get_packed_size(&header);
    size_t bs = protobuf_c_message_get_packed_size(body);
    assert(hs+bs+16 <= sizeof(wire));
    memcpy(wire, "\xff\xff\xff\xff\x21\x4c\x5f\xa0", 8);
    IHS_WriteUInt32LE(wire+8, (uint32_t)hs);
    cmsg_remote_client_broadcast_header__pack(&header, wire+12);
    IHS_WriteUInt32LE(wire+12+hs, (uint32_t)bs);
    protobuf_c_message_pack(body, wire+16+hs);
    IHS_ClientReceiveRemotePacket(c, wire, 16+hs+bs);
}
int main(void) {
    IHS_Init();
    uint8_t secret[32], good[4096]; char hex[8192];
    assert(scanf("%8191s", hex) == 1 && strlen(hex)%2 == 0);
    size_t size = strlen(hex)/2;
    for (size_t n = 0; n < size; ++n) { unsigned b; assert(sscanf(hex+2*n, "%2x", &b) == 1); good[n] = b; }
    for (unsigned n = 0; n < 32; ++n) secret[n] = 32+n;
    IHS_ClientConfig config = {.deviceId=UINT64_C(0x1122334455667788), .secretKey=secret,
        .deviceName="handoff owner"};
    IHS_Client *c = IHS_ClientCreatePolled(&config); assert(c);
    peer.clientId=123; peer.universe=IHS_SteamUniversePublic; peer.address.port=27036;
    assert(IHS_IPAddressFromString(&peer.address.ip,"127.0.0.1"));
    IHS_ClientRoutingCallbacks routing = {.host=host};
    IHS_ClientStreamingCallbacks stream = {.connection=accepted, .failed=failed};
    IHS_ClientDiscoveryCallbacks discovery = {.discovered=observed};
    IHS_ClientSetRoutingCallbacks(c,&routing,NULL);
    IHS_ClientSetStreamingCallbacks(c,&stream,NULL);
    IHS_ClientSetDiscoveryCallbacks(c,&discovery,NULL);
    IHS_StreamingRequest request = {0};
    assert(!IHS_ClientStreamingHandoff(NULL) && !IHS_ClientStreamingHandoff(c));
    for (unsigned launch = 0; launch < 3; ++launch) {
        assert(IHS_ClientStreamingRequest(c,&peer,&request));
        assert(IHS_ClientHandshakePhase(c)==5 && !IHS_ClientStreamingHandoff(c));
        IHS_ClientReceiveRemotePacket(c,good,size);
        assert(accepts==launch+1 && IHS_ClientHandshakePhase(c)==6);
        c->authorizationCache.key=malloc(16); assert(c->authorizationCache.key);
        memset(c->authorizationCache.key,17,16); c->authorizationCache.keyLen=16;
        c->authorizationCache.result=k_ERemoteDeviceAuthorizationSuccess;
        unsigned before=sends;
        assert(IHS_ClientStreamingHandoff(c));
        assert(!IHS_ClientStreamingHandoff(c));
        assert(!c->taskHandles.streaming && IHS_ClientHandshakePhase(c)==1 && sends==before);
        assert(!c->authorizationCache.key && !c->authorizationCache.keyLen &&
               c->authorizationCache.result==k_ERemoteDeviceAuthorizationFailed);
        IHS_ClientReceiveRemotePacket(c,good,size);
        CMsgRemoteDeviceStreamingResponse response = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
        response.request_id=17;
        for (int result=1; result<=15; ++result) {
            response.result=(ERemoteDeviceStreamingResult)result;
            frame(c,k_ERemoteDeviceStreamingResponse,&response.base);
        }
        uint8_t challenge[]={1,2,3};
        CMsgRemoteDeviceProofRequest proof=CMSG_REMOTE_DEVICE_PROOF_REQUEST__INIT;
        proof.challenge=(ProtobufCBinaryData){sizeof(challenge),challenge};
        proof.has_request_id=proof.has_update_secret=true; proof.request_id=17; proof.update_secret=true;
        frame(c,k_ERemoteDeviceProofRequest,&proof.base);
        assert(!IHS_ClientHandshakeFail(c,IHS_AuthorizationFailed));
        assert(sends==before && accepts==launch+1 && !failures && IHS_ClientHandshakePhase(c)==1);
        uint8_t after[32]; IHS_ClientGetSecretKey(c,after);
        assert(!memcmp(after,secret,sizeof(secret)));
        CMsgRemoteClientBroadcastStatus status=CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
        status.hostname="Visible";
        status.has_version=status.has_min_version=status.has_euniverse=true;
        status.version=10; status.min_version=0; status.euniverse=IHS_SteamUniversePublic;
        frame(c,k_ERemoteClientBroadcastMsgStatus,&status.base);
        assert(statuses==launch+1);
        if (launch==1) {
            // A fresh explicit authorization action reopens handshake ingress.
            assert(IHS_ClientAuthorizationRequest(c,&peer,"1234"));
            assert(!c->streamingHandedOff);
            IHS_ClientAuthorizationCancel(c);
        }
    }
    // Explicit pairing is an independent new action, which reopens ingress.
    assert(IHS_ClientAuthorizationAwaitService(c));
    assert(IHS_ClientHandshakePhase(c)==2 && !c->streamingHandedOff);
    IHS_ClientAuthorizationCancel(c);
    assert(IHS_ClientHandshakePhase(c)==1);
    IHS_ClientStop(c); IHS_ClientThreadedJoin(c); IHS_ClientDestroy(c); IHS_Quit();
    printf("{\"accepts\":%u,\"failures\":%u,\"statuses\":%u,\"clean\":true}\n",accepts,failures,statuses);
}
