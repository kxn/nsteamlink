/* Real production session/OS UDP/control/crypto. The loopback peer is an
 * explicit fixture. Wrappers observe completed handlers and forward unchanged. */
#include "ihslib.h"
#include "session/session_pri.h"
#include "session/channels/ch_control.h"
#include "ihs_buffer_ext.h"
#include "crc32c.h"
#include <assert.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static atomic_bool requested, responded, serverDrained;
static bool missingServer;
void __real_IHS_SessionChannelControlRequestAuthentication(IHS_SessionChannel *);
void __wrap_IHS_SessionChannelControlRequestAuthentication(IHS_SessionChannel *c) {
    __real_IHS_SessionChannelControlRequestAuthentication(c);
    atomic_store(&requested,true);
}
void __real_IHS_SessionChannelControlOnAuthentication(IHS_SessionChannel *,EStreamControlMessage,IHS_Buffer *,const IHS_SessionPacketHeader *);
void __wrap_IHS_SessionChannelControlOnAuthentication(IHS_SessionChannel *c,EStreamControlMessage t,IHS_Buffer *p,const IHS_SessionPacketHeader *h) {
    __real_IHS_SessionChannelControlOnAuthentication(c,t,p,h);
    atomic_store(&responded,true);
}
void __real_IHS_SessionChannelControlDrainIncoming(IHS_SessionChannel *);
void __wrap_IHS_SessionChannelControlDrainIncoming(IHS_SessionChannel *c) {
    IHS_SessionChannelControl *control=(void *)c;
    IHS_MutexLock(control->incomingLock);
    bool incoming=control->incomingCount!=0;
    IHS_MutexUnlock(control->incomingLock);
    __real_IHS_SessionChannelControlDrainIncoming(c);
    if(missingServer && incoming) atomic_store(&serverDrained,true);
}
static size_t unhex(const char *text,uint8_t *bytes) {
    size_t n=strlen(text)/2;assert(n<256 && !(strlen(text)&1));
    for(size_t i=0;i<n;++i) {unsigned byte;assert(sscanf(text+2*i,"%2x",&byte)==1);bytes[i]=(uint8_t)byte;}
    return n;
}
static uint64_t millis(void) {
    struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));
    return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
static void sendPeer(int socket,const struct sockaddr_in *address,uint8_t type,uint8_t local,uint8_t channel,uint16_t id,const uint8_t *data,size_t size,bool crc) {
    uint8_t wire[512]={type,0,7,local,channel};
    wire[7]=(uint8_t)id;wire[8]=(uint8_t)(id>>8);
    wire[9]=0x40;wire[10]=0x42;wire[11]=0x0f; /* Explicit peer timestamp 1000000. */
    assert(size<sizeof(wire)-17);memcpy(wire+13,data,size);size+=13;
    if(crc) {wire[0]|=128;uint32_t value=IHS_CRC32C(wire,size);for(unsigned n=0;n<4;++n)wire[size++]=(uint8_t)(value>>(8*n));}
    assert(sendto(socket,wire,size,0,(const struct sockaddr *)address,sizeof(*address))==(ssize_t)size);
}
int main(int argc,char **argv) {
    assert(argc==5);
    bool crc=atoi(argv[1])!=0,hasResponse=strcmp(argv[3],"-")!=0;
    missingServer=atoi(argv[4])!=0;
    uint8_t server[256],response[256];size_t serverSize=unhex(argv[2],server),responseSize=hasResponse?unhex(argv[3],response):0;
    int peer=socket(AF_INET,SOCK_DGRAM,0);assert(peer>=0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!bind(peer,(struct sockaddr *)&address,sizeof(address)));
    socklen_t addressSize=sizeof(address);assert(!getsockname(peer,(struct sockaddr *)&address,&addressSize));
    IHS_Init();
    const uint8_t secret[32]={0};IHS_ClientConfig client={.deviceId=1,.secretKey=secret,.deviceName="UDP auth fixture"};
    IHS_SessionInfo info={.address.port=ntohs(address.sin_port),.sessionKeyLen=32,.steamId=0};
    assert(IHS_IPAddressFromString(&info.address.ip,"127.0.0.1"));
    for(unsigned n=0;n<32;++n)info.sessionKey[n]=(uint8_t)n;
    IHS_Session *session=IHS_SessionCreate(&client,&info);assert(session && IHS_SessionConnect(session));
    bool connected=false,handshake=false,reply=false,haveRequest=false;
    uint8_t request[256];size_t requestSize=0;unsigned connects=0,goodbyes=0;
    uint64_t deadline=millis()+5000;
    for(;;) {
        bool finished=missingServer?atomic_load(&serverDrained):hasResponse?atomic_load(&responded):atomic_load(&requested)&&haveRequest;
        if(finished && (!atomic_load(&session->transport.closeRequested) || goodbyes))break;
        assert(millis()<deadline);
        struct pollfd p={.fd=peer,.events=POLLIN};int ready=poll(&p,1,2);assert(ready>=0);if(!ready)continue;
        uint8_t raw[2048];struct sockaddr_in from;socklen_t length=sizeof(from);
        ssize_t size=recvfrom(peer,raw,sizeof(raw),0,(struct sockaddr *)&from,&length);assert(size>=13);
        uint8_t type=raw[0]&127;
        if(type==1) {
            ++connects;assert(size==17 && raw[0]==1 && raw[2] && !memcmp(raw+13,"\xc7\x3d\x8f\x3c",4));
            if(!connected) {sendPeer(peer,&from,2,raw[2],0,0,raw+9,4,crc);connected=true;}
        } else if(type==9) {
            ++goodbyes;assert((size_t)size==(crc?17u:13u));
            assert(raw[2] && raw[3]==7 && raw[4]==0);
            assert(((raw[0]&128)!=0)==crc);
            if(crc) {uint32_t value=0;for(unsigned n=0;n<4;++n)value|=(uint32_t)raw[size-4+n]<<(8*n);assert(IHS_CRC32C(raw,(size_t)size-4)==value);}
        } else if(type==5) {
            assert(raw[2] && raw[3]==7 && raw[4]==1);
            bool actualCrc=(raw[0]&128)!=0;assert(actualCrc==crc);
            if(actualCrc) {uint32_t value=0;for(unsigned n=0;n<4;++n)value|=(uint32_t)raw[size-4+n]<<(8*n);assert(IHS_CRC32C(raw,(size_t)size-4)==value);size-=4;}
            if(raw[13]==6 && !handshake) {assert(size==16 && !memcmp(raw+13,"\x06\x0a\x00",3));sendPeer(peer,&from,5,raw[2],1,0,server,serverSize,crc);handshake=true;}
            else if(raw[13]==1) {
                assert((size_t)size-13<sizeof(request));
                if(haveRequest)assert(requestSize==(size_t)size-13 && !memcmp(request,raw+13,requestSize));
                requestSize=(size_t)size-13;memcpy(request,raw+13,requestSize);haveRequest=true;
                if(hasResponse && !reply) {sendPeer(peer,&from,5,raw[2],1,1,response,responseSize,crc);reply=true;}
            }
        }
    }
    int phase=atomic_load(&session->state.connectionState);
    bool closed=atomic_load(&session->transport.closeRequested);
    int mtu=session->state.mtu; /* Handler terminal synchronizes this RX-owned value. */
    if(!closed)IHS_SessionInterrupt(session);
    IHS_SessionThreadedJoin(session);
    assert(!session->sendThread && !session->base.worker);
    assert(goodbyes==(closed?1u:0u));
    printf("{\"phase\":%d,\"closed\":%s,\"mtu\":%d,\"connects\":%u,\"goodbyes\":%u,\"requested\":%s,\"response_handled\":%s,\"request\":\"",phase,closed?"true":"false",mtu,connects,goodbyes,atomic_load(&requested)?"true":"false",atomic_load(&responded)?"true":"false");
    for(size_t n=0;n<requestSize;++n)printf("%02x",request[n]);
    puts("\"}");
    IHS_SessionDestroy(session);IHS_Quit();assert(!close(peer));return 0;
}
