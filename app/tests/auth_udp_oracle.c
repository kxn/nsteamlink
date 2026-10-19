/* Real production session/OS UDP/control/crypto. The loopback peer is an
 * explicit fixture. Wrappers observe completed handlers and forward unchanged. */
#include "ihslib.h"
#include "session/session_pri.h"
#include "session/channels/ch_control.h"
#include "ihs_buffer_ext.h"
#include "crc32c.h"
#include "stream_settings.h"
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
#include "udp_video_load.h"
#include "udp_video_backend.h"
#include "udp_microphone_backend.h"
#include "udp_audio_backend.h"
#include "udp_rx_observer.h"

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
static void sendEncryptedPeer(IHS_Session *s,int socket,const struct sockaddr_in *address,uint8_t local,uint16_t id,uint8_t kind,const uint8_t *plain,size_t size,uint64_t sequence,bool crc,bool badMac) {
    uint8_t body[512];body[0]=kind;size_t count=sizeof(body)-1;
    /* Match production serialization's non-null empty-body storage. */
    const uint8_t empty=0;if(!size)plain=&empty;
    assert(IHS_SessionFrameEncrypt(s,plain,size,body+1,&count,sequence)==0);
    /* Corrupt ciphertext input, not the real receiver's crypto result. */
    if(badMac)body[1]^=1;
    sendPeer(socket,address,5,local,1,id,body,count+1,crc);
}
int main(int argc,char **argv) {
    bool pressureReady=(argc==12 || argc==14) && !strcmp(argv[1],"--pressure-ready");
    bool pressure=pressureReady || (argc==12 && !strcmp(argv[1],"--pressure"));
    udpLoadPacketObserve=pressureReady;
    if(pressureReady && argc==14) {
        udpLoadSpacingUS=(unsigned)atoi(argv[12]);udpLoadTailSpacingUS=(unsigned)atoi(argv[13]);
        assert(udpLoadSpacingUS<=1000 && udpLoadTailSpacingUS<=1000);
    }
    bool load=pressure || (argc==10 && !strcmp(argv[1],"--load"));
    if(pressure) {
        udpLoadFault=!strcmp(argv[10],"repair")?1:!strcmp(argv[10],"drop")?2:0;
        udpLoadHole=atoi(argv[11]);
    }
    udpLoadMode=load;
    unsigned loadSent=0,loadFrames=load?(unsigned)atoi(argv[8]):0,loadRate=load?(unsigned)atoi(argv[9]):0;
    if(load) {udpLoadDelayUS=(unsigned)atoi(argv[7]);assert(loadFrames && loadFrames<UDP_LOAD_LIMIT && loadRate);}
    uint64_t loadStart=0;
    bool audio=argc==11 && !strcmp(argv[1],"--audio");
    bool audioBurst=audio && !strcmp(argv[9],"burst");udpRXObserve=audioBurst;
    unsigned audioFrames=audio?(unsigned)atoi(argv[7]):0,audioCalls=audio?(unsigned)atoi(argv[8]):0;
    bool audioBlocked=audio && !strcmp(argv[9],"blocked");
    bool audioGap=audio && strcmp(argv[10],"-");
    bool burst=argc==8 && !strcmp(argv[1],"--gap-burst");
    bool gap=burst || (argc==8 && !strcmp(argv[1],"--gap"));udpGapMode=gap || audio;
    bool recover=argc==7 && !strcmp(argv[1],"--recover");
    bool video=load || gap || recover || (argc==7 && !strcmp(argv[1],"--video"));
    bool microphone=argc==6 && !strcmp(argv[1],"--microphone");
    bool limited=argc==6 && !strcmp(argv[1],"--negotiate-limited");
    bool negotiate=audio || limited || microphone || video || (argc==6 && !strcmp(argv[1],"--negotiate"));assert(negotiate || argc==5);
    bool crc=atoi(argv[negotiate?2:1])!=0,hasResponse=negotiate || strcmp(argv[3],"-")!=0;
    bool badMac=negotiate && atoi(argv[5])!=0;
    if(gap) {assert(strlen(argv[7])<=sizeof(udpExpectedFeedback)*2);udpExpectedFeedbackSize=(uint32_t)unhex(argv[7],udpExpectedFeedback);}
    if(audioGap)udpExpectedFeedbackSize=(uint32_t)unhex(argv[10],udpExpectedFeedback);
    bool gapReliable=gap && (udpExpectedFeedback[0]&127)==8;
    assert(!burst || !gapReliable);
    missingServer=!negotiate && atoi(argv[4])!=0;
    uint8_t server[256],response[256],init[256];
    size_t serverSize=unhex(negotiate?"070a0308c00b":argv[2],server),responseSize=hasResponse?unhex(negotiate?"0208001001":argv[3],response):0;
    size_t initSize=negotiate?unhex(argv[4],init):0;
    int peer=socket(AF_INET,SOCK_DGRAM,0);assert(peer>=0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!bind(peer,(struct sockaddr *)&address,sizeof(address)));
    socklen_t addressSize=sizeof(address);assert(!getsockname(peer,(struct sockaddr *)&address,&addressSize));
    IHS_Init();
    const uint8_t secret[32]={0};IHS_ClientConfig client={.deviceId=1,.secretKey=secret,.deviceName="UDP auth fixture"};
    IHS_SessionInfo info={.address.port=ntohs(address.sin_port),.sessionKeyLen=32,.steamId=0};
    assert(IHS_IPAddressFromString(&info.address.ip,"127.0.0.1"));
    for(unsigned n=0;n<32;++n)info.sessionKey[n]=(uint8_t)n;
    IHS_Session *session=IHS_SessionCreate(&client,&info);assert(session);
    if(load)udpLoadSession=session;
    if(audio)audInstall(session);
    if(video) {
        udpVideo=sl_video_create();assert(udpVideo);
        assert(IHS_SessionSetVideoTrackingIdentity(session,1));
        static const IHS_StreamVideoCallbacks callbacks={.startTracked=udpVideoStart,.submitTracked=udpVideoSubmit,
            .stopTracked=udpVideoStop,.interruptTracked=udpVideoInterrupt,.thinkTracked=udpVideoThink,
            .flushTracked=udpVideoFlush,.reportsDecoderInfo=true};
        /* Session borrows this static table through worker teardown. */
        IHS_SessionSetVideoCallbacks(session,&callbacks,NULL);
    }
    if(microphone) {
        static const IHS_StreamMicrophoneCallbacks callbacks={.start=micStart,.stop=micStop};
        IHS_SessionSetMicrophoneCallbacks(session,&callbacks,&micStarts);
    }
    sl_stream_settings settings;
    if(negotiate) {
        const sl_auth_store legacy={0};assert(sl_stream_settings_init(&settings,&legacy));
        assert(sl_stream_settings_load(&settings,argv[3])==0);
        const sl_stream_request_limits limits={.width=1280,.height=720,.fps=60,.hevc=false};
        assert(limited ? sl_stream_settings_apply_limited(&settings,session,&limits)
                       : sl_stream_settings_apply(&settings,session));
        /* Default desktop capability input matches the original SDK lookup.
         * Limited mode exercises current Switch request limits/H264 support
         * through common production functions, without physical-device claims. */
        const IHS_StreamClientCapabilities caps={.hasVideoDecoderCapabilities=true,.supportsVideoHevc=!limited};
        assert(IHS_SessionSetClientCapabilities(session,&caps));
    }
    assert(IHS_SessionConnect(session));
    bool connected=false,handshake=false,reply=false,haveRequest=false;
    uint8_t request[256];size_t requestSize=0;unsigned connects=0,goodbyes=0;
    bool configReceived=false,completeReceived=false,videoInfo=false,videoStop=false;
    bool repaired=false;uint8_t feedbackWire[64];size_t feedbackSize=0;
    unsigned gapStage=0;
    unsigned audioStage=0,audioBlockedPolls=0;
    struct sockaddr_in videoAddress={0};uint8_t videoLocal=0;
    uint8_t outputPlain[7][512],outputCipher[7][512];size_t plainSizes[7]={0},cipherSizes[7]={0};
    unsigned micStage=0,micWireCount=0;uint8_t micWires[7][2048];size_t micWireSizes[7]={0};
    bool micControlSeen[5]={0};
    char micEvents[12][32];unsigned micEventCount=0;
    uint64_t deadline=millis()+(load?20000:5000);
    for(;;) {
        if(pressureReady && completeReceived && !loadStart && atomic_load(&udpLoadChannelReady)) {
            /* Fixture boundary: start large bursts after the actual channel
             * is published and its real decoder worker exists. Early-media
             * cache behavior remains a separate input scenario. */
            loadStart=udpLoadNow();
        }
        if(load && loadStart) {
            while(loadSent<loadFrames && udpLoadNow()-loadStart>=(uint64_t)loadSent*1000000000/loadRate) {
                udpLoadSend(peer,&videoAddress,videoLocal,loadSent?NULL:argv[6],crc,loadSent+1==loadFrames,loadFrames-loadSent<=2);++loadSent;
            }
        }
        if(audio && !audioStage && atomic_load(&audFrames)>=1) {
            udpReplayMedia(peer,&videoAddress,videoLocal,NULL,crc);audioStage=1;
        }
        if(audio && audioBlocked && repaired)++audioBlockedPolls;
        if(audio && !strcmp(argv[9],"drop") && audioStage==1 && repaired && atomic_load(&audFrames)>=2) {
            udpReplayMedia(peer,&videoAddress,videoLocal,NULL,crc);audioStage=2;
        }
        if(audio && !videoStop && atomic_load(&audFrames)>=(audioBurst?1:audioFrames) && atomic_load(&audCalls)>=audioCalls &&
            (!audioBurst || audInputs[atomic_load(&audFrames)-1].id==27) &&
            (audioBlocked?audioBlockedPolls>=30:atomic_load(&audPlayed)>0)) {
            sendEncryptedPeer(session,peer,&videoAddress,videoLocal,5,51,NULL,0,3,crc,false);videoStop=true;
        }
        if(microphone && micStage==0 && atomic_load(&micPeerMessages)==2) {
            assert(!micStarts && !micStops && !session->microphone.channel);
            assert(micStartStream(session));assert(session->microphone.channel==3);
            assert(IHS_SessionSendMicrophoneData(session,micSmall[0],4));assert(IHS_SessionSendMicrophoneData(session,micSmall[1],4));
            uint8_t large[4000];for(unsigned n=0;n<sizeof(large);++n)large[n]=(uint8_t)n;
            assert(IHS_SessionSendMicrophoneData(session,large,sizeof(large)));micStage=1;
        }
        if(microphone && micStage==1 && micWireCount==5) {
            sendEncryptedPeer(session,peer,&videoAddress,videoLocal,6,108,NULL,0,4,crc,false);micStage=2;
        }
        if(microphone && micStage==2 && atomic_load(&micPeerMessages)==3) {
            assert(session->microphone.channel==3 && micStarts==1 && !micStops);
            assert(IHS_SessionStopMicrophoneStream(session));assert(!IHS_SessionSendMicrophoneData(session,micSmall[0],4));
            assert(micStartStream(session));assert(session->microphone.channel==4);
            assert(IHS_SessionSendMicrophoneData(session,micSmall[2],4));
            assert(micStartStream(session));assert(session->microphone.channel==5);
            assert(IHS_SessionSendMicrophoneData(session,micSmall[2],4));
            micStage=3;
        }
        if(microphone && micStage==3 && micWireCount==7) {
            assert(IHS_SessionStopMicrophoneStream(session));assert(!IHS_SessionStopMicrophoneStream(session));micStage=4;
        }
        if(video) {
            udpTakePicture();
            if(gap && udpPictureCount==1 && !gapStage) {udpReplayMedia(peer,&videoAddress,videoLocal,NULL,crc);gapStage=1;}
            if(gap && !burst && !gapReliable && udpPictureCount==2 && gapStage==1) {assert(repaired);udpReplayMedia(peer,&videoAddress,videoLocal,NULL,crc);gapStage=2;}
            bool videoDone=load?udpHavePicture && udpPictureId==100+loadFrames-1:gap?(gapReliable?repaired:burst?udpPictureId==30:udpPictureCount==3):udpHavePicture;
            if(videoInfo && videoDone && !videoStop) {
                sendEncryptedPeer(session,peer,&videoAddress,videoLocal,5,53,NULL,0,3,crc,false);videoStop=true;
            }
        }
        bool micDone=microphone && micStage==4 && micWireCount==7 && micStarts==3 && micStops==3;
        for(unsigned n=0;n<5;++n)if(!micControlSeen[n])micDone=false;
        bool finished=audio?videoStop && atomic_load(&audStops):microphone?micDone:video?videoStop && atomic_load(&udpStopped):negotiate?completeReceived && atomic_load(&session->state.connectionState)==6:missingServer?atomic_load(&serverDrained):hasResponse?atomic_load(&responded):atomic_load(&requested)&&haveRequest;
        if(finished && (!atomic_load(&session->transport.closeRequested) || goodbyes))break;
        if(audio && millis()>=deadline)fprintf(stderr,"audio timeout: frames=%u calls=%u played=%u stage=%u feedback=%u stops=%u\n",
            atomic_load(&audFrames),atomic_load(&audCalls),atomic_load(&audPlayed),audioStage,repaired,atomic_load(&audStops));
        if(pressureReady && millis()>=deadline) {
            fprintf(stderr,"pressure timeout: complete_rx=%u socket_drops=%ld admitted/unique:",
                    atomic_load(&udpLoadReceived),udpLoadSocketDrops(ntohs(videoAddress.sin_port)));
            for(unsigned group=1;group<=26;++group)
                fprintf(stderr," %u:%u/%u",group,atomic_load(&udpLoadFECAdmitted[group]),atomic_load(&udpLoadFECUnique[group]));
            fputc('\n',stderr);
        }
        assert(millis()<deadline);
        struct pollfd p={.fd=peer,.events=POLLIN};int ready=poll(&p,1,2);assert(ready>=0);if(!ready)continue;
        uint8_t raw[2048];struct sockaddr_in from;socklen_t length=sizeof(from);
        ssize_t size=recvfrom(peer,raw,sizeof(raw),0,(struct sockaddr *)&from,&length);assert(size>=13);
        uint8_t type=raw[0]&127;
        /* Explicit large-fixture input: acknowledge each received reliable
         * control packet. Without this, peer-side retry traffic can overflow
         * the peer's own socket while its producer paces a large group. */
        if(pressureReady && type==5 && raw[4]==1)
            sendPeer(peer,&from,7,raw[2],1,(uint16_t)(raw[7]|(unsigned)raw[8]<<8),raw+9,4,crc);
        udpLoadPeerWire(raw,(size_t)size);
        if(load)udpLoadOnFeedback(peer,&from,raw,(size_t)size,crc);
        if(load && type==3 && raw[4]==3 && size==(crc?18:14) && raw[13]==2)++udpLoadDataLost;
        if((recover || gap || audioGap) && (type==8 || type==10 || (gap && type==3 && raw[13]==2)) && raw[4]==3 && !repaired) {
            assert(((raw[0]&128)!=0)==crc && raw[2] && raw[3]==7);
            size_t plainSize=(size_t)size;
            if(crc) {uint32_t value=0;for(unsigned n=0;n<4;++n)value|=(uint32_t)raw[size-4+n]<<(8*n);assert(IHS_CRC32C(raw,(size_t)size-4)==value);plainSize-=4;}
            assert(plainSize<=sizeof(feedbackWire));uint8_t normalized[64];memcpy(normalized,raw,plainSize);normalized[2]=normalized[3]=0;memset(normalized+9,0,4);
            if(udpExpectedFeedbackSize!=plainSize || memcmp(normalized,udpExpectedFeedback,plainSize))continue;
            if(audio) {assert(audioStage==1 && atomic_load(&audFrames)==1);}
            else if(gap) {assert(gapStage==1 && udpPictureCount==1 && atomic_load(&udpSdkPackets)==1);}
            else {assert(!atomic_load(&udpSubmitted) && !atomic_load(&udpSdkPackets));}
            assert((size_t)size<=sizeof(feedbackWire));memcpy(feedbackWire,raw,(size_t)size);feedbackSize=(size_t)size;
            if(audio ? !audioBlocked : (!gap || !gapReliable))udpReplayMedia(peer,&from,raw[2],NULL,crc);
            repaired=true;
        } else if(microphone && raw[4]>=3 && raw[4]<=5 && (type==3 || type==4 || type==5 || type==6)) {
            assert(((raw[0]&128)!=0)==crc && raw[2] && raw[3]==7 && (size_t)size<=sizeof(micWires[0]));
            if(crc) {uint32_t value=0;for(unsigned n=0;n<4;++n)value|=(uint32_t)raw[size-4+n]<<(8*n);assert(IHS_CRC32C(raw,(size_t)size-4)==value);}
            unsigned id=raw[7]|(unsigned)raw[8]<<8,index=raw[4]==3?id:5u+(unsigned)raw[4]-4u;assert(index<7);
            if(micWireSizes[index]) {assert(micWireSizes[index]==(size_t)size && !memcmp(micWires[index]+13,raw+13,(size_t)size-13-(crc?4:0)));}
            else {assert(micEventCount<12);snprintf(micEvents[micEventCount++],32,"data:%u:%u",raw[4],id);memcpy(micWires[index],raw,(size_t)size);micWireSizes[index]=(size_t)size;++micWireCount;}
        } else if(type==1) {
            ++connects;assert(size==17 && raw[0]==1 && raw[2] && !memcmp(raw+13,"\xc7\x3d\x8f\x3c",4));
            if(!connected) {sendPeer(peer,&from,2,raw[2],0,0,raw+9,4,crc);connected=true;}
        } else if(type==9) {
            ++goodbyes;assert((size_t)size==(crc?17u:13u));
            assert(raw[2] && raw[3]==7 && raw[4]==0);
            assert(((raw[0]&128)!=0)==crc);
            if(crc) {uint32_t value=0;for(unsigned n=0;n<4;++n)value|=(uint32_t)raw[size-4+n]<<(8*n);assert(IHS_CRC32C(raw,(size_t)size-4)==value);}
        } else if(type==5) {
            if(video && raw[4]!=1)continue;
            assert(raw[2] && raw[3]==7 && raw[4]==1);
            bool actualCrc=(raw[0]&128)!=0;assert(actualCrc==crc);
            if(actualCrc) {uint32_t value=0;for(unsigned n=0;n<4;++n)value|=(uint32_t)raw[size-4+n]<<(8*n);assert(IHS_CRC32C(raw,(size_t)size-4)==value);size-=4;}
            if(raw[13]==6 && !handshake) {assert(size==16 && !memcmp(raw+13,"\x06\x0a\x00",3));sendPeer(peer,&from,5,raw[2],1,0,server,serverSize,crc);handshake=true;}
            else if(raw[13]==1) {
                assert((size_t)size-13<sizeof(request));
                if(haveRequest)assert(requestSize==(size_t)size-13 && !memcmp(request,raw+13,requestSize));
                requestSize=(size_t)size-13;memcpy(request,raw+13,requestSize);haveRequest=true;
                if(hasResponse && !reply) {
                    sendPeer(peer,&from,5,raw[2],1,1,response,responseSize,crc);reply=true;
                    if(negotiate) {
                        if(badMac)sendEncryptedPeer(session,peer,&from,raw[2],2,3,init,initSize,0,crc,true);
                        sendEncryptedPeer(session,peer,&from,raw[2],2+(unsigned)badMac,3,init,initSize,(unsigned)badMac,crc,false);
                    }
                }
            } else if(negotiate && (raw[13]==4 || raw[13]==5 || (video && raw[13]==80) || (microphone && (raw[13]==107 || raw[13]==108)))) {
                unsigned index=raw[13]==4?0:raw[13]==5?1:2;
                if(microphone) {unsigned id=raw[7]|(unsigned)raw[8]<<8;assert(id>=2 && id<9);index=id-2;static const uint8_t tags[]={4,5,107,108,107,107,108};assert(raw[13]==tags[index]);if(index>=2) {if(!micControlSeen[index-2]) {assert(micEventCount<12);snprintf(micEvents[micEventCount++],32,"control:%u:%u",raw[13],index);}micControlSeen[index-2]=true;}}
                uint64_t sequence;
                IHS_Buffer in=IHS_BUFFER_WRAP(raw+14,(size_t)size-14),plain=IHS_BUFFER_INIT(512,512);
                assert(IHS_SessionFrameDecrypt(session,&in,&plain,index,&sequence)==IHS_SessionFrameDecryptOK && sequence==index);
                assert(plain.size+1<sizeof(outputPlain[index]) && (size_t)size-13<sizeof(outputCipher[index]));
                outputPlain[index][0]=raw[13];memcpy(outputPlain[index]+1,IHS_BufferPointer(&plain),plain.size);plainSizes[index]=plain.size+1;
                memcpy(outputCipher[index],raw+13,(size_t)size-13);cipherSizes[index]=(size_t)size-13;
                if(index==0 && !configReceived) {
                    CNegotiationSetConfigMsg *message=cnegotiation_set_config_msg__unpack(NULL,plain.size,IHS_BufferPointer(&plain));assert(message && message->config);
                    CNegotiationSetConfigMsg selected=CNEGOTIATION_SET_CONFIG_MSG__INIT;selected.config=message->config;
                    uint8_t body[256];size_t count=cnegotiation_set_config_msg__get_packed_size(&selected);assert(count<sizeof(body));cnegotiation_set_config_msg__pack(&selected,body);
                    sendEncryptedPeer(session,peer,&from,raw[2],3+(unsigned)badMac,4,body,count,1+(unsigned)badMac,crc,false);
                    cnegotiation_set_config_msg__free_unpacked(message,NULL);configReceived=true;
                } else if(index==1 && !completeReceived) {
                    assert(configReceived && plain.size==0);completeReceived=true;
                    if(microphone) {
                        const uint8_t start[]={0x10,3,0x18,3,0x28,0x80,0xf7,2,0x30,2};
                        videoAddress=from;videoLocal=raw[2];
                        sendEncryptedPeer(session,peer,&from,raw[2],4,107,start,sizeof(start),2,crc,false);
                        sendEncryptedPeer(session,peer,&from,raw[2],5,108,NULL,0,3,crc,false);
                    }
                    if(video) {
                        const uint8_t start[]={0x08,3,0x10,4,0x20,0x80,1,0x28,0x48};
                        videoAddress=from;videoLocal=raw[2];
                        sendEncryptedPeer(session,peer,&from,raw[2],4,52,start,sizeof(start),2,crc,false);
                        if(load) {if(!pressureReady)loadStart=udpLoadNow();}else udpReplayMedia(peer,&from,raw[2],argv[6],crc);
                    }
                    if(audio) {
                        const uint8_t start[]={0x10,3,0x18,3,0x28,0x80,0xf7,2,0x30,2};
                        videoAddress=from;videoLocal=raw[2];
                        sendEncryptedPeer(session,peer,&from,raw[2],4,50,start,sizeof(start),2,crc,false);
                        udpReplayMedia(peer,&from,raw[2],argv[6],crc);
                    }
                } else if(index==2)videoInfo=true;
                IHS_BufferClear(&plain,true);
            }
        }
    }
    int phase=atomic_load(&session->state.connectionState);
    bool closed=atomic_load(&session->transport.closeRequested);
    int mtu=session->state.mtu; /* Handler terminal synchronizes this RX-owned value. */
    uint64_t receivedSequence=0,sendSequence=0;
    if(negotiate) {IHS_SessionChannelControl *control=(void *)session->channels[1];IHS_BaseLock(&session->base);receivedSequence=control->recvEncryptSequence;IHS_BaseUnlock(&session->base);IHS_MutexLock(control->sendLock);sendSequence=control->sendEncryptSequence;IHS_MutexUnlock(control->sendLock);}
    /* Socket counters disappear when the real receive worker closes its fd.
     * Snapshot after the peer/decoder Stop, before interrupt/join; report the
     * atomic admission rows only after those workers have joined. */
    long finalSocketDrops=pressureReady?udpLoadSocketDrops(ntohs(videoAddress.sin_port)):-1;
    long finalPeerDrops=pressureReady?udpLoadSocketDrops(ntohs(address.sin_port)):-1;
    if(!closed)IHS_SessionInterrupt(session);
    IHS_SessionThreadedJoin(session);
    assert(!session->sendThread && !session->base.worker);
    if(audio)stream_media_audio_close(NULL);
    assert(goodbyes==(closed?1u:0u));
    printf("{\"phase\":%d,\"closed\":%s,\"mtu\":%d,\"connects\":%u,\"goodbyes\":%u,\"requested\":%s,\"response_handled\":%s,\"request\":\"",phase,closed?"true":"false",mtu,connects,goodbyes,atomic_load(&requested)?"true":"false",atomic_load(&responded)?"true":"false");
    for(size_t n=0;n<requestSize;++n)printf("%02x",request[n]);
    printf("\"");
    if(negotiate) {
        printf(",\"receive_sequence\":%llu,\"send_sequence\":%llu,\"frames\":[",(unsigned long long)receivedSequence,(unsigned long long)sendSequence);
        for(unsigned i=0;i<(microphone?7u:video?3u:2u);++i) {printf("%s{\"sequence\":%u,\"plain\":\"",i?",":"",i);for(size_t n=0;n<plainSizes[i];++n)printf("%02x",outputPlain[i][n]);printf("\",\"cipher\":\"");for(size_t n=0;n<cipherSizes[i];++n)printf("%02x",outputCipher[i][n]);printf("\"}");}
        printf("]");
    }
    if(video) {
        unsigned count=gap && !gapReliable?3:1;
        assert(udpHavePicture && udpStarts==1 && (load || (udpSubmits==count && udpSdkPackets==count)) && atomic_load(&udpStopped));
        printf(",\"video\":{\"id\":%u,\"shape\":[%u,%u,0],\"md5\":\"",udpPictureId,udpWidth,udpHeight);
        for(unsigned i=0;i<16;++i)printf("%02x",udpPixelMd5[i]);
        printf("\",\"sdk_size\":%zu,\"sdk_sha256\":\"",udpSdkSize);for(unsigned i=0;i<32;++i)printf("%02x",udpSdkSha[i]);
        printf("\",\"starts\":%u,\"submits\":%u,\"stopped\":true}",udpStarts,udpSubmits);
    }
    if(load)udpLoadReport();
    if(pressureReady)udpLoadSocketReport(ntohs(videoAddress.sin_port),finalSocketDrops,ntohs(address.sin_port),finalPeerDrops);
    if(audio)audReport(audioBurst?atomic_load(&audFrames):audioFrames,audioCalls,audioBlocked);
    if(audioBurst)rxReport();
    if(audioGap) {
        assert(repaired && feedbackSize && !udpReplayFile);
        printf(",\"audio_feedback\":\"");for(size_t n=0;n<feedbackSize;++n)printf("%02x",feedbackWire[n]);printf("\"");
    }
    if(recover) {
        assert(repaired && !udpReplayFile && feedbackSize);
        printf(",\"repair_feedback\":\"");for(size_t n=0;n<feedbackSize;++n)printf("%02x",feedbackWire[n]);
        printf("\",\"sdk_packets_before_repair\":0");
    }
    if(gap) {
        assert(repaired && !udpReplayFile && feedbackSize &&
            (burst ? udpPictureCount>=2 && udpPictureCount<=3 : udpPictureCount==(gapReliable?1u:3u)));
        printf(",\"gap_feedback\":\"");for(size_t n=0;n<feedbackSize;++n)printf("%02x",feedbackWire[n]);
        printf("\",\"sdk_packets_before_feedback\":1,\"pictures\":[");
        for(unsigned n=0;n<udpPictureCount;++n) {printf("%s{\"id\":%u,\"md5\":\"",n?",":"",udpPictures[n].id);for(unsigned j=0;j<16;++j)printf("%02x",udpPictures[n].md5[j]);printf("\"}");}
        printf("],\"sdk_inputs\":[");
        for(unsigned n=0;n<atomic_load(&udpSdkPackets);++n) {printf("%s{\"size\":%zu,\"sha256\":\"",n?",":"",udpSdkInputs[n].size);for(unsigned j=0;j<32;++j)printf("%02x",udpSdkInputs[n].sha[j]);printf("\"}");}
        printf("]");
    }
    if(microphone) {
        assert(!session->microphone.channel && session->microphone.nextFrame==1 && micStarts==3 && micStops==3);
        printf(",\"microphone\":{\"starts\":%u,\"stops\":%u,\"peer_messages\":%u,\"wires\":[",micStarts,micStops,atomic_load(&micPeerMessages));
        for(unsigned n=0;n<7;++n) {printf("%s\"",n?",":"");for(size_t j=0;j<micWireSizes[n];++j)printf("%02x",micWires[n][j]);printf("\"");}
        assert(micEventCount==12);printf("],\"events\":[");for(unsigned n=0;n<micEventCount;++n)printf("%s\"%s\"",n?",":"",micEvents[n]);printf("]}");
    }
    puts("}");
    IHS_SessionDestroy(session);if(negotiate)sl_stream_settings_destroy(&settings);
    if(video) {sl_video_reap(udpVideo);assert(sl_video_destroy(udpVideo));udpVideo=NULL;}
    if(audio)stream_media_shutdown();
    IHS_Quit();assert(!close(peer));return 0;
}
