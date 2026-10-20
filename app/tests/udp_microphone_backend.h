/* Explicit encoded input/capture lifecycle adapter; no capture/Opus claims. */
static atomic_uint micPeerMessages;
static unsigned micStarts, micStops;
static const uint8_t micSmall[][4]={{0x11,0x22,0x33,0x44},{0x55,0x66,0x77,0x88},{0,1,2,3}};
static int micStart(IHS_Session *s,const IHS_StreamAudioConfig *c,void *context) {
    (void)s;assert(context==&micStarts && c->codec==IHS_StreamAudioCodecOpus && c->frequency==48000 && c->channels==2);
    assert(!c->codecData && !c->codecDataLen);++micStarts;return 0;
}
static void micStop(IHS_Session *s,void *context) {
    assert(context==&micStarts);assert(!IHS_SessionSendMicrophoneData(s,micSmall[0],4));++micStops;
}
void __real_IHS_SessionChannelControlOnMessageReceived(IHS_SessionChannel *,EStreamControlMessage,IHS_Buffer *,const IHS_SessionPacketHeader *);
void __wrap_IHS_SessionChannelControlOnMessageReceived(IHS_SessionChannel *c,EStreamControlMessage type,IHS_Buffer *p,const IHS_SessionPacketHeader *h) {
    __real_IHS_SessionChannelControlOnMessageReceived(c,type,p,h);
    if(type==107 || type==108)atomic_fetch_add(&micPeerMessages,1);
}
static bool micStartStream(IHS_Session *s) {
    IHS_StreamAudioConfig c={.codec=IHS_StreamAudioCodecOpus,.frequency=48000,.channels=2};
    return IHS_SessionStartMicrophoneStream(s,&c);
}
