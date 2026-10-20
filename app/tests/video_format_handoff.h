/* Included by the real runtime/worker/SDK oracle. No alternate format model. */
static void format_wait_pending(void) {
    for(unsigned n=0;n<5000;++n) {
        if(sl_video_formats_pending(pipeline)) return;
        assert(atomic_load(&processed)<target); /* Worker must wait for actor. */
        usleep(1000);
    }
    assert(!"SDK did not publish a deferred format request");
}
static void format_wait_processed(void) {
    for(unsigned n=0;n<5000 && atomic_load(&processed)<target;++n) usleep(1000);
    assert(atomic_load(&processed)==target);
}
static void format_actor_update(sl_runtime *r) {
    r->session->base.callbacks.run->update(&r->session->base,
                                           r->session->base.callbackContexts.run);
}
static void format_queue_control(IHS_Session *s,EStreamControlMessage type,const ProtobufCMessage *message) {
    IHS_Buffer body=IHS_BUFFER_INIT(64,4096);IHS_BufferAppendMessage(&body,message);
    IHS_SessionPacketHeader header={.type=IHS_SessionPacketTypeReliable,.channelId=1};
    IHS_SessionChannelControlHandoff(s->channels[1],type,&body,&header);
    IHS_BufferClear(&body,true);
}
static sl_video_frame *format_picture(unsigned id) {
    sl_video_selection selection={0};
    assert(sl_video_select(pipeline,&selection) && selection.frame && selection.ticket);
    assert(IHS_FrameTicketIdentity(selection.ticket).frameId==id);
    uint8_t md5[16];hash(selection.frame,md5);assert(!memcmp(md5,golden,16));
    sl_video_frame *frame=selection.frame;selection.frame=NULL;
    sl_video_selection_release(&selection);
    return frame;
}
static atomic_bool formatBaseHeld;
static void *format_interrupt_while_base_held(void *context) {
    IHS_Session *session=context;
    IHS_BaseLock(&session->base);
    atomic_store(&formatBaseHeld,true);
    for(unsigned n=0;n<5000 && !atomic_load(&formatInfoEntered);++n) usleep(1000);
    assert(atomic_load(&formatInfoEntered));
    /* Actor is about to take Base. Its format lock must already be released. */
    IHS_SessionInterrupt(session);
    IHS_BaseUnlock(&session->base);
    return NULL;
}
static void format_handoff_case(sl_runtime *r,CStartVideoDataMsg *start,const char *mode) {
    const char *codecHex=NULL;
    if(!strcmp(mode,"codec_empty")) codecHex="";
    if(!strcmp(mode,"codec_opaque")) codecHex="61626364";
    if(!strcmp(mode,"codec_truncated")) codecHex="01";
    if(!strcmp(mode,"codec_annexb")) codecHex="000000016764000aacb4105fcb8088000003000800000301e07891350000000168ef0fcb";
    if(!strcmp(mode,"codec_avcc") || !strcmp(mode,"codec_avcc_reset")) codecHex="0164000affe100186764000aacb4105fcb8088000003000800000301e078913501000468ef0fcb";
    uint8_t codecBytes[64];
    if(codecHex) {
        size_t n=strlen(codecHex)/2;assert(n<=sizeof(codecBytes));
        for(size_t i=0;i<n;++i) {unsigned byte;assert(sscanf(codecHex+2*i,"%2x",&byte)==1);codecBytes[i]=(uint8_t)byte;}
        start->has_codec_data=true;start->codec_data=(ProtobufCBinaryData){.len=n,.data=codecBytes};
        memcpy(codecDataExpected,codecBytes,n);codecDataExpectedSize=n;
        codecDataChecking=true;
    }
    bool normal=!strcmp(mode,"normal") || codecHex, restart=!strcmp(mode,"restart") || !strcmp(mode,"codec_avcc_reset");
    bool config=!strcmp(mode,"config_pending");
    bool reset=!strcmp(mode,"reset_pending"), replace=!strcmp(mode,"replace_pending");
    bool stop=!strcmp(mode,"stop_pending"), disconnect=!strcmp(mode,"disconnect_pending");
    bool freeze=!strcmp(mode,"freeze_pending"), race=!strcmp(mode,"base_cancel");
    bool opening=!strcmp(mode,"opening_guard");
    bool unavailable=!strcmp(mode,"reset_unavailable");
    assert(normal||restart||config||reset||replace||stop||disconnect||freeze||race||opening||unavailable);
    formatChecking=true;formatActor=pthread_self();testCpuCount=4;
    infoSendOk=false; /* Source's unconnected Frame::Send fails, without reset. */
    uint8_t software[]={0x38,0};
    assert(IHS_SessionSetStreamingClientConfig(r->session,software,sizeof(software),true));
    if(opening) infoOpenCallback=formatOpeningCheck=true;
    format_queue_control(r->session,k_EStreamControlStartVideoData,&start->base);
    format_actor_update(r);
    assert(r->facts.epoch==1 && !atomic_load(&formatWrongThread));
    assert(!r->session->videoStarting && !r->session->videoStartingEpoch.video_epoch);
    assert(!sl_video_formats_pending(pipeline));
    if(opening) {
        assert(infoCount==1 && infoPhases[0]==4);
        puts("{\"mode\":\"opening_guard\",\"infos\":1,\"actor\":true}");
        return;
    }
    assert(infoCount==0);
    if(codecHex) assert(codecDataOpenStatus==0);
    infoPhase=3;clockTick=1000000;
    packet_enqueue(r->session,23,1,24,1000000,0,sizeof(payload));
    format_wait_pending();
    assert(infoCount==0 && atomic_load(&processed)<target);
    sl_video_frame *held[2]={0};unsigned heldCount=0;
    if(normal||restart||config) {
        if(config) {
            CStreamingClientConfig values=CSTREAMING_CLIENT_CONFIG__INIT;
            values.has_enable_hardware_decoding=true;values.enable_hardware_decoding=true;
            CSetStreamingClientConfig message=CSET_STREAMING_CLIENT_CONFIG__INIT;
            message.config=&values;
            format_queue_control(r->session,k_EStreamControlSetStreamingClientConfig,&message.base);
        }
        format_actor_update(r);
        assert(!sl_video_formats_pending(pipeline) && infoCount==1);
        assert(r->facts.epoch==1); /* Config reset is for the next actor turn. */
        format_wait_processed();held[heldCount++]=format_picture(23);
        assert(!resetRequested); /* Failed informational send must not reset. */
        if(restart||config) {
            if(restart) assert(IHS_SessionVideoRequestReset(r->session));
            format_actor_update(r);
            assert(r->facts.epoch==2 && infoCount==1);
            packet_enqueue(r->session,24,2,24,1000000,0,sizeof(payload));
            format_wait_pending();format_actor_update(r);format_wait_processed();
            held[heldCount++]=format_picture(24);
        }
    } else if(reset||replace||unavailable) {
        if(reset||unavailable) {
            if(unavailable) formatFailOpen=true;
            assert(IHS_SessionVideoRequestReset(r->session));
            format_actor_update(r); /* Cancel/join/reopen before format phase. */
            assert(infoCount==1);
            assert(!sl_video_formats_pending(pipeline));
        } else {
            format_queue_control(r->session,k_EStreamControlStartVideoData,&start->base);
            format_actor_update(r);
            assert(infoCount==0 && !sl_video_formats_pending(pipeline));
        }
        assert(r->facts.epoch==2);
        if(!unavailable) {
            packet_enqueue(r->session,24,2,24,1000000,0,sizeof(payload));
            format_wait_pending();format_actor_update(r);format_wait_processed();
            held[heldCount++]=format_picture(24);
            assert(infoCount==(reset?2:1));
        }
    } else if(race) {
        pthread_t interrupter;
        assert(!pthread_create(&interrupter,NULL,format_interrupt_while_base_held,r->session));
        for(unsigned n=0;n<5000 && !atomic_load(&formatBaseHeld);++n) usleep(1000);
        assert(atomic_load(&formatBaseHeld));
        IHS_SessionVideoHandleFormatRequests(r->session);
        assert(!pthread_join(interrupter,NULL));
        format_wait_processed();
        assert(r->session->base.interrupted && !sl_video_formats_pending(pipeline));
    } else {
        if(freeze) sl_media_close_video();
        if(disconnect||freeze) IHS_SessionInterrupt(r->session);
        else {
            CStopVideoDataMsg message=CSTOP_VIDEO_DATA_MSG__INIT;
            format_queue_control(r->session,k_EStreamControlStopVideoData,&message.base);
            format_actor_update(r);
        }
        format_wait_processed();
        assert(!sl_video_formats_pending(pipeline) && infoCount==0);
    }
    assert(!atomic_load(&formatWrongThread));
    if(codecHex) {
        assert(codecDataSdkSize==0);assert(codecDataStartCalls==(restart?2:1));
        assert(codecDataSdkOpens==codecDataStartCalls);
        for(unsigned n=0;n<codecDataSdkOpens;++n) {
            assert(codecDataSdkSizes[n]==0);assert(!codecDataSdkPointers[n]);
        }
        assert(codecDataPackets==codecDataStartCalls);
    }
    assert(infoCount==0 || (r->session->videoDecoderInfo &&
        !strcmp(r->session->videoDecoderInfo,"libavcodec software decoding with 4 threads")));
    unsigned infos=infoCount;
    unsigned epoch=(unsigned)r->facts.epoch;
    if(!r->session->base.interrupted) {
        CStopVideoDataMsg message=CSTOP_VIDEO_DATA_MSG__INIT;
        controlMessage(r->session,k_EStreamControlStopVideoData,&message.base);
    }
    assert(!sl_video_formats_pending(pipeline));
    for(unsigned n=0;n<heldCount;++n) {
        uint8_t md5[16];hash(held[n],md5);assert(!memcmp(md5,golden,16));
        sl_resource_release(&held[n]->ref);
    }
    sl_video_reap(pipeline);
    unsigned losses=0;
    for(unsigned n=0;n<eventCount;++n) losses+=events[n][1]==2;
    printf("{\"mode\":\"%s\",\"infos\":%u,\"epoch\":%u,\"pictures\":%u,\"losses\":%u,\"actor\":true,\"sdk\":[",
        mode,infos,epoch,heldCount,losses);
    bool comma=false;
    for(unsigned n=0;n<eventCount;++n) if(events[n][1]==4 || events[n][1]==5) {
        printf("%s[%lld,%lld]",comma?",":"",(long long)events[n][1],(long long)events[n][2]);comma=true;
    }
    printf("]");
    if(codecHex) {
        printf(",\"codec_data\":\"");
        for(size_t n=0;n<codecDataExpectedSize;++n) printf("%02x",codecDataExpected[n]);
        printf("\",\"codec_packets\":%u,\"codec_sdk_sizes\":[",codecDataPackets);
        for(unsigned n=0;n<codecDataSdkOpens;++n) printf("%s%d",n?",":"",codecDataSdkSizes[n]);
        printf("]");
    }
    puts("}");
}
