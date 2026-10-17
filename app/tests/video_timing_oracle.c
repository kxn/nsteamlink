/* Actual runtime/control/parser/worker/FFmpeg and production timing/queue TU.
 * Private reads are observations. Clock, network and rendering opportunities
 * are declared terminals. SDK-equivalent byte input remains real FFmpeg data. */
#define sl_video_create timing_create
#define sl_video_submit timing_submit
#include "../platforms/common/video_pipeline.c"
#undef sl_video_create
#undef sl_video_submit
static sl_video_pipeline *pipeline;
static uint32_t clockTick;
static unsigned inputTicks, outputTicks;
static unsigned action, pictureCount, submitCount, completionCount, selectCount, waitCount;
static uint32_t pictures[512][3], submits[512][3], completed[2048][2];
static unsigned decodeCount;
static uint32_t decodeEvents[1024][4];
static int64_t selected[512][3], waits[512][2];
static uint8_t payload[2204];
static bool recording, presenting;
static int suppressOutput = -1;
static unsigned physicalCount, prepCount, codecCount;
static uint64_t codecPts[512][4];
static uint32_t physical[1024][3], prep[1024][3];
sl_video_pipeline *sl_video_create(void) { return pipeline = timing_create(); }
sl_video_submit_result sl_video_submit(sl_video_pipeline *p, sl_video_key key, const unsigned char *data,
                                       size_t size, IHS_FrameTicket *ticket, bool *taken, bool keyframe) {
    uint32_t stamp;
    assert(IHS_FrameTicketVideoTimestamp(ticket, &stamp));
    assert(!size || (size == sizeof(payload) && !memcmp(data, payload, size)));
    IHS_FrameIdentity identity = IHS_FrameTicketIdentity(ticket);
    assert(submitCount < 512);
    submits[submitCount][0] = action; submits[submitCount][1] = identity.frameId;
    submits[submitCount++][2] = stamp;
    uint64_t before = p->publish_seq;
    sl_video_submit_result result = timing_submit(p, key, data, size, ticket, taken, keyframe);
    assert(result == SL_VIDEO_SUBMIT_OK && p->publish_seq <= before + (size != 0));
    pthread_mutex_lock(&p->mailbox);
    assert(p->job_count && codecCount < 512);
    input_job *job=&p->jobs[p->job_count-1];
    assert(IHS_FrameTicketIdentity(job->ticket).frameId==identity.frameId);
    codecPts[codecCount][0]=action;codecPts[codecCount][1]=identity.frameId;
    codecPts[codecCount][2]=stamp;codecPts[codecCount++][3]=job->codec_timestamp;
    pthread_mutex_unlock(&p->mailbox);
    if (!size || p->publish_seq==before) return result;
    pthread_mutex_lock(&p->mailbox);
    sl_video_frame *frame = p->pending[p->pending_count - 1];
    assert(frame->has_media_timestamp && frame->media_timestamp == stamp);
    assert(pictureCount < 512);
    pictures[pictureCount][0] = action;
    pictures[pictureCount][1] = IHS_FrameTicketIdentity(frame->ticket).frameId;
    pictures[pictureCount++][2] = frame->media_timestamp;
    pthread_mutex_unlock(&p->mailbox);
    return result;
}
#include "../platforms/common/runtime.c"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "session/channels/ch_control.h"
#include "session/channels/video/ch_data_video.h"
#include "session/frame_tracker.h"
#include "session/session_pri.h"
#include "test_session.h"
#include "video_scheduler.h"
#include <libavutil/imgutils.h>
#include <libavutil/md5.h>
#include <stdio.h>
#include <unistd.h>
static atomic_uint processed;
static unsigned target;
int __real_avcodec_send_packet(AVCodecContext *, const AVPacket *);
int __wrap_avcodec_send_packet(AVCodecContext *c,const AVPacket *packet) {
    int result=__real_avcodec_send_packet(c,packet);
    if (result>=0) clockTick+=inputTicks;
    return result;
}
int __real_avcodec_receive_frame(AVCodecContext *, AVFrame *);
int __wrap_avcodec_receive_frame(AVCodecContext *c,AVFrame *frame) {
    int result=__real_avcodec_receive_frame(c,frame);
    if (result>=0 && suppressOutput>=0) {
        packet_token *token=(void *)frame->opaque_ref->data;
        if (IHS_FrameTicketIdentity(token->ticket).frameId==suppressOutput) {
            av_frame_unref(frame);
            return AVERROR(EAGAIN);
        }
    }
    if (result>=0) clockTick+=outputTicks;
    return result;
}
uint32_t __wrap_IHS_SessionPacketTimestamp(void) { return clockTick; }
bool __wrap_IHS_BaseSend(IHS_Base *b, IHS_SocketAddress a, const IHS_Buffer *data) {
    (void)b; (void)a; (void)data; return true;
}
bool __wrap_IHS_SessionSendControlMessage(IHS_Session *s, EStreamControlMessage t,
                                          const ProtobufCMessage *message) {
    (void)s; (void)t; (void)message; return true;
}
void __real_IHS_SessionPacketsWindowReleaseFrame(IHS_SessionFrame *);
void __wrap_IHS_SessionPacketsWindowReleaseFrame(IHS_SessionFrame *f) {
    __real_IHS_SessionPacketsWindowReleaseFrame(f);
    atomic_fetch_add(&processed, 1);
}
bool __real_IHS_FrameTicketVideoDecodeStage(IHS_FrameTicket *, bool);
bool __wrap_IHS_FrameTicketVideoDecodeStage(IHS_FrameTicket *ticket, bool end) {
    bool recorded = __real_IHS_FrameTicketVideoDecodeStage(ticket, end);
    if (recording && recorded) {
        assert(decodeCount < 1024);
        decodeEvents[decodeCount][0] = action;
        decodeEvents[decodeCount][1] = IHS_FrameTicketIdentity(ticket).frameId;
        decodeEvents[decodeCount][2] = end ? 15 : 14;
        decodeEvents[decodeCount++][3] = clockTick;
    }
    return recorded;
}
bool __real_IHS_FrameTicketComplete(IHS_FrameTicket *, const IHS_FrameOutcome *);
bool __wrap_IHS_FrameTicketComplete(IHS_FrameTicket *ticket, const IHS_FrameOutcome *outcome) {
    bool done = __real_IHS_FrameTicketComplete(ticket, outcome);
    if (recording && done && (outcome->result == IHS_VideoFrameResultDisplayed ||
                             outcome->result == IHS_VideoFrameResultDroppedLate)) {
        assert(completionCount < 2048);
        completed[completionCount][0] = IHS_FrameTicketIdentity(ticket).frameId;
        completed[completionCount++][1] = outcome->result;
    }
    return done;
}
static void controlMessage(IHS_Session *s, EStreamControlMessage t, const ProtobufCMessage *m) {
    IHS_Buffer b = IHS_BUFFER_INIT(64,4096);
    IHS_BufferAppendMessage(&b,m);
    IHS_SessionPacketHeader h = {.type=IHS_SessionPacketTypeReliable,.channelId=1};
    IHS_SessionChannelControlHandoff(s->channels[1],t,&b,&h);
    IHS_SessionChannelControlDrainIncoming(s->channels[1]);
    IHS_BufferClear(&b,true);
}
static void packet(IHS_Session *s, unsigned fid, unsigned seq, unsigned flags, uint32_t stamp,
                   unsigned offset, unsigned size) {
    assert(offset <= sizeof(payload) && size <= sizeof(payload)-offset);
    IHS_SessionFrame f = {.header={.type=IHS_SessionPacketTypeReliable,.channelId=3,
                                   .sendTimestamp=clockTick,.receiveTimestamp=clockTick,
                                   .receiveBegin=clockTick}};
    IHS_BufferInit(&f.body,64,65536);
    IHS_BufferAppendUInt8(&f.body,k_EStreamDataPacket);
    IHS_BufferAppendUInt16LE(&f.body,fid);
    IHS_BufferAppendUInt32LE(&f.body,stamp);
    IHS_BufferAppendUInt16LE(&f.body,0);
    IHS_BufferAppendUInt32LE(&f.body,0);
    IHS_BufferAppendUInt16LE(&f.body,seq);
    IHS_BufferAppendUInt8(&f.body,flags);
    IHS_BufferAppendUInt16LE(&f.body,0); IHS_BufferAppendUInt16LE(&f.body,0);
    IHS_BufferAppendMem(&f.body,payload+offset,size);
    IHS_SessionDeliverReliableFrame(s,&f);
    IHS_SessionFrameClear(&f,true);
    ++target;
    for (unsigned n=0;n<5000 && atomic_load(&processed)<target;++n) usleep(1000);
    assert(atomic_load(&processed)==target && !s->base.interrupted);
}
static void hash(sl_video_frame *frame, uint8_t out[16]) {
    uint8_t bytes[128*72*3/2];
    assert(av_image_copy_to_buffer(bytes,sizeof(bytes),(const uint8_t *const *)frame->pixels->data,
                                  frame->pixels->linesize,AV_PIX_FMT_YUV420P,128,72,1)==sizeof(bytes));
    av_md5_sum(out,bytes,sizeof(bytes));
}
static uint8_t golden[16];
static sl_video_scheduler scheduler;
static void record_selection(const sl_video_selection *s, bool selectedJob) {
    assert(selectCount<512);
    selected[selectCount][0]=action;
    selected[selectCount][1]=selectedJob?IHS_FrameTicketIdentity(s->ticket).frameId:-1;
    selected[selectCount++][2]=selectedJob?s->media_timestamp:0;
    if (selectedJob && s->frame) {
        assert(physicalCount<1024);
        physical[physicalCount][0]=action;
        physical[physicalCount][1]=IHS_FrameTicketIdentity(s->frame->ticket).frameId;
        physical[physicalCount++][2]=s->frame->media_timestamp;
        uint8_t actual[16];hash(s->frame,actual);assert(!memcmp(golden,actual,16));
    }
}
bool __real_sl_video_select(sl_video_pipeline *, sl_video_selection *);
bool __wrap_sl_video_select(sl_video_pipeline *p,sl_video_selection *s) {
    bool selectedJob=__real_sl_video_select(p,s);
    if (presenting) record_selection(s,selectedJob);
    return selectedJob;
}
bool __real_IHS_FrameTicketUploadStage(IHS_FrameTicket *,bool,uint64_t);
bool __wrap_IHS_FrameTicketUploadStage(IHS_FrameTicket *t,bool end,uint64_t us) {
    bool recorded=__real_IHS_FrameTicketUploadStage(t,end,us);
    if (recording && recorded) {
        assert(prepCount<1024);
        prep[prepCount][0]=action;prep[prepCount][1]=IHS_FrameTicketIdentity(t).frameId;
        prep[prepCount++][2]=end?17:16;
    }
    return recorded;
}
static void consume(void) {
    sl_video_selection s={0};
    bool selectedJob=!sl_video_scheduler_wait(&scheduler,pipeline,now_us()) && sl_video_select(pipeline,&s);
    record_selection(&s,selectedJob);
    if (!selectedJob) return;
    IHS_FrameOutcome out={.result=IHS_VideoFrameResultDisplayed,.presentationSerial=selectCount,
                          .completionUs=now_us()};
    sl_video_selection_complete(&s,&out);
    sl_video_selection_release(&s);
}
static void observe(void) {
    pthread_mutex_lock(&pipeline->mailbox);
    sl_video_timing *timing=&pipeline->timing;
    uint32_t sum; memcpy(&sum,&timing->sum,4);
    printf("{\"jitter\":{\"count\":%u,\"sum_bits\":%u,\"budget\":%d,\"samples\":\"",timing->count,sum,timing->budget);
    const uint8_t *bytes=(const uint8_t *)timing->samples;
    for (unsigned n=0;n<timing->count*4;++n) printf("%02x",bytes[n]);
    printf("\"},\"pending\":[");
    for (unsigned n=0;n<pipeline->job_count;++n) {
        input_job *j=&pipeline->jobs[n];
        printf("%s[%u,%u]",n?",":"",IHS_FrameTicketIdentity(j->ticket).frameId,j->media_timestamp);
    }
    pthread_mutex_unlock(&pipeline->mailbox);
    printf("],\"pictures\":[");
    for (unsigned n=0;n<pictureCount;++n) printf("%s[%u,%u,%u]",n?",":"",pictures[n][0],pictures[n][1],pictures[n][2]);
    printf("],\"submissions\":[");
    for (unsigned n=0;n<submitCount;++n) printf("%s[%u,%u,%u]",n?",":"",submits[n][0],submits[n][1],submits[n][2]);
    printf("],\"decode_events\":[");
    for (unsigned n=0;n<decodeCount;++n) printf("%s[%u,%u,%u,%u]",n?",":"",decodeEvents[n][0],decodeEvents[n][1],decodeEvents[n][2],decodeEvents[n][3]);
    printf("],\"selected\":[");
    for (unsigned n=0;n<selectCount;++n) {
        printf("%s[%ld,",n?",":"",(long)selected[n][0]);
        if (selected[n][1]<0) printf("null]");
        else printf("[%ld,%ld]]",(long)selected[n][1],(long)selected[n][2]);
    }
    printf("],\"waits\":[");
    for (unsigned n=0;n<waitCount;++n) printf("%s[%ld,%ld]",n?",":"",(long)waits[n][0],(long)waits[n][1]);
    printf("],\"completed\":[");
    for (unsigned n=0;n<completionCount;++n) printf("%s[%u,%u]",n?",":"",completed[n][0],completed[n][1]);
    printf("],\"physical_selected\":[");
    for(unsigned n=0;n<physicalCount;++n) printf("%s[%u,%u,%u]",n?",":"",physical[n][0],physical[n][1],physical[n][2]);
    printf("],\"prep\":[");
    for(unsigned n=0;n<prepCount;++n) printf("%s[%u,%u,%u]",n?",":"",prep[n][0],prep[n][1],prep[n][2]);
    printf("],\"codec_pts\":[");
    for(unsigned n=0;n<codecCount;++n) printf("%s[%llu,%llu,%llu,%llu]",n?",":"",(unsigned long long)codecPts[n][0],(unsigned long long)codecPts[n][1],(unsigned long long)codecPts[n][2],(unsigned long long)codecPts[n][3]);
    puts("]}");
}
static sl_video_frame *resourceOld;
static void *resourceMapping;
static uint32_t resourceStamp;
static void resources(sl_runtime *r) {
    recording=false;
    for (unsigned n=0;n<60;++n) {
        clockTick=1000000+n*1092;
        packet(r->session,n,n,n?8:24,clockTick-655,0,sizeof(payload));
        if (!n) {
            sl_video_selection first={0};assert(sl_video_select(pipeline,&first));
            resourceOld=first.frame;first.frame=NULL;assert(resourceOld);
            IHS_FrameOutcome displayed={.result=IHS_VideoFrameResultDisplayed,.completionUs=now_us()};
            sl_video_selection_complete(&first,&displayed);sl_video_selection_release(&first);
            resourceMapping=sl_video_hold_mapping(resourceOld);assert(resourceMapping);
            resourceStamp=resourceOld->media_timestamp;
            uint8_t actual[16];hash(resourceOld,actual);assert(!memcmp(actual,golden,16));
        } else consume();
    }
    assert(pipeline->timing.budget==9 && !pipeline->pending_count);
    sl_video_frame *cached=pipeline->image;assert(cached);
    /* Real first marked fragment flushes only the backend, not player tasks
     * or its already selected immutable image; finish arrives separately. */
    packet(r->session,60,60,16,clockTick+655,0,0);
    assert(pipeline->image==cached && !pipeline->pending_count && !pipeline->job_count);
    unsigned last=60+LEASE_COUNT+6;
    for (unsigned n=60;n<last;++n)
        packet(r->session,n,n+1,8,clockTick+655,0,sizeof(payload));
    assert(pipeline->pending_count==LEASE_COUNT-2 && pipeline->counters.replaced==8);
    sl_video_selection future={0};
    assert(sl_video_wait(pipeline)>0 && !sl_video_select(pipeline,&future));
    packet(r->session,last,last+1,72,clockTick,0,sizeof(payload));
    IHS_SessionVideoHandlePendingReset(r->session);
    assert(r->facts.epoch==2 && pipeline->timing.budget==9 && !pipeline->pending_count);
    packet(r->session,last+1,last+2,88,clockTick-655,0,sizeof(payload));
    consume();
    /* Accepted input with no returned pixel keeps its task/metadata alive;
     * Stop must cancel this separate waiting owner before session teardown. */
    suppressOutput=(int)last+2;clockTick+=1092;
    packet(r->session,last+2,last+3,72,clockTick-655,0,sizeof(payload));
    sl_video_selection waiting={0};assert(!sl_video_select(pipeline,&waiting));
    assert(pipeline->waiting.ticket && IHS_FrameTicketIdentity(pipeline->waiting.ticket).frameId==last+2);
    IHS_TrackedFrame records[IHS_FRAME_TRACKER_CAPACITY];
    size_t count=IHS_FrameTrackerCopyStats(r->session->frameTracker,records,IHS_FRAME_TRACKER_CAPACITY);
    bool pending=false;
    for(size_t n=0;n<count;++n) if(records[n].identity.frameId==last+2) {
        assert(records[n].hasDecodeBegin && records[n].hasDecodeEnd && !records[n].statsComplete);
        pending=true;
    }
    assert(pending);suppressOutput=-1;
    uint8_t actual[16];hash(resourceOld,actual);
    assert(!memcmp(actual,golden,16) && resourceOld->media_timestamp==resourceStamp);
}
int main(int argc,char **argv) {
    assert(argc==2 || (argc==3 && !strcmp(argv[2],"--resources")));
    assert(!setenv("SDL_VIDEODRIVER","dummy",1));
    assert(!setenv("SDL_AUDIODRIVER","dummy",1));
    assert(!setenv("SDL_RENDER_DRIVER","software",1));
    assert(stream_media_init(NULL));
    IHS_Init();
    sl_runtime r={0}; pthread_mutex_init(&r.lock,NULL); r.facts.session_id=90;
    r.session=IHS_TestSessionCreate(); assert(r.session);
    IHS_TimerTaskStopImmediate(r.session->retransmission.timer);
    r.session->state.connectionState=IHS_SessionConnectionStateConnected;
    assert(IHS_SessionSetVideoTrackingIdentity(r.session,90));
    IHS_SessionSetVideoCallbacks(r.session,&video_cb,&r);
    CStartVideoDataMsg m=CSTART_VIDEO_DATA_MSG__INIT;
    m.channel=3;m.has_codec=m.has_width=m.has_height=true;
    m.codec=k_EStreamVideoCodecH264;m.width=128;m.height=72;
    controlMessage(r.session,k_EStreamControlStartVideoData,&m.base);
    FILE *in=fopen(argv[1],"rb");assert(in);
    assert(fread(payload,1,sizeof(payload),in)==sizeof(payload));assert(!fclose(in));
    char goldenPath[4096], goldenLine[256], digest[33] = {0};
    assert(strlen(argv[1]) > 5 && strlen(argv[1]) < 4000);
    snprintf(goldenPath,sizeof(goldenPath),"%.*s.framemd5",(int)strlen(argv[1])-5,argv[1]);
    FILE *goldenFile=fopen(goldenPath,"r");assert(goldenFile);
    while(fgets(goldenLine,sizeof(goldenLine),goldenFile)) {
        if (goldenLine[0]=='#') continue;
        char *comma=strrchr(goldenLine,',');assert(comma && sscanf(comma+1,"%32s",digest)==1);break;
    }
    assert(!fclose(goldenFile) && strlen(digest)==32);
    for(unsigned n=0;n<16;++n) { unsigned value;assert(sscanf(digest+n*2,"%2x",&value)==1);golden[n]=value; }
    sl_video_scheduler_init(&scheduler,true);
    recording=true;
    if (argc==3) resources(&r);
    char line[512];
    while (argc==2 && fgets(line,sizeof(line),stdin)) {
        if (line[0]=='Q') {
            assert(sscanf(line,"Q %u %u",&inputTicks,&outputTicks)==2);
        } else if (line[0]=='P') {
            unsigned fid,seq,flags,offset,size,stamp,now;
            assert(sscanf(line,"P %u %u %u %u %u %u %u",&fid,&seq,&flags,&stamp,&now,&offset,&size)==7);
            clockTick=now;packet(r.session,fid,seq,flags,stamp,offset,size);
        } else if (line[0]=='B') {
            unsigned budget;assert(sscanf(line,"B %u",&budget)==1);
            pthread_mutex_lock(&pipeline->mailbox);pipeline->timing.budget=(int)budget;pthread_mutex_unlock(&pipeline->mailbox);
        } else if (line[0]=='X') {
            assert(sscanf(line,"X %d",&suppressOutput)==1);
        } else if (line[0]=='D') {
            assert(sscanf(line,"D %u",&clockTick)==1);
            presenting=true;stream_media_present();presenting=false;
        } else if (line[0]=='N') {
            assert(sscanf(line,"N %u",&clockTick)==1);consume();
        } else if (line[0]=='W') {
            assert(sscanf(line,"W %u",&clockTick)==1);assert(waitCount<512);
            waits[waitCount][0]=action; waits[waitCount++][1]=sl_video_wait(pipeline);
        } else {
            assert(line[0]=='R');IHS_SessionVideoHandlePendingReset(r.session);
        }
        observe();++action;
    }
    recording=false;
    CStopVideoDataMsg stop=CSTOP_VIDEO_DATA_MSG__INIT;
    controlMessage(r.session,k_EStreamControlStopVideoData,&stop.base);
    sl_media_collect();
    IHS_SessionDestroy(r.session);IHS_Quit();
    if (resourceOld) {
        assert(!sl_media_video_clean());
        uint8_t actual[16];hash(resourceOld,actual);
        assert(!memcmp(actual,golden,16) && resourceOld->media_timestamp==resourceStamp);
        sl_resource_release(&resourceOld->ref);
        assert(!sl_media_video_clean());
        sl_video_release_mapping(resourceMapping);
    }
    assert(sl_media_video_clean());
    if (argc==3) puts("Video timing resources passed");
    pthread_mutex_destroy(&r.lock);stream_media_shutdown();
    return 0;
}
