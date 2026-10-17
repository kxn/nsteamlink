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
static bool recording;
static unsigned action;
static uint8_t golden[16];
static int forcedSend=INT_MAX, forcedReceive=INT_MAX, parseDelta, parsedSize=-1;
static int forcedWidth=-1, forcedHeight=-1, forcedFormat=-1;
static bool resetRequested, presentReturned=true;
static int formatResult=-2;
static bool requestedHardware;
static unsigned controlCount, controlSteps[512], controlSizes[512];
static uint8_t controlBodies[512][1024];
sl_video_open_result __real_sl_video_open_ex(sl_video_pipeline *,sl_video_key,const sl_video_config *);
sl_video_open_result __wrap_sl_video_open_ex(sl_video_pipeline *p,sl_video_key key,const sl_video_config *config) {
    requestedHardware=config->hardware;
    return __real_sl_video_open_ex(p,key,config);
}
static int64_t forcedPts=AV_NOPTS_VALUE;
static unsigned eventCount;
static int64_t events[8192][5];
static void event(unsigned kind,int64_t a,int64_t b,int64_t c) {
    if (!recording) return;
    assert(eventCount<8192);
    events[eventCount][0]=action;events[eventCount][1]=kind;
    events[eventCount][2]=a;events[eventCount][3]=b;events[eventCount++][4]=c;
}
static unsigned action, pictureCount, submitCount, completionCount, selectCount, waitCount;
static uint32_t pictures[512][3], submits[512][3], completed[2048][2];
static unsigned decodeCount;
static uint32_t decodeEvents[1024][4];
static int64_t selected[512][3], waits[512][2];
static uint8_t payload[2204];
static bool recording, presenting;
static int suppressOutput = -1;
static unsigned physicalCount, prepCount, inputCount;
static uint64_t inputSerials[512][4];
static uint32_t physical[1024][3], prep[1024][3];
sl_video_pipeline *sl_video_create(void) { return pipeline = timing_create(); }
sl_video_submit_result sl_video_submit(sl_video_pipeline *p, sl_video_key key, const unsigned char *data,
                                       size_t size, IHS_FrameTicket *ticket, bool *taken, bool keyframe, sl_video_feedback_fn feedback, void *context) {
    uint32_t stamp;
    assert(IHS_FrameTicketVideoTimestamp(ticket, &stamp));
    assert(!size || (size == sizeof(payload) && !memcmp(data, payload, size)));
    IHS_FrameIdentity identity = IHS_FrameTicketIdentity(ticket);
    assert(submitCount < 512);
    submits[submitCount][0] = action; submits[submitCount][1] = identity.frameId;
    submits[submitCount++][2] = stamp;
    uint64_t before = p->publish_seq;
    sl_video_submit_result result = timing_submit(p, key, data, size, ticket, taken, keyframe, feedback, context);
    assert(result != SL_VIDEO_SUBMIT_ERROR && p->publish_seq <= before + (size != 0));
    pthread_mutex_lock(&p->mailbox);
    assert(inputCount < 512);
    if (!p->job_count) { pthread_mutex_unlock(&p->mailbox); return result; }
    input_job *job=&p->jobs[p->job_count-1];
    assert(IHS_FrameTicketIdentity(job->ticket).frameId==identity.frameId);
    inputSerials[inputCount][0]=action;inputSerials[inputCount][1]=identity.frameId;
    inputSerials[inputCount][2]=stamp;inputSerials[inputCount++][3]=job->input_serial;
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
sl_gfx_present_result __real_sl_gfx_present(sl_gfx *);
sl_gfx_present_result __wrap_sl_gfx_present(sl_gfx *g) {
    sl_gfx_present_result result=__real_sl_gfx_present(g);
    result.output_returned=presentReturned;
    return result;
}
static atomic_uint processed;
static unsigned target;
int __real_avcodec_send_packet(AVCodecContext *, const AVPacket *);
int __wrap_avcodec_send_packet(AVCodecContext *c,const AVPacket *packet) {
    int result=__real_avcodec_send_packet(c,packet);
    if (packet) clockTick+=inputTicks;
    if (packet && forcedSend!=INT_MAX) result=forcedSend;
    if(packet) assert(packet->pts==AV_NOPTS_VALUE);
    event(4,result,packet?packet->size:0,clockTick);
    return result;
}
static void verify_pixels(AVFrame *frame) {
    uint8_t bytes[128*72*3/2],digest[16];
    assert(av_image_copy_to_buffer(bytes,sizeof(bytes),(const uint8_t *const *)frame->data,
           frame->linesize,AV_PIX_FMT_YUV420P,128,72,1)==sizeof(bytes));
    av_md5_sum(digest,bytes,sizeof(bytes));assert(!memcmp(digest,golden,16));
}
int __real_avcodec_receive_frame(AVCodecContext *, AVFrame *);
void __real_avcodec_flush_buffers(AVCodecContext *);
void __wrap_avcodec_flush_buffers(AVCodecContext *c) {
    event(8,0,0,clockTick);__real_avcodec_flush_buffers(c);
}
int __wrap_avcodec_receive_frame(AVCodecContext *c,AVFrame *frame) {
    int result=__real_avcodec_receive_frame(c,frame);
    if (!result) {
        verify_pixels(frame);
        packet_token *token=(void *)frame->opaque_ref->data;
        if (IHS_FrameTicketIdentity(token->ticket).frameId==suppressOutput ||
            (forcedReceive!=INT_MAX && forcedReceive!=0)) {
            av_frame_unref(frame);
            result=forcedReceive!=INT_MAX?forcedReceive:AVERROR(EAGAIN);
        } else {
            frame->pts=forcedPts;
            if (forcedWidth>=0) frame->width=forcedWidth;
            if (forcedHeight>=0) frame->height=forcedHeight;
            if (forcedFormat>=0) frame->format=forcedFormat;
        }
    } else if (forcedReceive!=INT_MAX) {
        assert(forcedReceive!=0); /* never fabricate a successful physical frame */
        result=forcedReceive;
    }
    clockTick+=outputTicks;
    event(5,result,0,clockTick);
    return result;
}
int __real_av_parser_parse2(AVCodecParserContext *,AVCodecContext *,uint8_t **,int *,
                           const uint8_t *,int,int64_t,int64_t,int64_t);
int __wrap_av_parser_parse2(AVCodecParserContext *parser,AVCodecContext *context,uint8_t **out,int *size,
                           const uint8_t *in,int count,int64_t pts,int64_t dts,int64_t pos) {
    int result=__real_av_parser_parse2(parser,context,out,size,in,count,pts,dts,pos);
    if(parsedSize>=0) { assert(parsedSize<=count);*size=parsedSize; }
    return result+parseDelta;
}
void __real_sl_video_timing_update(sl_video_timing *,uint32_t,uint32_t,bool);
void __wrap_sl_video_timing_update(sl_video_timing *t,uint32_t stamp,uint32_t now,bool surface) {
    event(3,stamp,now,0);__real_sl_video_timing_update(t,stamp,now,surface);
}
bool __real_IHS_SessionVideoDecodeFeedback(IHS_Session *,const IHS_VideoEpochInfo *,IHS_StreamVideoSubmitResult);
bool __wrap_IHS_SessionVideoDecodeFeedback(IHS_Session *s,const IHS_VideoEpochInfo *e,IHS_StreamVideoSubmitResult r) {
    bool ok=__real_IHS_SessionVideoDecodeFeedback(s,e,r);
    if(ok && (r&IHS_StreamVideoSubmitReset)) resetRequested=true;
    event(7,r,ok,clockTick);
    return ok;
}
bool __real_IHS_SessionChannelQueuePacket(IHS_SessionChannel *,IHS_SessionPacket *,bool);
bool __wrap_IHS_SessionChannelQueuePacket(IHS_SessionChannel *ch,IHS_SessionPacket *packet,bool retry) {
    if(packet->header.channelId==3 && packet->body.size==1 && IHS_BufferPointer(&packet->body)[0]==2)
        event(2,3,2,clockTick); /* exact empty DataLost body, through real serializer/queue */
    return __real_IHS_SessionChannelQueuePacket(ch,packet,retry);
}
uint32_t __wrap_IHS_SessionPacketTimestamp(void) { return clockTick; }
bool __wrap_IHS_BaseSend(IHS_Base *b, IHS_SocketAddress a, const IHS_Buffer *data) {
    (void)b; (void)a; (void)data; return true;
}
bool __wrap_IHS_SessionSendControlMessage(IHS_Session *s, EStreamControlMessage t,
                                          const ProtobufCMessage *message) {
    (void)s;
    if(recording) {
        assert(controlCount<512);size_t size=protobuf_c_message_get_packed_size(message);
        assert(size+1<=sizeof(controlBodies[0]));
        controlSteps[controlCount]=action;controlSizes[controlCount]=(unsigned)size+1;
        controlBodies[controlCount][0]=(uint8_t)t;
        assert(protobuf_c_message_pack(message,controlBodies[controlCount]+1)==size);
        ++controlCount;
    }
    event(9,t,0,clockTick); return true;
}
static void config_changed(IHS_Session *s,const uint8_t *p,size_t n,bool local,void *context) {
    event(10,n,local,clockTick);
    if(session_cb.clientConfigChanged)
        session_cb.clientConfigChanged(s,p,n,local,context); /* Actual production table. */
}
static void config_saved(IHS_Session *s,const uint8_t *p,size_t n,void *context) {
    (void)s;(void)p;(void)context;event(11,n,0,clockTick);
}
static const IHS_StreamSessionCallbacks config_callbacks={
    .clientConfigChanged=config_changed,.saveClientConfig=config_saved,
};
bool __real_IHS_SessionVideoRequestReset(IHS_Session *);
bool __wrap_IHS_SessionVideoRequestReset(IHS_Session *s) {
    bool applied=__real_IHS_SessionVideoRequestReset(s);
    event(12,applied,0,clockTick);return applied;
}
void __real_IHS_SessionPacketsWindowReleaseFrame(IHS_SessionFrame *);
void __wrap_IHS_SessionPacketsWindowReleaseFrame(IHS_SessionFrame *f) {
    __real_IHS_SessionPacketsWindowReleaseFrame(f);
    atomic_fetch_add(&processed, 1);
}
bool __real_IHS_FrameTicketVideoDecodeStage(IHS_FrameTicket *, bool);
bool __wrap_IHS_FrameTicketVideoDecodeStage(IHS_FrameTicket *ticket, bool end) {
    bool recorded = __real_IHS_FrameTicketVideoDecodeStage(ticket, end);
    event(0,IHS_FrameTicketIdentity(ticket).frameId,end?15:14,clockTick);
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
    event(1,IHS_FrameTicketIdentity(ticket).frameId,outcome->result,done);
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
/* CopyStats consumes each completion once. Retain that actual consumed
 * record in observer history; a later non-repeat must not look pending again. */
static IHS_TrackedFrame observedStats[IHS_FRAME_TRACKER_CAPACITY];
static void observe(sl_runtime *runtime) {
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
    printf("],\"input_serials\":[");
    for(unsigned n=0;n<inputCount;++n) printf("%s[%llu,%llu,%llu,%llu]",n?",":"",(unsigned long long)inputSerials[n][0],(unsigned long long)inputSerials[n][1],(unsigned long long)inputSerials[n][2],(unsigned long long)inputSerials[n][3]);
    printf("],\"events\":[");
    for(unsigned n=0;n<eventCount;++n) printf("%s[%lld,%lld,%lld,%lld,%lld]",n?",":"",
        (long long)events[n][0],(long long)events[n][1],(long long)events[n][2],(long long)events[n][3],(long long)events[n][4]);
    printf("],\"tracker\":[");
    IHS_TrackedFrame records[IHS_FRAME_TRACKER_CAPACITY];
    size_t count=IHS_FrameTrackerCopyStats(runtime->session->frameTracker,records,IHS_FRAME_TRACKER_CAPACITY);
    for(size_t n=0;n<count;++n) {
        IHS_TrackedFrame *f=&records[n];
        IHS_TrackedFrame *old=&observedStats[f->identity.frameId%IHS_FRAME_TRACKER_CAPACITY];
        if(f->statsComplete) *old=*f;
        else if(old->statsComplete && old->identity.epoch==f->identity.epoch &&
                old->identity.receiveSerial==f->identity.receiveSerial) {
            f->statsComplete=true;f->outcome=old->outcome;
        }
        printf("%s{\"id\":%u,\"complete\":%s,\"result\":%d,\"decode_begin\":%s,\"decode_end\":%s}",
            n?",":"",f->identity.frameId,f->statsComplete?"true":"false",f->outcome.result,
            f->hasDecodeBegin?"true":"false",f->hasDecodeEnd?"true":"false");
    }
    printf("],\"control_bodies\":[");
    for(unsigned n=0;n<controlCount;++n) {
        printf("%s[%u,\"",n?",":"",controlSteps[n]);
        for(unsigned k=0;k<controlSizes[n];++k)printf("%02x",controlBodies[n][k]);
        printf("\"]");
    }
    printf("],\"reset_feedback_applied\":%s,\"hardware_preference\":%s,\"config\":\"",
        resetRequested?"true":"false",IHS_SessionVideoHardwareDecodingEnabled(runtime->session)?"true":"false");
    uint8_t config[512];size_t configSize=IHS_SessionGetStreamingClientConfig(runtime->session,config,sizeof(config));
    assert(configSize<=sizeof(config));for(size_t n=0;n<configSize;++n)printf("%02x",config[n]);
    printf("\",\"epoch\":%llu,\"format_result\":%d,\"requested_hardware\":%s,\"player_hardware_cache\":%s}\n",
        (unsigned long long)runtime->facts.epoch,formatResult,requestedHardware?"true":"false",
        runtime->player_hardware_decoding?"true":"false");
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
    /* AVCodec EAGAIN is a completed error plus a consumable placeholder. */
    suppressOutput=(int)last+2;clockTick+=1092;
    packet(r->session,last+2,last+3,72,clockTick-655,0,sizeof(payload));
    sl_video_selection waiting={0};assert(sl_video_select(pipeline,&waiting));
    assert(waiting.ticket && !waiting.frame);sl_video_selection_release(&waiting);
    IHS_TrackedFrame records[IHS_FRAME_TRACKER_CAPACITY];
    size_t count=IHS_FrameTrackerCopyStats(r->session->frameTracker,records,IHS_FRAME_TRACKER_CAPACITY);
    bool pending=false;
    for(size_t n=0;n<count;++n) if(records[n].identity.frameId==last+2) {
        assert(records[n].hasDecodeBegin && records[n].hasDecodeEnd && records[n].statsComplete && records[n].outcome.result==IHS_VideoFrameResultDroppedReset);
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
    client_config_begin(r.session,&r);
    IHS_SessionSetSessionCallbacks(r.session,&config_callbacks,&r);
    CStartVideoDataMsg m=CSTART_VIDEO_DATA_MSG__INIT;
    m.channel=3;m.has_codec=m.has_width=m.has_height=true;
    m.codec=k_EStreamVideoCodecH264;m.width=128;m.height=72;
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
    if (argc==3) {controlMessage(r.session,k_EStreamControlStartVideoData,&m.base);resources(&r);}
    bool videoStarted=false;
    char line[512];
    while (argc==2 && fgets(line,sizeof(line),stdin)) {
        if(!videoStarted && line[0]!='C') {
            recording=false;
            controlMessage(r.session,k_EStreamControlStartVideoData,&m.base);
            recording=true;videoStarted=true;
        }
        if (line[0]=='C' || line[0]=='U' || line[0]=='G') {
            uint8_t config[256];size_t n=0;
            unsigned local=1;char *hex=line+2;
            if(line[0]=='U') {assert((line[2]=='0'||line[2]=='1')&&line[3]==' ');local=line[2]-'0';hex=line+4;}
            if(hex[0]!='-') {
                size_t length=strcspn(hex,"\r\n");assert(!(length&1) && length/2<=sizeof(config));
                for(;n<length/2;++n){unsigned value;assert(sscanf(hex+n*2,"%2x",&value)==1);config[n]=value;}
            }
            if(line[0]=='G') {
                IHS_Buffer b=IHS_BUFFER_INIT(64,4096);IHS_BufferAppendMem(&b,config,n);
                IHS_SessionPacketHeader h={.type=IHS_SessionPacketTypeReliable,.channelId=1};
                IHS_SessionChannelControlHandoff(r.session->channels[1],k_EStreamControlSetStreamingClientConfig,&b,&h);
                IHS_SessionChannelControlDrainIncoming(r.session->channels[1]);IHS_BufferClear(&b,true);
            } else {
                assert(IHS_SessionSetStreamingClientConfig(r.session,config,n,local));
            }
        } else if (line[0]=='F') {
            unsigned count;int used;assert(sscanf(line,"F %u%n",&count,&used)==1 && count<16);
            enum AVPixelFormat formats[16];char *next=line+used;
            for(unsigned n=0;n<count;++n)formats[n]=(enum AVPixelFormat)strtol(next,&next,10);
            formats[count]=AV_PIX_FMT_NONE;
            domain unavailable={.hardware_format=AV_PIX_FMT_NONE};
            AVCodecContext context={.opaque=&unavailable};
            formatResult=hardware_format(&context,formats); /* Explicit unavailable target HW input. */
        } else if (line[0]=='T') {
            long long value;assert(sscanf(line,"T %lld",&value)==1);forcedPts=value;
        } else if (line[0]=='V') {
            int value;assert(sscanf(line,"V %d",&value)==1);presentReturned=value!=0;
        } else if (line[0]=='E') {
            assert(sscanf(line,"E %d %d %d %d %d %d %d",&forcedSend,&forcedReceive,&parseDelta,&parsedSize,
                &forcedWidth,&forcedHeight,&forcedFormat)==7);
        } else if (line[0]=='Q') {
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
        observe(&r);++action;
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
