/* Headless endpoint adapter: production IHS and production video pipeline.
 * No runtime/SDL/GPU renderer, forced SDK result, or parsed media input. */
#include "video_pipeline.h"
#include <libavcodec/avcodec.h>
#include <libavutil/md5.h>
#include <libavutil/sha.h>
#include <libavutil/mem.h>

static sl_video_pipeline *udpVideo;
static atomic_bool udpSubmitted, udpStopped;
static unsigned udpStarts, udpSubmits;
static atomic_uint udpSdkPackets;
static bool udpGapMode;
static struct { size_t size; uint8_t sha[32]; } udpSdkInputs[3];
static struct { unsigned id; uint8_t md5[16]; } udpPictures[3];
static unsigned udpPictureCount;
static size_t udpSdkSize;
static uint8_t udpSdkSha[32], udpPixelMd5[16];
static unsigned udpPictureId, udpWidth, udpHeight;
static bool udpHavePicture;
static uint8_t udpCpuCount(void) { return 4; } /* Explicit matching Source CPU fact. */
static sl_video_key udpKey(const IHS_VideoEpochInfo *e) {
    return (sl_video_key){e->session_id,e->video_epoch};
}
static void udpHash(const uint8_t *p,size_t size,uint8_t out[32]) {
    struct AVSHA *sha=av_sha_alloc();assert(sha);
    assert(!av_sha_init(sha,256));av_sha_update(sha,p,size);av_sha_final(sha,out);av_free(sha);
}
int __real_avcodec_send_packet(AVCodecContext *, const AVPacket *);
int __wrap_avcodec_send_packet(AVCodecContext *context,const AVPacket *packet) {
    if(udpVideo && packet) {
        unsigned index=atomic_fetch_add(&udpSdkPackets,1);udpSdkSize=(size_t)packet->size;
        udpHash(packet->data,udpSdkSize,udpSdkSha);
        if(udpGapMode) {assert(index<3);udpSdkInputs[index].size=udpSdkSize;memcpy(udpSdkInputs[index].sha,udpSdkSha,32);}
    }
    uint64_t begin=udpLoadMode?udpLoadSDKBegin(udpSdkSize,udpSdkSha):0;
    int result=__real_avcodec_send_packet(context,packet);
    if(udpLoadMode)udpLoadSDKEnd(begin,result);
    return result;
}
typedef struct udpBorrowed { IHS_Session *session; const IHS_VideoEpochInfo *epoch; } udpBorrowed;
static void udpInfo(void *context,const char *text,unsigned threads) {
    udpBorrowed *b=context;IHS_SessionVideoDecoderInfo(b->session,b->epoch,text,threads);
}
static void udpFeedback(void *context,sl_video_submit_result result) {
    udpBorrowed *b=context;unsigned flags=0;
    if(result&SL_VIDEO_SUBMIT_RESET)flags|=IHS_StreamVideoSubmitReset;
    if(result&SL_VIDEO_SUBMIT_CORRUPT)flags|=IHS_StreamVideoSubmitReportLost;
    if(result&SL_VIDEO_SUBMIT_DISABLE_HARDWARE)flags|=IHS_StreamVideoSubmitDisableHardware;
    assert(IHS_SessionVideoDecodeFeedback(b->session,b->epoch,(IHS_StreamVideoSubmitResult)flags));
}
static int udpVideoStart(IHS_Session *session,const IHS_VideoEpochInfo *epoch,const IHS_StreamVideoConfig *c,void *context) {
    (void)context;assert(c->codec==IHS_StreamVideoCodecH264 && c->width==128 && c->height==72);
    assert(!IHS_SessionVideoHardwareDecodingEnabled(session));
    udpBorrowed borrowed={session,epoch};
    sl_video_config config={.width=c->width,.height=c->height,.hardware=false,.info=udpInfo,.info_context=&borrowed,.cpu_count=udpCpuCount,.deferred_formats=true};
    assert(sl_video_open_ex(udpVideo,udpKey(epoch),&config)==SL_VIDEO_OPEN_READY);
    ++udpStarts;return 0;
}
static IHS_StreamVideoSubmitResult udpVideoSubmit(IHS_Session *session,const IHS_VideoEpochInfo *epoch,uint16_t id,IHS_FrameTicket *ticket,IHS_Buffer *data,IHS_StreamVideoFrameFlag flags,bool *taken,void *context) {
    (void)context;assert(id==23 || udpGapMode || udpLoadMode);
    if(udpLoadMode)udpLoadSubmittingId=id;
    udpBorrowed b={session,epoch};
    sl_video_submit_result result=sl_video_submit(udpVideo,udpKey(epoch),IHS_BufferPointer(data),data->size,ticket,taken,(flags&IHS_StreamVideoFrameKeyFrame)&&!(flags&IHS_StreamVideoFrameFlushHandled),udpFeedback,udpInfo,&b);
    assert(result!=SL_VIDEO_SUBMIT_ERROR);++udpSubmits;
    atomic_store(&udpSubmitted,true);return IHS_StreamVideoSubmitOK;
}
static void udpVideoInterrupt(IHS_Session *s,const IHS_VideoEpochInfo *e,bool restarting,void *ctx) {
    (void)s;(void)ctx;sl_video_cancel_formats(udpVideo,udpKey(e),restarting);
}
static void udpVideoThink(IHS_Session *s,const IHS_VideoEpochInfo *e,void *ctx) {
    (void)ctx;udpBorrowed b={s,e};sl_video_process_formats(udpVideo,udpKey(e),udpInfo,&b);
}
static void udpVideoFlush(IHS_Session *s,const IHS_VideoEpochInfo *e,IHS_StreamVideoFlushPhase phase,void *ctx) {
    (void)s;(void)ctx;
    if(phase==IHS_StreamVideoFlushPlayer)sl_video_close(udpVideo,udpKey(e));
    else sl_video_discard_buffers(udpVideo,udpKey(e));
}
static void udpVideoStop(IHS_Session *s,const IHS_VideoEpochInfo *e,void *ctx) {
    (void)s;(void)ctx;sl_video_stop(udpVideo,udpKey(e));sl_video_reap(udpVideo);atomic_store(&udpStopped,true);
}
static void udpTakePicture(void) {
    if((udpHavePicture && !udpGapMode && !udpLoadMode) || !atomic_load(&udpSubmitted))return;
    sl_video_selection selected={0};
    sl_video_frame *f;
    if(udpLoadMode) {
        /* Sustained playback consumes both jobs and pixels, as media.c does.
         * Raw sl_video_take is only the bounded codec-probe observation API. */
        if(!sl_video_select(udpVideo,&selected))return;
        f=selected.frame;
        if(!f) {sl_video_selection_release(&selected);return;}
    } else {f=sl_video_take(udpVideo);if(!f)return;}
    AVFrame *af=f->pixels;assert(af->format==AV_PIX_FMT_YUV420P);
    udpWidth=(unsigned)af->width;udpHeight=(unsigned)af->height;
    struct AVMD5 *md5=av_md5_alloc();assert(md5);av_md5_init(md5);
    for(unsigned p=0;p<3;++p) {
        unsigned width=p?udpWidth/2:udpWidth,height=p?udpHeight/2:udpHeight;
        assert(af->linesize[p]>0);
        for(unsigned row=0;row<height;++row)av_md5_update(md5,af->data[p]+row*(unsigned)af->linesize[p],width);
    }
    av_md5_final(md5,udpPixelMd5);av_free(md5);
    udpPictureId=IHS_FrameTicketIdentity(f->ticket).frameId;
    if(udpGapMode) {assert(udpPictureCount<3);udpPictures[udpPictureCount].id=udpPictureId;memcpy(udpPictures[udpPictureCount].md5,udpPixelMd5,16);++udpPictureCount;}
    if(udpLoadMode)udpLoadPixel(udpPictureId,udpPixelMd5);
    /* Headless observation has no physical Displayed outcome. Release the
     * consumed task through its normal cancellation/retirement contract. */
    if(udpLoadMode)sl_video_selection_release(&selected);else sl_resource_release(&f->ref);
    udpHavePicture=true;
}
static FILE *udpReplayFile;
static uint8_t udpExpectedFeedback[64];
static uint32_t udpExpectedFeedbackSize;
static uint32_t udpReplaySize(FILE *file) {
    uint8_t bytes[4];assert(fread(bytes,1,4,file)==4);uint32_t size=0;
    for(unsigned i=0;i<4;++i)size|=(uint32_t)bytes[i]<<(8*i);
    return size;
}
static void udpReplayMedia(int socket,const struct sockaddr_in *address,uint8_t local,const char *filename,bool crc) {
    if(filename) {assert(!udpReplayFile);udpReplayFile=fopen(filename,"rb");assert(udpReplayFile);}
    FILE *file=udpReplayFile;assert(file);
    uint8_t length[4];unsigned count=0;
    while(fread(length,1,4,file)==4) {
        uint32_t size=0;for(unsigned i=0;i<4;++i)size|=(uint32_t)length[i]<<(8*i);
        if(!size) {
            assert(count);
            if(udpGapMode)return; /* Pixel/real-feedback fixture barrier. */
            assert(!udpExpectedFeedbackSize);
            udpExpectedFeedbackSize=udpReplaySize(file);assert(udpExpectedFeedbackSize>=13 && udpExpectedFeedbackSize<=sizeof(udpExpectedFeedback));
            assert(fread(udpExpectedFeedback,1,udpExpectedFeedbackSize,file)==udpExpectedFeedbackSize);
            return; /* Controlled peer waits for actual matching feedback. */
        }
        uint8_t wire[2048];assert(size>=13 && size<=sizeof(wire));assert(fread(wire,1,size,file)==size);
        assert(wire[4]==3 && ((wire[0]&128)!=0)==crc);wire[3]=local;
        if(crc) {uint32_t value=IHS_CRC32C(wire,size-4);for(unsigned i=0;i<4;++i)wire[size-4+i]=(uint8_t)(value>>(8*i));}
        assert(sendto(socket,wire,size,0,(const struct sockaddr *)address,sizeof(*address))==(ssize_t)size);++count;
    }
    assert(feof(file) && !ferror(file) && count>=1);assert(!fclose(file));udpReplayFile=NULL;
}
