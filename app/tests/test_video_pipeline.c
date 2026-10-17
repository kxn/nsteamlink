#include "session/frame_tracker.h"
#include "video_pipeline.h"
#include <assert.h>
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libavutil/md5.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
static pthread_mutex_t open_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t open_cond = PTHREAD_COND_INITIALIZER;
static bool block_open, entered_open, release_open;
static int send_failure;
static int open_failure;
static bool flag_missing_reference;
int __real_avcodec_receive_frame(AVCodecContext *, AVFrame *);
int __wrap_avcodec_receive_frame(AVCodecContext *c, AVFrame *frame) {
    int result = __real_avcodec_receive_frame(c, frame);
    if (!result && flag_missing_reference) {
        frame->decode_error_flags |= FF_DECODE_ERROR_MISSING_REFERENCE;
        flag_missing_reference = false;
    }
    return result;
}
int __real_avcodec_send_packet(AVCodecContext *, const AVPacket *);
int __wrap_avcodec_send_packet(AVCodecContext *c, const AVPacket *packet) {
    if (send_failure) {
        int error = send_failure;
        send_failure = 0;
        return error;
    }
    return __real_avcodec_send_packet(c, packet);
}

int __real_avcodec_open2(AVCodecContext *, const AVCodec *, AVDictionary **);
int __wrap_avcodec_open2(AVCodecContext *c, const AVCodec *codec, AVDictionary **options) {
    if (open_failure) {
        int error = open_failure;
        open_failure = 0;
        return error;
    }
    pthread_mutex_lock(&open_lock);
    if (block_open) {
        entered_open = true;
        pthread_cond_signal(&open_cond);
        while (!release_open)
            pthread_cond_wait(&open_cond, &open_lock);
    }
    pthread_mutex_unlock(&open_lock);
    return __real_avcodec_open2(c, codec, options);
}
static void *opening(void *p) {
    sl_video_config config = {.width = 128, .height = 72};
    assert(!sl_video_open(p, (sl_video_key){5, 1}, &config));
    return NULL;
}
static void close_during_open(sl_video_pipeline *p) {
    block_open = true;
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, opening, p));
    pthread_mutex_lock(&open_lock);
    while (!entered_open)
        pthread_cond_wait(&open_cond, &open_lock);
    sl_video_freeze(p); /* must not wait for the FFmpeg decoder lock */
    release_open = true;
    pthread_cond_signal(&open_cond);
    pthread_mutex_unlock(&open_lock);
    pthread_join(thread, NULL);
    block_open = false;
    assert(!sl_video_is_current(p, (sl_video_key){5, 1}));
    sl_video_reap(p);
    assert(sl_video_clean(p));
}
static void opening_results(void) {
    sl_video_pipeline *p = sl_video_create();
    sl_video_config config = {.width = 128, .height = 72};
    assert(p);
    assert(sl_video_open_ex(p, (sl_video_key){1, 0}, &config) == SL_VIDEO_OPEN_GUARD);
    open_failure = AVERROR(EIO);
    assert(sl_video_open_ex(p, (sl_video_key){1, 1}, &config) == SL_VIDEO_OPEN_UNAVAILABLE);
    assert(sl_video_clean(p));
    open_failure = AVERROR(ENOMEM);
    assert(sl_video_open_ex(p, (sl_video_key){1, 2}, &config) == SL_VIDEO_OPEN_GUARD);
    assert(sl_video_clean(p));
    assert(sl_video_open_ex(p, (sl_video_key){1, 3}, &config) == SL_VIDEO_OPEN_READY);
    sl_video_stop(p, (sl_video_key){1, 3});
    sl_video_reap(p);
    assert(sl_video_destroy(p));
}
#endif
typedef struct run {
    sl_video_pipeline *pipeline;
    IHS_FrameTracker *tracker;
    sl_video_key key;
    unsigned packets, outputs, reordered, logical_tasks;
    bool use_selection;
    sl_video_frame *held;
    char golden[16][33];
    unsigned golden_count, golden_cursor;
} run;
static void take(run *r) {
    sl_video_selection selected={0};
    sl_video_frame *frame;
    if(r->use_selection) {
        assert(sl_video_select(r->pipeline,&selected));
        assert(IHS_FrameTicketIdentity(selected.ticket).frameId==r->packets);
        ++r->logical_tasks;frame=selected.frame;
        if(!frame) {
            IHS_TrackedFrame stats[IHS_FRAME_TRACKER_CAPACITY];
            size_t n=IHS_FrameTrackerCopyStats(r->tracker,stats,IHS_FRAME_TRACKER_CAPACITY);
            bool found=false;
            for(size_t j=0;j<n;++j) if(stats[j].identity.frameId==r->packets) {
                assert(stats[j].statsComplete && stats[j].outcome.result==IHS_VideoFrameResultDroppedReset);
                found=true;
            }
            assert(found);sl_video_selection_release(&selected);return;
        }
    } else frame=sl_video_take(r->pipeline);
    if(!frame)return;
    sl_publication_snapshot history;
    assert(sl_video_publications(r->pipeline,(sl_video_key){0},0,&history));
    assert(history.key.session==r->key.session && history.pending==0);
    assert(frame->publish_seq && frame->publish_seq<=history.latest);
    bool found=false;
    for(unsigned i=0;i<history.count;++i) {
        assert(history.items[i].seq==i+1);
        if(history.items[i].seq==frame->publish_seq) {
            assert(history.items[i].us>=frame->decode_end_us); found=true;
        }
    }
    assert(found);
    IHS_FrameIdentity identity = IHS_FrameTicketIdentity(frame->ticket);
    assert(frame->pixels->pts == AV_NOPTS_VALUE);
    assert(frame->has_media_timestamp && frame->media_timestamp == 0x100000u + identity.frameId * 777u);
    assert(frame->pixels->width == 128 && frame->pixels->height == 72);
    assert(frame->pixels->format == AV_PIX_FMT_YUV420P);
    assert(frame->decode_end_us >= frame->decode_begin_us);
    unsigned char pixels[128 * 72 * 3 / 2], digest[16];
    assert(av_image_copy_to_buffer(
               pixels, sizeof(pixels), (const uint8_t *const *)frame->pixels->data,
               frame->pixels->linesize, AV_PIX_FMT_YUV420P, 128, 72, 1) == sizeof(pixels));
    av_md5_sum(digest, pixels, sizeof(pixels));
    char hash[33];
    for (unsigned i = 0; i < 16; ++i)
        snprintf(hash + i * 2, 3, "%02x", digest[i]);
    while (r->golden_cursor < r->golden_count && strcmp(hash, r->golden[r->golden_cursor]))
        ++r->golden_cursor;
    assert(r->golden_cursor < r->golden_count); /* ordered visible pixels, excluding padding */
    ++r->golden_cursor;
    r->reordered += identity.frameId != r->packets;
    ++r->outputs;
    IHS_FrameOutcome result = {.result = IHS_VideoFrameResultDisplayed,
                               .completionUs = frame->decode_end_us,
                               .presentationSerial = r->outputs};
    if(r->use_selection) {
        sl_video_selection_complete(&selected,&result);
        IHS_TrackedFrame current[IHS_FRAME_TRACKER_CAPACITY];
        size_t count=IHS_FrameTrackerCopyStats(r->tracker,current,IHS_FRAME_TRACKER_CAPACITY);
        bool done=false;
        for(size_t j=0;j<count;++j) if(current[j].identity.frameId==r->packets) {
            assert(current[j].statsComplete && current[j].outcome.result==IHS_VideoFrameResultDisplayed);
            done=true;
        }
        assert(done); /* current task, even when physical pixels belong to an older input */
        selected.frame=NULL; /* transfer actual pixel reference to held */
        sl_video_selection_release(&selected);
    } else sl_video_frame_complete(frame,&result);
    if (r->held)
        sl_resource_release(&r->held->ref);
    r->held = frame; /* old displayed frame remains pinned until replaced */
}
static void submit(run *r, const unsigned char *data, size_t size) {
    IHS_FrameReceive received = {.firstReceiveUs = 1, .lastReceiveUs = 1};
    IHS_FrameTicket *ticket;
    assert(IHS_FrameTrackerBegin(r->tracker, r->key.epoch, ++r->packets, &received, &ticket) ==
           IHS_FrameBeginOK);
    IHS_FrameTicketSetVideoTimestamp(ticket, 0x100000u + r->packets * 777u);
    bool taken = false;
    sl_video_submit_result submitted=sl_video_submit(r->pipeline,r->key,data,size,ticket,&taken,false,NULL,NULL);
    assert(submitted!=SL_VIDEO_SUBMIT_ERROR && !(submitted&SL_VIDEO_SUBMIT_RESET) && taken);
    /* Outputs may be reordered and published after a later packet. The
     * presentation stamp belongs to the packet token, never a mutable ticket. */
    IHS_FrameTicketSetVideoTimestamp(ticket, 0xdeadbeefu);
    IHS_FrameTicketRelease(ticket);
    take(r);
}
static void fixture(run *r, const char *path) {
    char golden_path[1024];
    snprintf(golden_path, sizeof(golden_path), "%.*s.framemd5", (int)strlen(path) - 5, path);
    FILE *golden = fopen(golden_path, "r");
    assert(golden);
    char line[256];
    while (fgets(line, sizeof(line), golden)) {
        if (line[0] == '#')
            continue;
        char *hash = strrchr(line, ',');
        assert(hash && r->golden_count < 16);
        assert(sscanf(hash + 1, "%32s", r->golden[r->golden_count++]) == 1);
    }
    fclose(golden);
    FILE *f = fopen(path, "rb");
    assert(f);
    assert(fseek(f, 0, SEEK_END) == 0);
    long size = ftell(f);
    assert(size > 0 && size < 1024 * 1024);
    rewind(f);
    unsigned char *data = calloc(1, size + AV_INPUT_BUFFER_PADDING_SIZE);
    assert(data && fread(data, 1, size, f) == (size_t)size);
    fclose(f);
    AVCodecParserContext *parser = av_parser_init(AV_CODEC_ID_H264);
    AVCodecContext *context = avcodec_alloc_context3(NULL);
    assert(parser && context);
    long offset = 0;
    while (offset < size) {
        uint8_t *packet;
        int bytes;
        int consumed = av_parser_parse2(parser, context, &packet, &bytes, data + offset,
                                        size - offset, AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);
        assert(consumed >= 0 && (consumed || bytes));
        offset += consumed;
        if (bytes)
            submit(r, packet, bytes);
    }
    uint8_t *packet;
    int bytes;
    assert(av_parser_parse2(parser, context, &packet, &bytes, NULL, 0, AV_NOPTS_VALUE,
                            AV_NOPTS_VALUE, 0) >= 0);
    if (bytes)
        submit(r, packet, bytes);
    assert(r->packets == 12);
    assert(sl_video_flush(r->pipeline,r->key));
    bool selecting=r->use_selection;r->use_selection=false;
    take(r); /* explicit probe-only drain: no invented application task */
    r->use_selection=selecting;
    if(selecting) assert(r->logical_tasks==r->packets);
    assert(r->outputs >= 10 && r->outputs <= 12);
    av_parser_close(parser);
    avcodec_free_context(&context);
    free(data);
}
static void corruption_and_recovery(sl_video_pipeline *pipeline, const char *path) {
    sl_video_config config = {.width = 128, .height = 72};
    run r = {.pipeline = pipeline, .tracker = IHS_FrameTrackerCreate(6), .key = {6, 1}};
    assert(IHS_FrameTrackerOpenEpoch(r.tracker, 1));
    assert(sl_video_open(pipeline, r.key, &config));
    FILE *f = fopen(path, "rb");
    assert(f && !fseek(f, 0, SEEK_END));
    long size = ftell(f);
    rewind(f);
    uint8_t *input = calloc(1, size + AV_INPUT_BUFFER_PADDING_SIZE);
    assert(input && fread(input, 1, size, f) == (size_t)size);
    fclose(f);
    AVCodecParserContext *parser = av_parser_init(AV_CODEC_ID_H264);
    AVCodecContext *context = avcodec_alloc_context3(NULL);
    uint8_t *first;
    int bytes;
    assert(av_parser_parse2(parser, context, &first, &bytes, input, size, AV_NOPTS_VALUE,
                            AV_NOPTS_VALUE, 0) > 0 &&
           bytes > 0);
    // Compare recovered visible pixels to the first clean decoded output.
    IHS_FrameReceive received = {.firstReceiveUs = 1, .lastReceiveUs = 1};
    IHS_FrameTicket *ticket;
    bool taken;
    assert(IHS_FrameTrackerBegin(r.tracker, 1, 1, &received, &ticket) == IHS_FrameBeginOK);
    assert(sl_video_submit(pipeline, r.key, first, bytes, ticket, &taken, true, NULL, NULL) ==
               SL_VIDEO_SUBMIT_OK &&
           taken);
    IHS_FrameTicketRelease(ticket);
    sl_video_frame *held = sl_video_take(pipeline);
    assert(held);
    uint8_t before[128 * 72 * 3 / 2], after[sizeof(before)];
    assert(av_image_copy_to_buffer(
               before, sizeof(before), (const uint8_t *const *)held->pixels->data,
               held->pixels->linesize, AV_PIX_FMT_YUV420P, 128, 72, 1) == sizeof(before));
    const uint8_t broken[] = {0, 0, 0, 1, 0x65, 0x80}; // truncated IDR slice
    assert(IHS_FrameTrackerBegin(r.tracker, 1, 2, &received, &ticket) == IHS_FrameBeginOK);
    sl_video_submit_result bad=sl_video_submit(pipeline,r.key,broken,sizeof(broken),ticket,&taken,false,NULL,NULL);
    assert((bad&SL_VIDEO_SUBMIT_CORRUPT) && taken);
    IHS_FrameTicketRelease(ticket);
    assert(!sl_video_take(pipeline)); // damaged output never replaces displayed frame
    assert(IHS_FrameTrackerBegin(r.tracker, 1, 3, &received, &ticket) == IHS_FrameBeginOK);
    assert(sl_video_submit(pipeline, r.key, first, bytes, ticket, &taken, true, NULL, NULL) ==
               SL_VIDEO_SUBMIT_OK &&
           taken);
    IHS_FrameTicketRelease(ticket);
    sl_video_frame *recovered = sl_video_take(pipeline);
    assert(recovered);
    assert(av_image_copy_to_buffer(
               after, sizeof(after), (const uint8_t *const *)recovered->pixels->data,
               recovered->pixels->linesize, AV_PIX_FMT_YUV420P, 128, 72, 1) == sizeof(after));
    assert(!memcmp(before, after, sizeof(before)));
    // Backend flush must preserve caller/GPU-held output buffers.
    assert(av_image_copy_to_buffer(after, sizeof(after), (const uint8_t *const *)held->pixels->data,
                                   held->pixels->linesize, AV_PIX_FMT_YUV420P, 128, 72,
                                   1) == sizeof(after));
    assert(!memcmp(before, after, sizeof(before)));
#if defined(__linux__)
    // Official AVCodec uses successful dimensions/format, not reference flags.
    // This controlled marker changes no actual pixels; prove both publication
    // and real image bytes rather than retaining the superseded veto.
    assert(IHS_FrameTrackerBegin(r.tracker, 1, 4, &received, &ticket) == IHS_FrameBeginOK);
    flag_missing_reference = true;
    assert(sl_video_submit(pipeline, r.key, first, bytes, ticket, &taken, true, NULL, NULL) ==
               SL_VIDEO_SUBMIT_OK && taken);
    IHS_FrameTicketRelease(ticket);
    sl_video_frame *flagged=sl_video_take(pipeline);assert(flagged && !flag_missing_reference);
    assert(av_image_copy_to_buffer(after,sizeof(after),(const uint8_t *const *)flagged->pixels->data,
               flagged->pixels->linesize,AV_PIX_FMT_YUV420P,128,72,1)==sizeof(after));
    assert(!memcmp(before,after,sizeof(before)));sl_resource_release(&flagged->ref);
    // SDK send failure requests reset and still receives once; it is distinct
    // from the port's local allocation/identity guard.
    assert(IHS_FrameTrackerBegin(r.tracker, 1, 5, &received, &ticket) == IHS_FrameBeginOK);
    send_failure = AVERROR(ENOMEM);
    assert(sl_video_submit(pipeline, r.key, first, bytes, ticket, &taken, false, NULL, NULL) ==
               (SL_VIDEO_SUBMIT_RESET | SL_VIDEO_SUBMIT_CORRUPT) && taken);
    taken = true;
    assert(sl_video_submit(pipeline, (sl_video_key){7, 1}, first, bytes, ticket, &taken, false, NULL, NULL) ==
               SL_VIDEO_SUBMIT_ERROR &&
           !taken);
    IHS_FrameTicketRelease(ticket);
#endif
    sl_resource_release(&held->ref);
    sl_resource_release(&recovered->ref);
    sl_video_stop(pipeline, r.key);
    sl_video_reap(pipeline);
    IHS_FrameTrackerClose(r.tracker);
    av_parser_close(parser);
    avcodec_free_context(&context);
    free(input);
}

int main(int argc, char **argv) {
    assert(argc == 3);
#if defined(__linux__)
    opening_results();
#endif
    sl_video_config config = {.width = 128, .height = 72};
    sl_video_pipeline *pipeline = sl_video_create();
    assert(pipeline);
    run a = {.pipeline = pipeline, .tracker = IHS_FrameTrackerCreate(1), .key = {1, 1}, .use_selection=true};
    assert(IHS_FrameTrackerOpenEpoch(a.tracker, 1));
    sl_video_freeze(pipeline);
    assert(!sl_video_open(pipeline, a.key, &config)); /* stop before begin */
    sl_video_thaw(pipeline);
    assert(sl_video_open(pipeline, a.key, &config));
    fixture(&a, argv[1]);
    assert(a.reordered);
    sl_video_stop(pipeline, a.key);
    sl_video_reap(pipeline);
    assert(!sl_video_clean(pipeline)); /* held output keeps its codec domain alive */
    IHS_FrameTrackerClose(a.tracker);  /* displayed lease survives endpoint close */
    run b = {.pipeline = pipeline, .tracker = IHS_FrameTrackerCreate(2), .key = {2, 1}, .use_selection=true};
    assert(IHS_FrameTrackerOpenEpoch(b.tracker, 1));
    assert(sl_video_open(pipeline, b.key, &config));
    fixture(&b, argv[2]);
    assert(b.outputs == 12 && b.reordered == 0);
    sl_video_stop(pipeline, b.key);
    assert(sl_video_open_ex(pipeline, (sl_video_key){3, 1}, &config) ==
           SL_VIDEO_OPEN_UNAVAILABLE); /* two pinned domains */
    sl_resource_release(&a.held->ref);
    sl_video_reap(pipeline);
    assert(sl_video_open(pipeline, (sl_video_key){4, 1}, &config));
    assert(sl_video_flush(pipeline, (sl_video_key){4, 1})); /* flush before first frame */
    sl_video_stop(pipeline, (sl_video_key){4, 1});
    IHS_FrameTrackerClose(b.tracker);
    assert(!sl_video_destroy(pipeline));
    sl_resource_release(&b.held->ref);
    sl_video_reap(pipeline);
    assert(sl_video_clean(pipeline));
#if defined(__linux__)
    close_during_open(pipeline);
#endif
    sl_video_thaw(pipeline);
    corruption_and_recovery(pipeline, argv[2]);
    assert(sl_video_destroy(pipeline));
    return 0;
}
