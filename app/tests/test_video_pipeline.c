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
int __real_avcodec_open2(AVCodecContext *, const AVCodec *, AVDictionary **);
int __wrap_avcodec_open2(AVCodecContext *c, const AVCodec *codec, AVDictionary **options) {
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
#endif
typedef struct run {
    sl_video_pipeline *pipeline;
    IHS_FrameTracker *tracker;
    sl_video_key key;
    unsigned packets, outputs, reordered;
    sl_video_frame *held;
    char golden[16][33];
    unsigned golden_count, golden_cursor;
} run;
static void take(run *r) {
    sl_video_frame *frame = sl_video_take(r->pipeline);
    if (!frame)
        return;
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
    assert(frame->pixels->pts == (int64_t)identity.receiveSerial);
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
    sl_video_frame_complete(frame, &result);
    if (r->held)
        sl_resource_release(&r->held->ref);
    r->held = frame; /* old displayed frame remains pinned until replaced */
}
static void submit(run *r, const unsigned char *data, size_t size) {
    IHS_FrameReceive received = {.firstReceiveUs = 1, .lastReceiveUs = 1};
    IHS_FrameTicket *ticket;
    assert(IHS_FrameTrackerBegin(r->tracker, r->key.epoch, ++r->packets, &received, &ticket) ==
           IHS_FrameBeginOK);
    bool taken = false;
    assert(sl_video_submit(r->pipeline, r->key, data, size, ticket, &taken) && taken);
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
    assert(sl_video_flush(r->pipeline, r->key));
    take(r);
    assert(r->outputs >= 10 && r->outputs <= 12);
    av_parser_close(parser);
    avcodec_free_context(&context);
    free(data);
}
int main(int argc, char **argv) {
    assert(argc == 3);
    sl_video_config config = {.width = 128, .height = 72};
    sl_video_pipeline *pipeline = sl_video_create();
    assert(pipeline);
    run a = {.pipeline = pipeline, .tracker = IHS_FrameTrackerCreate(1), .key = {1, 1}};
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
    run b = {.pipeline = pipeline, .tracker = IHS_FrameTrackerCreate(2), .key = {2, 1}};
    assert(IHS_FrameTrackerOpenEpoch(b.tracker, 1));
    assert(sl_video_open(pipeline, b.key, &config));
    fixture(&b, argv[2]);
    assert(b.outputs == 12 && b.reordered == 0);
    sl_video_stop(pipeline, b.key);
    assert(!sl_video_open(pipeline, (sl_video_key){3, 1}, &config)); /* two pinned domains */
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
    assert(sl_video_destroy(pipeline));
    return 0;
}
