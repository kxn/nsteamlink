#include "resolution_pixels.h"
#include <assert.h>
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libavutil/md5.h>
#include <stdio.h>

typedef struct replay {
    sl_video_pipeline *pipeline;
    sl_gfx *gfx;
    IHS_FrameTracker *tracker;
    sl_video_key key;
    unsigned packets, outputs;
    char golden[4][33];
} replay;
static void take_frame(replay *r) {
    sl_video_frame *frame;
    while ((frame = sl_video_take(r->pipeline))) {
        assert(frame->pixels->width == 1920 && frame->pixels->height == 1080 &&
               frame->pixels->format == AV_PIX_FMT_YUV420P && r->outputs < 4);
        size_t bytes = 1920 * 1080 * 3 / 2;
        unsigned char *pixels = malloc(bytes), digest[16];
        assert(pixels);
        assert(av_image_copy_to_buffer(pixels, bytes, (const uint8_t *const *)frame->pixels->data,
                                       frame->pixels->linesize, AV_PIX_FMT_YUV420P, 1920, 1080,
                                       1) == (int)bytes);
        av_md5_sum(digest, pixels, bytes);
        free(pixels);
        char hash[33];
        for (unsigned i = 0; i < 16; ++i)
            snprintf(hash + 2 * i, 3, "%02x", digest[i]);
        assert(!strcmp(hash, r->golden[r->outputs]));
        assert(sl_gfx_begin(r->gfx) == SL_GFX_READY && sl_gfx_video(r->gfx, frame));
        assert(sl_gfx_present(r->gfx).result == SL_GFX_READY);
        assert(sl_gfx_poll_drain(r->gfx) == SL_GFX_READY);
        IHS_FrameOutcome outcome = {.result = IHS_VideoFrameResultDisplayed, .completionUs = 1};
        sl_video_frame_complete(frame, &outcome);
        sl_resource_release(&frame->ref);
        ++r->outputs;
    }
}
static void submit_packet(replay *r, const uint8_t *packet, int size) {
    IHS_FrameReceive receive = {.firstReceiveUs = 1, .lastReceiveUs = 1};
    IHS_FrameTicket *ticket = NULL;
    assert(IHS_FrameTrackerBegin(r->tracker, 1, ++r->packets, &receive, &ticket) ==
           IHS_FrameBeginOK);
    bool taken = false;
    sl_video_submit_result result =
        sl_video_submit(r->pipeline, r->key, packet, size, ticket, &taken, false, NULL, NULL, NULL);
    assert(result == SL_VIDEO_SUBMIT_OK && taken);
    IHS_FrameTicketRelease(ticket);
    take_frame(r);
}
static void decode_fixture(sl_gfx *gfx, const char *path, uint64_t session) {
    replay r = {.pipeline = sl_video_create(),
                .gfx = gfx,
                .tracker = IHS_FrameTrackerCreate(session),
                .key = {session, 1}};
    assert(r.pipeline && r.tracker && IHS_FrameTrackerOpenEpoch(r.tracker, 1));
    sl_video_config config = {.width = 1920, .height = 1080};
    assert(sl_video_open(r.pipeline, r.key, &config));
    char golden_path[1024], line[256];
    snprintf(golden_path, sizeof(golden_path), "%.*s.framemd5", (int)strlen(path) - 5, path);
    FILE *golden = fopen(golden_path, "r");
    assert(golden);
    unsigned count = 0;
    while (fgets(line, sizeof(line), golden)) {
        if (line[0] == '#')
            continue;
        char *hash = strrchr(line, ',');
        assert(hash && count < 4 && sscanf(hash + 1, " %32s", r.golden[count++]) == 1);
    }
    assert(count == 4 && !fclose(golden));
    FILE *file = fopen(path, "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long size = ftell(file);
    assert(size > 0 && !fseek(file, 0, SEEK_SET));
    uint8_t *data = calloc(1, size + AV_INPUT_BUFFER_PADDING_SIZE);
    assert(data && fread(data, 1, size, file) == (size_t)size && !fclose(file));
    AVCodecParserContext *parser = av_parser_init(AV_CODEC_ID_H264);
    AVCodecContext *context = avcodec_alloc_context3(NULL);
    assert(parser && context);
    for (int offset = 0; offset < size;) {
        uint8_t *packet;
        int bytes;
        int consumed = av_parser_parse2(parser, context, &packet, &bytes, data + offset,
                                        size - offset, AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);
        assert(consumed >= 0 && (consumed || bytes));
        offset += consumed;
        if (bytes)
            submit_packet(&r, packet, bytes);
    }
    uint8_t *packet;
    int bytes;
    assert(av_parser_parse2(parser, context, &packet, &bytes, NULL, 0, AV_NOPTS_VALUE,
                            AV_NOPTS_VALUE, 0) >= 0);
    if (bytes)
        submit_packet(&r, packet, bytes);
    assert(sl_video_flush(r.pipeline, r.key));
    take_frame(&r);
    assert(r.packets == 4 && r.outputs == 4);
    av_parser_close(parser);
    avcodec_free_context(&context);
    free(data);
    sl_video_stop(r.pipeline, r.key);
    sl_gfx_forget_video(gfx);
    sl_video_reap(r.pipeline);
    assert(sl_video_destroy(r.pipeline));
    IHS_FrameTrackerClose(r.tracker);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    assert(!SDL_Init(SDL_INIT_VIDEO));
    const unsigned heights[] = {720, 1080, 720};
    for (unsigned i = 0; i < 3; ++i) {
        sl_gfx *gfx = sl_gfx_create(&(sl_gfx_config){.width = 1280,
                                                     .height = 720,
                                                     .output_height = heights[i],
                                                     .title = "Resolution pixel test"});
        assert(gfx);
        decode_fixture(gfx, argv[1], i + 1);
        assert(resolution_pixels(gfx, heights[i]));
        sl_gfx_destroy(gfx);
    }
    SDL_Quit();
    puts("PASS H264 1080p decode matches framemd5, one-pixel native detail, 720p scaling, readback "
         "bounds and three lifecycles");
    return 0;
}
