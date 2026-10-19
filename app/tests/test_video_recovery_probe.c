#include "video_recovery_probe.h"
#include <assert.h>
#include <stdio.h>
#include <time.h>
static uint64_t clock_us(void *context) {
    (void)context;
    struct timespec t;
    assert(!clock_gettime(CLOCK_MONOTONIC, &t));
    return (uint64_t)t.tv_sec * 1000000 + (uint64_t)t.tv_nsec / 1000;
}
typedef struct test_context {
    int cancel_at;
    unsigned calls, reject_id;
} test_context;
static bool active(void *context) {
    test_context *test = context;
    return test->cancel_at < 0 || test->calls++ != (unsigned)test->cancel_at;
}
static bool picture(void *context, sl_video_selection *selection, IHS_FrameOutcome *outcome) {
    test_context *test = context;
    if (IHS_FrameTicketIdentity(selection->frame->ticket).frameId == test->reject_id)
        return false;
    bool verified = recovery_reference_pixels(selection->frame);
    outcome->result = IHS_VideoFrameResultDroppedReset; /* Headless observation. */
    outcome->completionUs = clock_us(NULL);
    return verified;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    unsigned char fixture[97067];
    FILE *file = fopen(argv[1], "rb");
    assert(file && fread(fixture, 1, sizeof(fixture), file) == sizeof(fixture) &&
           fgetc(file) == EOF);
    assert(!fclose(file));
    sl_video_pipeline *pipeline = sl_video_create();
    assert(pipeline);
    test_context context = {.cancel_at = -1};
    recovery_callbacks cb = {
        .now = clock_us, .picture = picture, .running = active, .context = &context};
    for (unsigned n = 0; n < 4; ++n) {
        recovery_result result;
        bool ok = recovery_run(pipeline, (sl_video_key){n + 1, 1}, fixture, sizeof(fixture), false,
                               n & 1, &cb, &result);
        if (!ok)
            fprintf(stderr, "recovery failure: %s inputs=%u tasks=%u pictures=%u\n", result.failure,
                    result.inputs, result.tasks, result.pictures);
        assert(ok && result.inputs == RECOVERY_INPUTS && result.tasks == RECOVERY_INPUTS);
        assert(result.pictures == RECOVERY_INPUTS && result.stopped);
        for (unsigned i = 0; i < RECOVERY_INPUTS; ++i)
            assert(result.rows[i].task_id == recovery_ids[i]);
        sl_video_reap(pipeline);
    }
    for (unsigned n = 0; n < 2; ++n) {
        context = (test_context){.cancel_at = n ? -1 : 2, .reject_id = n ? 106 : 0};
        recovery_result result;
        assert(!recovery_run(pipeline, (sl_video_key){5 + n, 1}, fixture, sizeof(fixture), false,
                             n != 0, &cb, &result));
        assert(result.stopped && result.inputs == 2 && result.tasks == 2);
        assert(!strcmp(result.failure, n ? "pixels" : "interrupted"));
        sl_video_reap(pipeline);
    }
    if (av_hwdevice_find_type_by_name("nvtegra") == AV_HWDEVICE_TYPE_NONE) {
        context = (test_context){.cancel_at = -1};
        recovery_result result;
        assert(!recovery_run(pipeline, (sl_video_key){7, 1}, fixture, sizeof(fixture), true, false,
                             &cb, &result));
        assert(!result.hardware_context && result.stopped &&
               !strcmp(result.failure, "hardware-context"));
        sl_video_reap(pipeline);
    }
    assert(sl_video_destroy(pipeline));
    puts("Decoder recovery fixture: 4 software runs, real selection/bytes/pixels/stop, hardware "
         "untested");
    return 0;
}
