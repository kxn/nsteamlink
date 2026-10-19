/* Observation state transitions only. Times, headers and TLS input are explicit
 * adapters; this is not a Steam peer, producer, network or decoder execution. */
#include "live_media_gap_observer.h"
#include <assert.h>
#include <string.h>

static uint8_t body[20];
static uint64_t header(unsigned channel, uint16_t id, uint16_t seq, uint8_t flags) {
    memset(body, 0, sizeof(body));
    body[0] = k_EStreamDataPacket;
    body[1] = id;
    body[2] = id >> 8;
    body[13] = seq;
    body[14] = seq >> 8;
    body[15] = flags;
    return probe_gap_header(channel, body, sizeof(body));
}
int main(void) {
    uint64_t loss = header(4, 100, 10, VideoFrameFlagFrameFinish);
    probe_gap_scope scope = {.input = header(4, 101, 11, VideoFrameFlagFrameFinish)};
    probe_gap_loss(loss, 1000);
    probe_gap_current = &scope;
    probe_gap_request(4, 1001);
    assert(atomic_load(&probe_gap.calls) == 1 && atomic_load(&probe_gap.producer) == scope.input);
    header(4, 102, 12, VideoFrameFlagKeyFrame | VideoFrameFlagFrameFinish);
    probe_gap_key(4, body, sizeof(body), 1002); /* no successful socket send */
    assert(!atomic_load(&probe_gap.key));
    probe_gap_socket(true, 1003);
    probe_gap_key(4, body, sizeof(body), 1004);
    assert(atomic_load(&probe_gap.key) && atomic_load(&probe_gap.key_ms) == 1004);
    assert(!probe_gap_submit(101, IHS_StreamVideoFrameKeyFrame, IHS_StreamVideoSubmitOK, 1005));
    assert(!probe_gap_submit(102, 0, IHS_StreamVideoSubmitOK, 1005));
    assert(!probe_gap_submit(102, IHS_StreamVideoFrameKeyFrame, IHS_StreamVideoSubmitError, 1005));
    assert(probe_gap_submit(102, IHS_StreamVideoFrameKeyFrame, IHS_StreamVideoSubmitOK, 1006));
    assert(atomic_load(&probe_gap.submitted) && atomic_load(&probe_gap.submit_ms) == 1006);
    assert(!atomic_load(&probe_gap.unscoped) && !atomic_load(&probe_gap.failed));
    probe_gap_current = NULL;
    probe_gap_request(4, 1007);
    assert(atomic_load(&probe_gap.unscoped) == 1);
    probe_gap_current = &scope;
    scope.input = header(3, 101, 11, VideoFrameFlagFrameFinish);
    probe_gap_request(4, 1008);
    assert(atomic_load(&probe_gap.unscoped) == 2);
    scope.input = loss;
    probe_gap_request(4, 1009);
    assert(atomic_load(&probe_gap.unscoped) == 3 && atomic_load(&probe_gap.calls) == 1);
    assert(!probe_gap_submit(100, 0, IHS_StreamVideoSubmitOK, 1010));
    assert(atomic_load(&probe_gap.lost_submits) == 1);
    probe_gap_socket(false, 1011);
    assert(atomic_load(&probe_gap.failed) == 1);
    probe_gap = (probe_gap_observer){0};
    loss = header(4, UINT16_MAX, UINT16_MAX, VideoFrameFlagFrameFinish);
    probe_gap_loss(loss, 2000);
    scope.input = header(4, 0, 0, VideoFrameFlagFrameFinish);
    probe_gap_request(4, 2001);
    assert(atomic_load(&probe_gap.calls) == 1); /* modular wrap */
    probe_gap_socket(true, 2002);
    header(4, 1, 1, VideoFrameFlagKeyFrame | VideoFrameFlagFrameFinish);
    body[16] = 1;
    probe_gap_key(4, body, sizeof(body), 2003);
    assert(!atomic_load(&probe_gap.key));
    body[16] = 0;
    probe_gap_key(3, body, sizeof(body), 2003);
    probe_gap_key(4, body, 19, 2003);
    assert(!atomic_load(&probe_gap.key));
    probe_gap_key(4, body, sizeof(body), 2003);
    assert(atomic_load(&probe_gap.key));
    probe_gap_current = NULL;
    return 0;
}
