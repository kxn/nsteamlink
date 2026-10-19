/* Original Android byte fixture -> actual PacketParse/probe wrapper/FEC/RS.
 * Only group IDs / diagnostic scheduling are adapters; no local FEC encoder.
 * Check loss-witness negative cases, not Steam/decoder/device behavior. */
#define main live_media_probe_main
#include "live_media_probe.c"
#undef main
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static uint8_t wires[5][128], payload[128];
static size_t wire_bytes[5], payload_bytes;

static size_t unhex(const char *hex, uint8_t *out, size_t capacity) {
    size_t size = strlen(hex);
    assert(!(size & 1) && size / 2 <= capacity);
    for (size_t i = 0; i < size / 2; ++i) {
        unsigned b;
        assert(sscanf(hex + 2 * i, "%2x", &b) == 1);
        out[i] = b;
    }
    return size / 2;
}
static bool input(probe_fec_loss *s, IHS_FECReceiver *r, unsigned index, uint16_t group,
                  bool context, unsigned video, uint64_t submitted, bool correct) {
    uint8_t *copy = malloc(wire_bytes[index]);
    assert(copy);
    memcpy(copy, wires[index], wire_bytes[index]);
    IHS_Buffer raw = IHS_BUFFER_WRAP(copy, wire_bytes[index]);
    IHS_SessionPacket p;
    assert(IHS_SessionPacketParse(&p, &raw) == IHS_SessionPacketResultOK);
    p.header.packetId = group;
    IHS_SessionFrame f = {0};
    assert(s == &probe_loss);
    ordinary_rx = context; /* Explicit adapter for the actual RX wrapper scope. */
    atomic_store(&video_channel, video);
    atomic_store(&submit_returns, submitted);
    bool ready = __wrap_IHS_FECReceiverAdd(r, &p, &f);
    if (ready && correct)
        assert(f.body.size == payload_bytes &&
               !memcmp(IHS_BufferPointer(&f.body), payload, payload_bytes));
    IHS_SessionFrameClear(&f, true);
    IHS_SessionPacketClear(&p, true);
    IHS_BufferClear(&raw, true);
    return ready;
}
static IHS_FECReceiver *begin(probe_fec_loss *s, uint16_t group) {
    IHS_FECReceiver *r = IHS_FECReceiverCreate();
    assert(r);
    /* Seed the observed watermark, before warmup/video identity. */
    assert(!input(s, r, 0, group, true, 32, 0, true));
    assert(!s->selected);
    return r;
}
static void repair(probe_fec_loss *s, IHS_FECReceiver *r, uint16_t group, bool correct) {
    assert(!input(s, r, 0, group, true, 3, 120, correct));
    assert(s->selected && s->blocked);
    assert(!input(s, r, 1, group, true, 3, 120, correct));
    assert(!input(s, r, 2, group, true, 3, 120, correct));
    assert(input(s, r, 3, group, true, 3, 120, correct));
}
int main(int argc, char **argv) {
    assert(argc == 7);
    payload_bytes = unhex(argv[1], payload, sizeof(payload));
    for (unsigned i = 0; i < 5; ++i)
        wire_bytes[i] = unhex(argv[i + 2], wires[i], sizeof(wires[i]));
    /* Every survivor order, including parity first; duplicates cannot fill a
     * missing column or sneak the withheld original into the receiver. */
    for (unsigned a = 1; a <= 3; ++a)
        for (unsigned b = 1; b <= 3; ++b)
            for (unsigned c = 1; c <= 3; ++c) {
                if (a == b || a == c || b == c)
                    continue;
                probe_loss = (probe_fec_loss){.enabled = true};
                probe_fec_loss *s = &probe_loss;
                IHS_FECReceiver *r = begin(s, 0);
                assert(!input(s, r, 0, 1, true, 3, 120, true));
                assert(!input(s, r, 0, 1, true, 3, 120, true));
                assert(!input(s, r, a, 1, true, 3, 120, true));
                assert(!input(s, r, a, 1, true, 3, 120, true));
                assert(!input(s, r, b, 1, true, 3, 120, true));
                assert(input(s, r, c, 1, true, 3, 120, true));
                assert(s->completed && s->matched && atomic_load(&s->witnessed));
                assert(s->blocked == 2 && s->unique_data == 2 && s->unique_parity == 1);
                assert(!s->forwarded[0] && !s->conflict && !s->replaced);
                assert(!input(s, r, 0, 1, true, 3, 120, true));
                assert(s->blocked == 3); /* still withheld after completion */
                assert(!input(s, r, 0, 2, true, 3, 120, true));
                assert(!input(s, r, 1, 2, true, 3, 120, true));
                assert(input(s, r, 2, 2, true, 3, 120, true));
                assert(s->group == 1 && s->blocked == 3); /* one group only */
                IHS_FECReceiverDestroy(r);
            }
    /* Explicit no-injection boundaries, including first group and an index0
     * that had already been forwarded before eligibility changed. */
    for (unsigned mode = 0; mode < 7; ++mode) {
        probe_loss = (probe_fec_loss){.enabled = mode != 0};
        probe_fec_loss *s = &probe_loss;
        IHS_FECReceiver *r = IHS_FECReceiverCreate();
        assert(r);
        if (mode != 4)
            assert(!input(s, r, 0, 0, true, 32, 0, true));
        bool context = mode != 1;
        unsigned video = mode == 2 ? 4 : 3;
        uint64_t submitted = mode == 3 ? 119 : 120;
        if (mode == 5) /* same group: index0 already forwarded while cold */
            assert(!input(s, r, 0, 1, true, 32, 0, true));
        if (mode == 6) /* index1 arrived first: do not erase a later index0 */
            assert(!input(s, r, 1, 1, true, 3, 120, true));
        (void)input(s, r, 0, 1, context, video, submitted, true);
        assert(!s->selected && !atomic_load(&s->witnessed));
        IHS_FECReceiverDestroy(r);
    }
    /* Wire metadata outside erasure eligibility must not select an erasure:
     * m=0, k=1, malformed short body, invalid index and width beyond storage. */
    for (unsigned mode = 0; mode < 5; ++mode) {
        probe_loss = (probe_fec_loss){.enabled = true};
        probe_fec_loss *s = &probe_loss;
        IHS_FECReceiver *r = begin(s, 0);
        uint8_t body[PROBE_ERASURE_BYTES + 10] = {80, 0, 0, 0, 32, 0, 2, 0};
        size_t size = 40;
        if (mode == 0)
            body[6] = 0;
        if (mode == 1)
            body[0] = 20;
        if (mode == 2)
            size = 8;
        if (mode == 4) {
            unsigned width = PROBE_ERASURE_BYTES + 1;
            body[0] = 0xff;
            body[1] = 0x0a; /* k=2 */
            body[4] = width;
            body[5] = width >> 8;
            size = width + 8;
        }
        IHS_SessionPacket p = {.header = {.type = IHS_SessionPacketTypeUnreliableFEC,
                                          .channelId = 3,
                                          .packetId = 1,
                                          .fragmentId = mode == 3 ? 255 : 0},
                               .body = IHS_BUFFER_WRAP(body, size)};
        assert(!probe_fec_loss_before(s, r, &p, true, 3, 120));
        assert(!s->selected);
        IHS_FECReceiverDestroy(r);
    }
    /* A completed output isn't enough: parity corruption and changed saved
     * expectation must both be rejected by the exact-byte witness. */
    for (unsigned mode = 0; mode < 2; ++mode) {
        probe_loss = (probe_fec_loss){.enabled = true};
        probe_fec_loss *s = &probe_loss;
        IHS_FECReceiver *r = begin(s, 0);
        assert(!input(s, r, 0, 1, true, 3, 120, true));
        if (mode == 0)
            wires[3][21] ^= 1;
        else
            s->expected[0] ^= 1;
        assert(!input(s, r, 1, 1, true, 3, 120, false));
        assert(!input(s, r, 2, 1, true, 3, 120, false));
        assert(input(s, r, 3, 1, true, 3, 120, false));
        assert(s->completed && !s->matched && !atomic_load(&s->witnessed));
        if (mode == 0)
            wires[3][21] ^= 1;
        IHS_FECReceiverDestroy(r);
    }
    for (unsigned mode = 0; mode < 2; ++mode) {
        probe_loss = (probe_fec_loss){.enabled = true};
        probe_fec_loss *s = &probe_loss;
        IHS_FECReceiver *r = begin(s, 0);
        assert(!input(s, r, 0, 1, true, 3, 120, true));
        if (mode == 0) {
            wires[0][13]++; /* valid but inconsistent L, still block index0 */
            assert(!input(s, r, 0, 1, true, 3, 120, false));
            wires[0][13]--;
            assert(s->conflict && s->blocked == 2);
        } else {
            assert(!input(s, r, 0, 2, true, 3, 120, true));
            assert(s->replaced);
        }
        assert(!input(s, r, 1, 1, true, 3, 120, true));
        assert(!input(s, r, 2, 1, true, 3, 120, true));
        assert(input(s, r, 3, 1, true, 3, 120, true));
        assert(s->completed && !s->matched && !atomic_load(&s->witnessed));
        IHS_FECReceiverDestroy(r);
    }
    probe_loss = (probe_fec_loss){.enabled = true};
    probe_fec_loss *incomplete = &probe_loss;
    IHS_FECReceiver *incomplete_rx = begin(incomplete, 0);
    assert(!input(incomplete, incomplete_rx, 0, 1, true, 3, 120, true));
    assert(!input(incomplete, incomplete_rx, 1, 1, true, 3, 120, true));
    assert(!input(incomplete, incomplete_rx, 2, 1, true, 3, 120, true));
    assert(!incomplete->completed && !atomic_load(&incomplete->witnessed));
    IHS_FECReceiverDestroy(incomplete_rx);
    probe_loss = (probe_fec_loss){.enabled = true};
    probe_fec_loss *wrap = &probe_loss;
    IHS_FECReceiver *r = begin(wrap, UINT16_MAX);
    repair(wrap, r, 0, true);
    assert(wrap->matched);
    IHS_FECReceiverDestroy(r);
    puts(
        "PASS: official codeword erasure, duplicates, survivor orders and witness counterexamples");
    return 0;
}
