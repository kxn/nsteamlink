/* Optional diagnostic erasure, not a product receive policy. Only the network
 * owner touches this state, except witnessed (release/acquire). Read all other
 * fields only after that owner has joined. No allocation, I/O or waits here.
 * Evidence: protocol reference sections 26/33/110, original one-group RX/RS.
 * drop-one withholds index0 and ALL its duplicates, then compares useful bytes
 * in the real receiver output. drop-group withholds every target shard and
 * duplicate for a later key-recovery witness. Never supply saved bytes to RX. */
#pragma once
#include "session/channels/video/ch_data_video.h"
#include "session/fec.h"
#include <stdatomic.h>
#include <string.h>

enum { PROBE_ERASURE_BYTES = 1472, PROBE_ERASURE_WARMUP = 120 };
typedef struct probe_fec_seen {
    const IHS_FECReceiver *receiver;
    uint16_t group;
    bool valid;
} probe_fec_seen;
typedef struct probe_fec_loss {
    bool enabled, selected, completed, matched, conflict, replaced, drop_group;
    atomic_bool witnessed;
    probe_fec_seen seen[32];
    const IHS_FECReceiver *receiver;
    uint16_t group, width, parity;
    uint32_t length, data;
    unsigned channel, blocked, unique_data, unique_parity;
    unsigned blocked_unique;
    uint8_t blocked_indices[255];
    uint8_t forwarded[255], expected[PROBE_ERASURE_BYTES];
} probe_fec_loss;
typedef struct probe_fec_shape {
    uint32_t length, data;
    uint16_t width, parity, index;
    const uint8_t *bytes;
} probe_fec_shape;

static bool probe_fec_shape_read(const IHS_SessionPacket *p, probe_fec_shape *s) {
    if (p->header.type != IHS_SessionPacketTypeUnreliableFEC || !p->body.data || p->body.size < 9)
        return false;
    const uint8_t *b = IHS_BufferPointer(&p->body);
    s->length = b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
    s->width = b[4] | (unsigned)b[5] << 8;
    s->parity = b[6] | (unsigned)b[7] << 8;
    s->index = (uint16_t)p->header.fragmentId;
    if (!s->length || s->length > IHS_FEC_MAX_DATA_BYTES || !s->width ||
        p->body.size != (size_t)s->width + 8)
        return false;
    s->data = (s->length + s->width - 1u) / s->width;
    uint32_t total = s->data + s->parity;
    if ((size_t)s->data * s->width > IHS_FEC_MAX_DATA_BYTES || total > 65536 || s->index >= total ||
        (s->parity && total > 255))
        return false;
    s->bytes = b + 8;
    return true;
}

static bool probe_fec_loss_before(probe_fec_loss *s, IHS_FECReceiver *r, const IHS_SessionPacket *p,
                                  bool media_context, unsigned video_channel,
                                  uint64_t submissions) {
    if (!s->enabled || !media_context || !r ||
        p->header.type != IHS_SessionPacketTypeUnreliableFEC || p->header.channelId < 3 ||
        p->header.channelId >= 32)
        return false;
    probe_fec_shape shape;
    bool valid = probe_fec_shape_read(p, &shape);
    bool target = s->selected && s->receiver == r && s->channel == p->header.channelId &&
                  s->group == p->header.packetId;
    if (target) {
        bool same = valid && shape.length == s->length && shape.width == s->width &&
                    shape.parity == s->parity;
        if (!same)
            s->conflict = true;
        /* Never expose the withheld data, including changed duplicates. */
        if (s->drop_group || (uint16_t)p->header.fragmentId == 0) {
            ++s->blocked;
            if (same && !s->blocked_indices[shape.index]) {
                s->blocked_indices[shape.index] = 1;
                ++s->blocked_unique;
            }
            return true;
        }
        if (same && !s->completed && !s->forwarded[shape.index]) {
            s->forwarded[shape.index] = 1;
            if (shape.index < s->data)
                ++s->unique_data;
            else
                ++s->unique_parity;
        }
        return false;
    }
    if (!valid)
        return false;
    if (s->selected && !s->completed && !s->drop_group && s->receiver == r &&
        s->channel == p->header.channelId)
        s->replaced = true;
    probe_fec_seen *seen = &s->seen[p->header.channelId];
    uint16_t distance = (uint16_t)(p->header.packetId - seen->group);
    bool fresh = seen->valid && seen->receiver == r && distance && distance < 0x8000;
    if (!seen->valid || seen->receiver != r || fresh) {
        seen->receiver = r;
        seen->group = p->header.packetId;
        seen->valid = true;
    }
    /* Never select the first observed group, a rollback, a partly observed
     * group or audio/test ingress. The watermark starts
     * before the channel is identified as video, so earlier forwarded index0
     * cannot be mistaken for an erasure later in that same group. */
    if (s->selected || !fresh || p->header.channelId != video_channel ||
        submissions < PROBE_ERASURE_WARMUP || shape.index || shape.width > PROBE_ERASURE_BYTES ||
        IHS_FECReceiverLastError(r) != IHS_FECReceiveOK)
        return false;
    if (s->drop_group) {
        /* One complete, unencrypted non-key media fragment. Reject unknown
         * roles/ranges and large no-parity groups outside the fixed ledger.
         * Byte offsets are the same data/video envelope as protocol §25/161. */
        const uint8_t *b = shape.bytes;
        if (shape.width < 20 || shape.length < 20 || shape.data + shape.parity > 255 ||
            b[0] != k_EStreamDataPacket || !(b[15] & VideoFrameFlagFrameFinish) ||
            (b[15] & (VideoFrameFlagKeyFrame | VideoFrameFlagEncrypted)) || b[16] || b[17] ||
            b[18] || b[19])
            return false;
    } else if (shape.data < 2 || !shape.parity)
        return false;
    s->selected = true;
    s->receiver = r;
    s->channel = p->header.channelId;
    s->group = p->header.packetId;
    s->width = shape.width;
    s->parity = shape.parity;
    s->length = shape.length;
    s->data = shape.data;
    s->blocked = 1;
    s->blocked_unique = 1;
    s->blocked_indices[0] = 1;
    memcpy(s->expected, shape.bytes, shape.width);
    return true;
}

static void probe_fec_loss_after(probe_fec_loss *s, IHS_FECReceiver *r, const IHS_SessionPacket *p,
                                 const IHS_SessionFrame *f, bool ready) {
    if (!s->enabled || !s->selected || s->completed || !ready || s->receiver != r ||
        s->channel != p->header.channelId || s->group != p->header.packetId)
        return;
    s->completed = true;
    s->matched = !s->conflict && !s->replaced && !s->forwarded[0] && s->unique_data < s->data &&
                 s->unique_parity && s->unique_data + s->unique_parity >= s->data &&
                 f->header.type == IHS_SessionPacketTypeUnreliableFEC &&
                 f->header.packetId == s->group && f->header.channelId == s->channel &&
                 f->body.data && f->body.size == s->length &&
                 !memcmp(IHS_BufferPointer(&f->body), s->expected, s->width);
    if (s->matched)
        atomic_store_explicit(&s->witnessed, true, memory_order_release);
}
