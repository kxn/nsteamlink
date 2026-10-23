#include "sdr_wire.h"
#include <string.h>

static uint16_t read16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1] << 8); }
static uint32_t read32(const uint8_t *p) {
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void write16(uint8_t *p, uint16_t n) { p[0] = (uint8_t)n; p[1] = (uint8_t)(n >> 8); }
static void write32(uint8_t *p, uint32_t n) {
    write16(p, (uint16_t)n); write16(p + 2, (uint16_t)(n >> 16));
}
size_t sl_sdr_ping(uint8_t *out, size_t cap, bool short_ping, uint64_t now,
                   uint32_t cookie, uint32_t revision, uint32_t ipv4, uint16_t port) {
    size_t size = short_ping ? 100 : 1300;
    if (!out || cap < size)
        return 0;
    memset(out, 0, size);
    out[0] = 1;
    out[1] = short_ping ? 0x82 : 0x02;
    memcpy(out + 2, "sdping", 6);
    write32(out + 8, (uint32_t)now);
    write32(out + 12, cookie);
    write32(out + 20, revision);
    write32(out + 24, ipv4 ^ cookie);
    write16(out + 28, (uint16_t)(port ^ cookie));
    write16(out + 30, 13);
    return size;
}
bool sl_sdr_parse_data(const uint8_t *p, size_t size, sl_sdr_data *out) {
    if (!p || !out || size < 9 || size > 1300 || (p[0] & 0xe0) != 0x40)
        return false;
    sl_sdr_data d = {.flags = p[0], .e2e_sequence = read16(p + 1),
        .relay_sequence = read16(p + 3), .connection_id = read32(p + 5),
        .sender_spacing_us = -1, .relay_spacing_us = -1};
    size_t at = 9;
    if (d.flags & 1) {
        uint32_t length = 0;
        unsigned shift = 0;
        for (;;) {
            if (at == size || shift >= 35)
                return false;
            uint8_t byte = p[at++];
            if (shift == 28 && byte > 15)
                return false;
            length |= (uint32_t)(byte & 127) << shift;
            if (!(byte & 128))
                break;
            shift += 7;
        }
        if (length > size - at)
            return false;
        d.stats = p + at;
        d.stats_size = length;
        at += length;
    }
    if (d.flags & 2) {
        if (size - at < 4)
            return false;
        d.sender_spacing_us = (int)read16(p + at) << 4;
        d.relay_spacing_us = (int)read16(p + at + 2) << 4;
        at += 4;
    }
    d.chunk = p + at;
    d.chunk_size = size - at;
    *out = d;
    return true;
}
size_t sl_sdr_write_data(uint8_t *out, size_t cap, const sl_sdr_data *d) {
    if (!out || !d || d->stats_size > UINT32_MAX ||
        (d->stats_size && !d->stats) || (d->chunk_size && !d->chunk))
        return 0;
    uint8_t length[5];
    unsigned count = 0;
    uint32_t n = (uint32_t)d->stats_size;
    if (d->stats_size) {
        do {
            length[count++] = (uint8_t)((n & 127) | (n > 127 ? 128 : 0));
            n >>= 7;
        } while (n);
    }
    bool timing = d->sender_spacing_us >= 0 && d->sender_spacing_us <= 250000;
    size_t header = 9 + count + d->stats_size + (timing ? 2 : 0);
    if (header > cap || d->chunk_size > cap - header)
        return 0;
    out[0] = 0xa0 | (count ? 1 : 0) | (timing ? 2 : 0);
    write16(out + 1, d->e2e_sequence);
    write16(out + 3, d->relay_sequence);
    write32(out + 5, d->connection_id);
    size_t at = 9;
    if (count) {
        memcpy(out + at, length, count);
        at += count;
        memcpy(out + at, d->stats, d->stats_size);
        at += d->stats_size;
    }
    if (timing) {
        write16(out + at, (uint16_t)((unsigned)d->sender_spacing_us >> 4));
        at += 2;
    }
    if (d->chunk_size)
        memcpy(out + at, d->chunk, d->chunk_size);
    return at + d->chunk_size;
}
void sl_sdr_ack_queue(sl_sdr_acks *q, uint16_t sequence, uint64_t now, bool immediate) {
    if (immediate)
        q->force = true;
    if (q->count && q->entries[q->count - 1].sequence == sequence)
        return;
    unsigned index = q->count;
    if (index == 5) {
        if (!immediate)
            return;
        index = 4;
    } else {
        ++q->count;
    }
    q->entries[index] = (sl_sdr_ack_record){sequence, now & UINT64_C(0xffffffffffff)};
}
uint64_t sl_sdr_ack_deadline(const sl_sdr_acks *q) {
    if (!q->count)
        return UINT64_MAX;
    return q->force || q->count == 5 ? 0 : q->entries[0].received_us + 250000;
}
size_t sl_sdr_ack_pack(const sl_sdr_acks *q, uint64_t now, uint32_t out[5]) {
    for (unsigned i = 0; i < q->count; ++i) {
        uint64_t time = q->entries[i].received_us;
        uint64_t delay = now < time ? UINT64_MAX : (now - time) / 64;
        if (delay > UINT16_MAX)
            delay = UINT16_MAX;
        out[i] = (uint32_t)q->entries[i].sequence << 16 | (uint32_t)delay;
    }
    return q->count;
}
void sl_sdr_ack_commit(sl_sdr_acks *q) { q->count = 0; q->force = false; }
bool sl_sdr_target_desire(sl_sdr_target *s, const uint8_t *p, size_t n, uint32_t pop) {
    if (n > SL_SDR_TOKEN_MAX || (n && !p))
        return false;
    if (n)
        memcpy(s->desired, p, n);
    s->desired_size = n;
    s->desired_pop = n ? pop : 0;
    return true;
}
bool sl_sdr_target_populate(sl_sdr_target *s) {
    if (!s->desired_size)
        return false;
    if (s->desired_size != s->sent_size || memcmp(s->desired, s->sent, s->desired_size)) {
        memcpy(s->sent, s->desired, s->desired_size);
        s->sent_size = s->desired_size;
        s->sent_pop = s->desired_pop;
        ++s->revision;
        s->acknowledged = false;
    }
    return true;
}
void sl_sdr_target_ack(sl_sdr_target *s, uint32_t revision) {
    s->acknowledged = revision == s->revision;
}
bool sl_sdr_routes_received(sl_sdr_revisions *s, bool parsed, uint32_t revision) {
    s->ack_pending = true;
    if (!parsed || revision <= s->peer)
        return false;
    s->peer = revision;
    return true;
}
void sl_sdr_routes_ack(sl_sdr_revisions *s, uint32_t revision) {
    if (revision > s->local)
        return;
    s->local_acked = revision;
    if (revision == s->local)
        s->retry_us = 0;
}
bool sl_sdr_routes_due(const sl_sdr_revisions *s, uint64_t now) {
    return s->local != s->local_acked && s->retry_us <= now;
}
sl_sdr_routing_fields sl_sdr_routes_populate_stats(const sl_sdr_revisions *s,
    bool target, bool target_acked, bool primary, bool current, bool force, bool confirm, uint64_t now) {
    sl_sdr_routing_fields f = {.flags = (primary ? 0u : 8u) | (current ? 0u : 16u)};
    bool eligible = target && (primary || force);
    f.forward = target && !target_acked;
    f.peer_ack = eligible && (s->ack_pending || confirm);
    f.routes = eligible && s->local != s->local_acked && (s->retry_us < now || confirm);
    f.e2e_mode = !target ? 0 : force || f.peer_ack || f.routes ? 2 : primary ? 1 : 0;
    return f;
}
void sl_sdr_routes_track_stats(sl_sdr_revisions *s, sl_sdr_routing_fields f, uint64_t now) {
    if (f.peer_ack)
        s->ack_pending = false;
    if (f.routes)
        s->retry_us = now + 500000;
}
sl_sdr_routing_fields sl_sdr_routes_rendezvous(sl_sdr_revisions *s, bool closed, uint64_t now) {
    sl_sdr_routing_fields f = {.peer_ack = true};
    s->ack_pending = false;
    if (!closed && sl_sdr_routes_due(s, now)) {
        f.routes = true;
        s->retry_us = now + 1000000;
    }
    return f;
}
