#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* NETWORKING sections 18.1–18.2. These are SDK encrypted chunks, never IHS
 * plaintext. Router -> client has TWO timing words; client -> router has one. */
typedef struct sl_sdr_data {
    uint8_t flags;
    uint16_t e2e_sequence, relay_sequence;
    uint32_t connection_id;
    const uint8_t *stats, *chunk;
    size_t stats_size, chunk_size;
    int sender_spacing_us, relay_spacing_us;
} sl_sdr_data;
size_t sl_sdr_ping(uint8_t *out, size_t capacity, bool short_ping, uint64_t now_us,
                   uint32_t cookie, uint32_t config_version, uint32_t ipv4, uint16_t port);
bool sl_sdr_parse_data(const uint8_t *, size_t, sl_sdr_data *);
size_t sl_sdr_write_data(uint8_t *, size_t, const sl_sdr_data *);

/* NETWORKING sections 21.12–21.16. The five pending relay ACK records are
 * independent of SNP acknowledgments and reliable rendezvous acknowledgments. */
typedef struct sl_sdr_ack_record { uint16_t sequence; uint64_t received_us; } sl_sdr_ack_record;
typedef struct sl_sdr_acks {
    sl_sdr_ack_record entries[5];
    unsigned count;
    bool force;
} sl_sdr_acks;
void sl_sdr_ack_queue(sl_sdr_acks *, uint16_t, uint64_t received_us, bool immediate);
/* Earliest required send. UINT64_MAX means no pending relay ACK. */
uint64_t sl_sdr_ack_deadline(const sl_sdr_acks *);
size_t sl_sdr_ack_pack(const sl_sdr_acks *, uint64_t now_us, uint32_t out[5]);
void sl_sdr_ack_commit(sl_sdr_acks *); /* Caller observes control/inline timing. */

#define SL_SDR_TOKEN_MAX 1024 /* Local resource limit, not a protocol constant. */
typedef struct sl_sdr_target {
    uint8_t desired[SL_SDR_TOKEN_MAX], sent[SL_SDR_TOKEN_MAX];
    size_t desired_size, sent_size;
    uint32_t desired_pop, sent_pop, revision;
    bool acknowledged;
} sl_sdr_target;
bool sl_sdr_target_desire(sl_sdr_target *, const uint8_t *, size_t, uint32_t pop);
/* Construction changes sent state before socket I/O; failure never rolls back. */
bool sl_sdr_target_populate(sl_sdr_target *);
void sl_sdr_target_ack(sl_sdr_target *, uint32_t revision);

typedef struct sl_sdr_revisions {
    uint32_t local, local_acked, peer;
    uint64_t retry_us;
    bool ack_pending;
} sl_sdr_revisions;
typedef struct sl_sdr_routing_fields {
    bool forward, peer_ack, routes;
    unsigned e2e_mode, flags;
} sl_sdr_routing_fields;
/* Call even on failed routes protobuf parse: it still creates a pending ACK. */
bool sl_sdr_routes_received(sl_sdr_revisions *, bool parsed, uint32_t revision);
void sl_sdr_routes_ack(sl_sdr_revisions *, uint32_t revision);
bool sl_sdr_routes_due(const sl_sdr_revisions *, uint64_t now_us);
sl_sdr_routing_fields sl_sdr_routes_populate_stats(const sl_sdr_revisions *,
    bool have_target, bool target_acked, bool primary_session, bool current_transport,
    bool force_e2e, bool need_confirm, uint64_t now_us);
void sl_sdr_routes_track_stats(sl_sdr_revisions *, sl_sdr_routing_fields, uint64_t now_us);
/* Always carries/consumes pending peer ACK, including connection_closed. */
sl_sdr_routing_fields sl_sdr_routes_rendezvous(sl_sdr_revisions *, bool closed, uint64_t now_us);
