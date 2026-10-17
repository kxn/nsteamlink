#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

enum { SL_SDR_CANDIDATES = 128, SL_SDR_UNKNOWN = 0x0fffffff };
/* Metrics are computed before the selector. Cluster identity is distinct from
 * an individual relay address. Times use the same monotonic microsecond clock.
 * See NETWORKING 21.1-21.3, 21.6-21.7. */
typedef struct sl_sdr_candidate {
    int32_t score, minimum, maximum, other_penalty, shutdown_seconds, migration;
    int32_t buckets, front_samples, cluster, alternate_penalty;
    int64_t last_received, front_oldest, last_ping_sent, bucket_end, gap;
    bool eligible, draining, ping_pending;
} sl_sdr_candidate;
typedef struct sl_sdr_selection {
    int32_t primary, backup;
    bool probe[SL_SDR_CANDIDATES];
} sl_sdr_selection;
bool sl_sdr_select(const sl_sdr_candidate *, size_t count, int32_t primary, int32_t backup,
                   bool migration_pending, int64_t now, sl_sdr_selection *);
/* INT_MAX means absent; 0x0fffffff is a distinct, very large initial reverse
 * score and participates in the average. */
int32_t sl_sdr_comparison_score(int32_t forward, int32_t reverse);

typedef struct sl_sdr_timeouts {
    int64_t ping_deadline, request_deadline, last_received;
    unsigned ping_failures, request_failures;
    bool established;
} sl_sdr_timeouts;
enum { SL_SDR_TIMEOUT_PING = 1, SL_SDR_TIMEOUT_REQUEST = 2,
       SL_SDR_TIMEOUT_REPROBE = 4, SL_SDR_TIMEOUT_REMOVE = 8 };
unsigned sl_sdr_expire(sl_sdr_timeouts *, int64_t now);
typedef struct sl_sdr_downtime { int64_t shutdown, avoid; bool known; } sl_sdr_downtime;
/* Random input is supplied by the caller, in the sample's [45,60] interval. */
bool sl_sdr_warn_downtime(sl_sdr_downtime *, int32_t seconds, float random_seconds, int64_t now);
typedef struct sl_sdr_probe_input {
    int ping, probes, received, front_samples, failures, reachability, pop_type, tier, special, failed_addresses;
    float estimate;
    int64_t since_sent, since_received;
} sl_sdr_probe_input;
bool sl_sdr_probe_priority(const sl_sdr_probe_input *, bool active_connection, bool need_backup, float *);
typedef struct sl_sdr_probe_candidate { unsigned index; float priority; } sl_sdr_probe_candidate;
typedef struct sl_sdr_probe_plan {
    sl_sdr_probe_candidate candidates[SL_SDR_CANDIDATES];
    size_t count;
    float cutoff;
    unsigned budget;
} sl_sdr_probe_plan;
/* Input is already ordered by routing estimate, with the caller supplying the
 * sample's random ordering for unknown estimates. Nearest-N counts nonfailed
 * clusters, including unknown reachability, rather than emitted probes. */
bool sl_sdr_plan_probes(const sl_sdr_probe_input *, size_t count, int nearest_limit,
    bool active_connection, bool need_backup, sl_sdr_probe_plan *);
bool sl_sdr_routing_ready(int ordinary, int measured, int fast, int medium, int broad, int64_t age);
typedef struct sl_sdr_failed_address { uint64_t address; int64_t failed; } sl_sdr_failed_address;
typedef struct sl_sdr_failure_cache {
    sl_sdr_failed_address entries[3];
    unsigned count, failures;
    int reachability;
    int64_t last_probe;
} sl_sdr_failure_cache;
void sl_sdr_fail_address(sl_sdr_failure_cache *, uint64_t address, unsigned advertised, int64_t now);
void sl_sdr_expire_addresses(sl_sdr_failure_cache *, unsigned advertised, int64_t now);
void sl_sdr_address_received(sl_sdr_failure_cache *, uint64_t address);
bool sl_sdr_address_failed(const sl_sdr_failure_cache *, uint64_t address);
enum { SL_SDR_STATE_IGNORE = 0, SL_SDR_STATE_THINK = 1, SL_SDR_STATE_CLOSE = 2,
       SL_SDR_STATE_INVALID = 3 };
int sl_sdr_state_action(int state);
int sl_sdr_established_action(int state);
/* On a routes recomputation, prune empty desired targets before selection.
 * Keeping survivor order promotes a surviving backup to the current primary,
 * so its switching hysteresis still applies. NETWORKING 21.13. */
bool sl_sdr_clean_active(const bool *desired, size_t count, int32_t *primary, int32_t *backup);

/* NETWORKING 21.10. Canonical POP mapping is supplied by the caller. The
 * capacity is local memory policy, not a wire limit. Estimated entries retain
 * ping/penalty/flags when a complete reply invalidates direct timestamps. */
typedef struct sl_sdr_latency {
    uint32_t pop;
    int32_t ping, penalty;
    uint32_t flags;
    int64_t measured;
} sl_sdr_latency;
typedef struct sl_sdr_latencies {
    sl_sdr_latency entries[SL_SDR_CANDIDATES];
    size_t count;
    int64_t last_full;
} sl_sdr_latencies;
bool sl_sdr_latencies_begin(sl_sdr_latencies *, uint32_t reply_flags, int64_t now);
bool sl_sdr_latency_measure(sl_sdr_latencies *, uint32_t pop, int32_t ping, bool p2p, int64_t now);
void sl_sdr_latency_estimate(sl_sdr_latencies *, uint32_t pop, int32_t ping);
void sl_sdr_latency_exception(sl_sdr_latencies *, uint32_t pop, uint32_t flags, int32_t penalty);
const sl_sdr_latency *sl_sdr_latency_find(const sl_sdr_latencies *, uint32_t pop);
int32_t sl_sdr_cluster_penalty(int32_t incoming);
typedef struct sl_sdr_edge { unsigned source, target; int32_t ping; } sl_sdr_edge;
/* Fixed client's three in-place passes, followed by the direct-source lower
 * bound midpoint. Output is unchanged on invalid/bounded-resource input. */
bool sl_sdr_route_estimates(const int32_t *front, size_t count, const sl_sdr_edge *,
    size_t edge_count, int32_t *estimates);
bool sl_sdr_router_ping_ms(uint32_t timestamp, int64_t now, int32_t *ping);
bool sl_sdr_router_cookie(uint32_t cookie, uint32_t root_cookie, uint32_t session_id, bool have_session);
bool sl_sdr_front_eligible(int pop_type, int ping, int reachability, int special);
enum { SL_SDR_ADVERT_ROUTES_MAX = SL_SDR_CANDIDATES*SL_SDR_CANDIDATES };
typedef struct sl_sdr_advert_cluster {
    int32_t ping, penalty, special;
    bool remote_used, old_member;
} sl_sdr_advert_cluster;
typedef struct sl_sdr_advert_route {
    unsigned local, remote;
    int32_t forward, reverse;
    bool internal, forced, old_member;
} sl_sdr_advert_route;
/* NETWORKING 21.9: union of four route sorts, then local-cluster requirements
 * and the independent four-plus-two cluster selection. No debug POP override.
 * Old mode fails if a rank>=3 item is missing from the old message. Outputs are
 * indexed like the inputs and remain unchanged on failure. */
bool sl_sdr_mark_advertisement(const sl_sdr_advert_cluster *, size_t clusters,
    const sl_sdr_advert_route *, size_t routes, bool old_mode,
    uint8_t *cluster_ranks, uint8_t *route_ranks);
/* Strict difference threshold; an old ping inside the current recent range
 * is retained even at/above that threshold. Pass low=high=-1 for penalties
 * and interior scores, which have no range exception. */
bool sl_sdr_old_metric_valid(int32_t current, int32_t previous, int32_t low, int32_t high);
/* TruncateLists sorts rank descending, then comparison score ascending, then
 * POP indices. All indices are returned; rank-zero items form the tail. */
bool sl_sdr_order_advertisement(const sl_sdr_advert_cluster *, size_t clusters,
    const sl_sdr_advert_route *, size_t routes, bool old_mode,
    const uint8_t *cluster_ranks, const uint8_t *route_ranks,
    unsigned *cluster_order, unsigned *route_order);
size_t sl_sdr_ping_request_size(int64_t last_full_latencies, int64_t now);

/* NETWORKING 21.18: automatic reply requests in a packet being populated.
 * These clocks belong to each stats tracker, independently of root probes. */
typedef struct sl_sdr_stats_probe {
    int activity, failures;
    int64_t last_received, last_immediate_request, last_ping;
    bool pending;
} sl_sdr_stats_probe;
uint32_t sl_sdr_stats_request_flags(const sl_sdr_stats_probe *relay,
    const sl_sdr_stats_probe *e2e, int request, int mode, uint32_t flags,
    bool content, int64_t now);

/* NETWORKING 21.21: outer routes/ACK delivery, separate from packet production. */
bool sl_sdr_outer_probe(bool usable, bool need_confirm, const sl_sdr_stats_probe *e2e, int64_t now);
bool sl_sdr_outer_relay_sufficient(bool sent, bool need_confirm, bool pending_ack, bool routes_due,
    const sl_sdr_stats_probe *relay, const sl_sdr_stats_probe *e2e, int64_t now);
