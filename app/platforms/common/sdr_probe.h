#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Diagnostic driver for independently signed Valve relay session requests.
 * It never reports a media connection or replaces the SDK's selected route.
 * Raw packets/identity material remain private; only counters are exposed. */
typedef struct sl_sdr_probe sl_sdr_probe;
typedef struct sl_sdr_probe_stats {
    unsigned sent_pings, valid_ping_replies, requests, established, rejected;
} sl_sdr_probe_stats;
sl_sdr_probe *sl_gns_sdr_probe_create(uint32_t connection_handle, const char *json, size_t);
void sl_gns_sdr_probe_update(sl_sdr_probe *);
void sl_gns_sdr_probe_stats(const sl_sdr_probe *, sl_sdr_probe_stats *);
void sl_gns_sdr_probe_destroy(sl_sdr_probe *);
bool sl_gns_sdr_transport_stats(uint32_t connection, unsigned out[16]);

/* Diagnostic only: -1 query, 0 clear, 1 drop the current primary in both
 * directions, leaving all other endpoints untouched. Captures one address;
 * changing primary does not retarget the filter. */
bool sl_gns_sdr_test_loss(uint32_t connection, int mode, unsigned out[5]);

bool sl_gns_sdr_test_terminal(uint32_t connection, int packet_case);
/* Offline synthetic topology fixture; requires initialized SDK/manual polling.
 * Binds one ephemeral UDP socket, sends no packets, returns first failed stage. */
int sl_gns_sdr_topology_fixture(void);
/* Synthetic notification to the production migration consumer; subsequent
 * probe/session/route traffic uses real service responses. The original endpoint
 * is dropped only after authenticated E2E arrives through the exact target. */
bool sl_gns_sdr_test_migration(uint32_t connection, bool start, unsigned out[6]);

/* Fixture-only metadata snapshot. UINT32_MAX means no timestamp; ages are
 * milliseconds. No addresses, identities, payloads, or SDK text are returned. */
typedef struct sl_sdr_loss_snapshot {
    unsigned generation, elapsed, dropped_tx, dropped_rx, primary_pop, backup_pop;
    unsigned root_failures, session_failures, root_received_age, session_received_age;
    unsigned root_request_age, root_pending, front_samples, front_oldest_age;
    unsigned backup_root_failures, backup_session_failures, backup_received_age;
    unsigned previous_root_failures, previous_received_age, e2e_count, e2e_received_age;
    unsigned local_revision, peer_revision, pending_revision_ack, forward_ack;
    unsigned target_pop, target_revision, peer_first_local, peer_first_remote;
    unsigned e2e_request_age, e2e_pending, e2e_failures;
    unsigned controlling, local_acked, local_first_local, local_first_remote;
    unsigned local_primary_token, local_primary_route, peer_primary_route;
    unsigned cm_routes_out, cm_routes_in, stats_routes_out, stats_routes_in;
    unsigned relay_closed, relay_no_connection, cm_closed, close_reason, close_relay_mode, close_pop;
} sl_sdr_loss_snapshot;
bool sl_gns_sdr_loss_snapshot(uint32_t connection, sl_sdr_loss_snapshot *);
