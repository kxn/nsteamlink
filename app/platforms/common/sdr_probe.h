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
