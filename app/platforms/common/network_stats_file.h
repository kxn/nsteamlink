#pragma once
#include <ihslib/network_test.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct sl_network_stats_average {
    float loss_percent, mean_ms, deviation_ms;
} sl_network_stats_average;

/* Runtime-worker file access only. Returns file readability, not protobuf
 * validity (official LoadNetworkStats, protocol reference §121). A missing file
 * leaves output unchanged; a readable file adopts defaults/parsed prefix.
 * output may be NULL for the first-connect decision. */
bool sl_network_stats_load(const char *directory, sl_network_stats_average *output);
bool sl_network_stats_save(const char *directory, const sl_network_stats_average *,
                           const IHS_NetworkTestSample *, size_t count);
/* Completed, joined test Session must remain alive until this returns.
 * Uses finalized batch loss, not the test's span-based result loss. */
bool sl_network_stats_save_session(const char *directory, IHS_Session *);

/* Official constructor actions: 0 ordinary, 3 initial test then ordinary.
 * Other explicit test actions bypass the automatic file/video condition. */
unsigned sl_network_stats_connect_action(unsigned requested, bool video_enabled,
                                         bool stats_readable);
