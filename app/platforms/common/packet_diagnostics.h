#pragma once
#include <stdbool.h>
#include <stdint.h>
#if NSL_DIAGNOSTICS
typedef struct sl_packet_snapshot {
    bool active;
    uint64_t raw_total, raw_media[32], admitted[32], recovery[32];
} sl_packet_snapshot;
void sl_packet_diagnostics_begin(uint64_t peer);
void sl_packet_diagnostics_raw(uint64_t peer, unsigned channel, bool media);
void sl_packet_diagnostics_admit(unsigned channel);
void sl_packet_diagnostics_recovery(unsigned channel);
void sl_packet_diagnostics_read(sl_packet_snapshot *);
#endif
