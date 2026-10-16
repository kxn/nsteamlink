#pragma once
#include "remote_protocol.h"
#include <ihslib/transport.h>

typedef struct sl_sns sl_sns;
typedef enum sl_sns_state {
    SL_SNS_CONNECTING = 1, SL_SNS_CONNECTED = 2, SL_SNS_FAILED = 3, SL_SNS_CLOSED = 4
} sl_sns_state;

/* The application owns one SDK instance and updates it from one worker. All
 * other methods except the datagram callbacks are owner-thread-only. No SDK
 * object may outlive destroy. The public GNS dependency supplies SNP/ICE and
 * certificates; Valve relay access additionally requires the SDR extension. */
sl_sns *sl_sns_create(const IHS_ClientConfig *, const sl_remote_material *,
                       bool share_ip, char *error, size_t error_size);
void sl_sns_update(sl_sns *, uint64_t monotonic_ms);
sl_sns_state sl_sns_get_state(const sl_sns *);
/* Numeric diagnostics only; SDK text may embed a peer identity. */
int sl_sns_end_reason(const sl_sns *);
typedef struct sl_sns_stats {
    bool authenticated, relayed;
    uint64_t datagrams_sent, datagrams_received;
} sl_sns_stats;
void sl_sns_get_stats(const sl_sns *, sl_sns_stats *);
/* Set packet MTU and return the resulting SDK application-message MTU. */
int sl_sns_set_mtu(sl_sns *, int packet_mtu);
const IHS_DatagramTransport *sl_sns_datagram_transport(void);
void sl_sns_destroy(sl_sns *);
