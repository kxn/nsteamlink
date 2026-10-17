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
/* Numeric terminal origin; SDK end_reason remains a separate value. */
typedef enum sl_sns_terminal_source {
    SL_SNS_TERMINAL_NONE, SL_SNS_TERMINAL_SIGNAL, SL_SNS_TERMINAL_CERTIFICATE,
    SL_SNS_TERMINAL_START, SL_SNS_TERMINAL_CONFIG, SL_SNS_TERMINAL_CONNECTION_INFO,
    SL_SNS_TERMINAL_STATUS, SL_SNS_TERMINAL_CONNECTION, SL_SNS_TERMINAL_SIGNAL_QUEUE,
    SL_SNS_TERMINAL_SEND, SL_SNS_TERMINAL_RECEIVE, SL_SNS_TERMINAL_DATAGRAM,
    SL_SNS_TERMINAL_MEMORY
} sl_sns_terminal_source;
typedef struct sl_sns_stats {
    bool authenticated, relayed;
    uint64_t datagrams_sent, datagrams_received;
    sl_sns_terminal_source terminal_source;
    int terminal_detail;
} sl_sns_stats;
void sl_sns_get_stats(const sl_sns *, sl_sns_stats *);
/* Explicit diagnostic: verify relay session authorization in parallel with the
 * selected media path. Does not claim or force a relay media route. */
#if NSL_SNS_PROBES
bool sl_sns_start_relay_probe(sl_sns *);
void sl_sns_relay_probe_stats(const sl_sns *, unsigned out[5]);
void sl_sns_sdr_debug(const sl_sns *, unsigned out[16]);
/* out: generation, dropped TX/RX, observed E2E counter while the new primary
 * is usable (zero otherwise), different POP. The fixture checks fresh counter
 * progress at the end of its hold; a lone packet cannot prove recovery. */
bool sl_sns_test_relay_loss(sl_sns *, int mode, unsigned out[5]);
bool sl_sns_test_terminal(sl_sns *, int packet_case);
#endif
/* Set packet MTU and return the resulting SDK application-message MTU. */
int sl_sns_set_mtu(sl_sns *, int packet_mtu);
const IHS_DatagramTransport *sl_sns_datagram_transport(void);
void sl_sns_destroy(sl_sns *);
