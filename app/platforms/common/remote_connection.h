#pragma once
#include "remote_protocol.h"
typedef struct sl_remote_connection sl_remote_connection;
/* Nonblocking multi-handle TLS provider. Uses curl's existing HTTPS backend,
 * including libnx SSL on Switch; does not require curl's newer WebSocket API. */
sl_remote_connection *sl_remote_connection_create(const IHS_ClientConfig *,
                                                  const sl_remote_callbacks *, void *);
sl_remote *sl_remote_connection_protocol(sl_remote_connection *);
void sl_remote_connection_update(sl_remote_connection *, uint64_t monotonic_ms);
#if NSL_DIAGNOSTICS
/* Owner-thread, read-only metadata; no endpoints' credentials or packet data. */
void sl_remote_connection_describe(const sl_remote_connection *, uint64_t monotonic_ms, char *,
                                   size_t);
#endif
/* Per-stream bridges retry immediately while wanted (NETWORKING section 13.1).
 * Discovery keeps its ordinary jittered initial-failure backoff. */
void sl_remote_connection_set_bridge_mode(sl_remote_connection *, bool);
/* Stop all requests/queued envelopes when no stream needs this connection. */
void sl_remote_connection_set_active(sl_remote_connection *, bool);
void sl_remote_connection_destroy(sl_remote_connection *);
