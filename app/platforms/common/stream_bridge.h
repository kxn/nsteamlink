#pragma once
#include "remote_connection.h"

typedef struct sl_signal_channel sl_signal_channel;
typedef struct sl_stream_bridge sl_stream_bridge;
typedef struct sl_signal_callbacks {
    /* Receiver forwards opaque SNS bytes. false is a terminal backend error;
     * bad framing/HMAC/protobuf never calls this callback. */
    bool (*receive)(const uint8_t *, size_t, void *);
    void (*failed)(void *);
    /* Once per authenticated/parsed inner message, including an empty sdr
     * list and SDK rejection. Recheck transport state after the whole list. */
    void (*updated)(void *);
} sl_signal_callbacks;

/* Single-owner bridge queue and codec, NETWORKING sections 8.3/8.8/13.
 * The key is the decrypted stream key, with its actual length. Deep copies
 * of opaque signals survive cloud reconnect, but never another stream. */
sl_signal_channel *sl_signal_channel_create(uint64_t peer_client, uint64_t peer_steam,
    const uint8_t *key, size_t key_size, const sl_signal_callbacks *, void *);
bool sl_signal_channel_queue(sl_signal_channel *, const uint8_t *, size_t);
void sl_signal_channel_flush(sl_signal_channel *, sl_remote *cloud);
/* 1 accepted, 0 rejected input, -1 terminal SDK failure. Requires a nonzero
 * inbound header client_id and this channel's HMAC; the header ID itself is
 * not compared to the selected computer by the original transport bridge. */
int sl_signal_channel_receive(sl_signal_channel *, uint64_t client_id,
                              const uint8_t *body, size_t);
bool sl_signal_channel_pending(const sl_signal_channel *);
bool sl_signal_channel_failed(const sl_signal_channel *);
void sl_signal_channel_destroy(sl_signal_channel *);

/* Owns a separate anonymous cloud connection. Caller updates the SNS backend
 * first, queues its pending signals, then pumps this object on the same owner
 * thread. No worker or global SNS instance is created by this bridge. */
sl_stream_bridge *sl_stream_bridge_create(const IHS_ClientConfig *,
    const sl_remote_material *, const sl_signal_callbacks *, void *);
bool sl_stream_bridge_queue(sl_stream_bridge *, const uint8_t *, size_t);
void sl_stream_bridge_update(sl_stream_bridge *, uint64_t now_ms, bool backend_wants_cloud);
bool sl_stream_bridge_failed(const sl_stream_bridge *);
void sl_stream_bridge_destroy(sl_stream_bridge *);
