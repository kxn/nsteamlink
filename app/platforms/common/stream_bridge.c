#include "stream_bridge.h"
#include "remote_wire.h"
#include "protobuf/discovery.pb-c.h"
#include "protobuf/remoteplay.pb-c.h"
#include <mbedtls/md.h>
#include <stdlib.h>
#include <string.h>

/* Local memory limits, not Valve limits. Exhaustion is explicit failure to
 * accept; candidates/retransmitted rendezvous messages are never deduplicated. */
enum { SIGNAL_MAX = 60000, QUEUE_COUNT = 64, QUEUE_BYTES = 256 * 1024 };
typedef struct pending_signal {
    struct pending_signal *next;
    size_t size;
    uint8_t bytes[];
} pending_signal;
struct sl_signal_channel {
    uint64_t client_id, steam_id;
    uint8_t key[128];
    size_t key_size, count, bytes;
    bool failed;
    sl_signal_callbacks cb;
    void *ctx;
    pending_signal *head, *tail;
};
struct sl_stream_bridge {
    sl_signal_channel *channel;
    sl_remote_connection *connection;
};
static void erase(void *p, size_t n) {
    volatile uint8_t *q = p;
    while (n--)
        *q++ = 0;
}
static bool mac(const sl_signal_channel *c, const uint8_t *p, size_t n, uint8_t out[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return md && !mbedtls_md_hmac(md, c->key, c->key_size, p, n, out);
}
sl_signal_channel *sl_signal_channel_create(uint64_t client, uint64_t steam,
    const uint8_t *key, size_t size, const sl_signal_callbacks *cb, void *ctx) {
    if (!client || !steam || !key || !size || size > 128 || !cb || !cb->receive)
        return NULL;
    sl_signal_channel *c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->client_id = client;
    c->steam_id = steam;
    memcpy(c->key, key, size);
    c->key_size = size;
    c->cb = *cb;
    c->ctx = ctx;
    return c;
}
bool sl_signal_channel_queue(sl_signal_channel *c, const uint8_t *data, size_t size) {
    if (!c || c->failed || !data || !size || size > SIGNAL_MAX ||
        c->count == QUEUE_COUNT || size > QUEUE_BYTES - c->bytes)
        return false;
    pending_signal *p = malloc(sizeof(*p) + size);
    if (!p)
        return false;
    p->next = NULL;
    p->size = size;
    memcpy(p->bytes, data, size);
    if (c->tail)
        c->tail->next = p;
    else
        c->head = p;
    c->tail = p;
    c->count++;
    c->bytes += size;
    return true;
}
void sl_signal_channel_flush(sl_signal_channel *c, sl_remote *cloud) {
    if (!c || c->failed || !cloud || !sl_remote_ready(cloud) || !c->head)
        return;
    uint8_t *inner = malloc(SIGNAL_MAX + 4), *outer = malloc(SIGNAL_MAX + 48);
    if (!inner || !outer)
        goto done;
    while (c->head) {
        /* Batch pending sdr elements, preserving duplicates and FIFO order. */
        sl_proto_writer payload = {inner, 0, SIGNAL_MAX + 4, false};
        pending_signal *p = c->head;
        size_t count = 0;
        while (p && (count == 0 || p->size + 4 <= payload.capacity - payload.size)) {
            sl_proto_bytes(&payload, 2, p->bytes, p->size);
            ++count;
            p = p->next;
        }
        uint8_t token[32];
        if (payload.invalid || !mac(c, inner, payload.size, token))
            break;
        sl_proto_writer envelope = {outer, 0, SIGNAL_MAX + 48, false};
        sl_proto_bytes(&envelope, 1, token, sizeof(token));
        sl_proto_bytes(&envelope, 2, inner, payload.size);
        erase(token, sizeof(token));
        if (envelope.invalid || !sl_remote_send_signal(cloud, c->steam_id, outer, envelope.size))
            break; /* Keep inner messages; a new cloud session needs new framing. */
        while (count--) {
            pending_signal *sent = c->head;
            c->head = sent->next;
            --c->count;
            c->bytes -= sent->size;
            erase(sent->bytes, sent->size);
            free(sent);
        }
        if (!c->head)
            c->tail = NULL;
    }
done:
    if (inner) {
        erase(inner, SIGNAL_MAX + 4);
        free(inner);
    }
    if (outer) {
        erase(outer, SIGNAL_MAX + 48);
        free(outer);
    }
}
int sl_signal_channel_receive(sl_signal_channel *c, uint64_t peer,
                              const uint8_t *body, size_t size) {
    if (!c || c->failed)
        return -1;
    if (peer != c->client_id || !body || size > SL_REMOTE_FRAME_MAX)
        return 0;
    CMsgRemoteDeviceStreamTransportSignal *message =
        cmsg_remote_device_stream_transport_signal__unpack(NULL, size, body);
    CTransportSignalMsg *inner = NULL;
    int result = 0;
    if (!message || !message->has_token || message->token.len != 32 || !message->has_payload)
        goto done;
    uint8_t expected[32];
    if (!mac(c, message->payload.data, message->payload.len, expected))
        goto done;
    unsigned mismatch = 0;
    for (size_t i = 0; i < 32; ++i)
        mismatch |= expected[i] ^ message->token.data[i];
    erase(expected, sizeof(expected));
    if (mismatch)
        goto done;
    inner = ctransport_signal_msg__unpack(NULL, message->payload.len, message->payload.data);
    if (!inner)
        goto done;
    result = 1;
    for (size_t i = 0; i < inner->n_sdr; ++i) {
        if (!c->cb.receive(inner->sdr[i].data, inner->sdr[i].len, c->ctx)) {
            c->failed = true;
            result = -1;
            if (c->cb.failed)
                c->cb.failed(c->ctx);
            break;
        }
    }
done:
    if (inner)
        ctransport_signal_msg__free_unpacked(inner, NULL);
    if (message)
        cmsg_remote_device_stream_transport_signal__free_unpacked(message, NULL);
    return result;
}
bool sl_signal_channel_pending(const sl_signal_channel *c) { return c && c->head; }
bool sl_signal_channel_failed(const sl_signal_channel *c) { return !c || c->failed; }
void sl_signal_channel_destroy(sl_signal_channel *c) {
    if (!c)
        return;
    while (c->head) {
        pending_signal *p = c->head;
        c->head = p->next;
        erase(p->bytes, p->size);
        free(p);
    }
    erase(c, sizeof(*c));
    free(c);
}
static void received(uint64_t peer, const uint8_t *body, size_t size, void *ctx) {
    sl_stream_bridge *b = ctx;
    sl_signal_channel_receive(b->channel, peer, body, size);
}
sl_stream_bridge *sl_stream_bridge_create(const IHS_ClientConfig *config,
    const sl_remote_material *m, const sl_signal_callbacks *cb, void *ctx) {
    if (!m)
        return NULL;
    sl_stream_bridge *b = calloc(1, sizeof(*b));
    if (!b)
        return NULL;
    b->channel = sl_signal_channel_create(m->client_id, m->steam_id, m->key, m->key_size, cb, ctx);
    sl_remote_callbacks remote_cb = {.transport_signal = received};
    if (b->channel)
        b->connection = sl_remote_connection_create(config, &remote_cb, b);
    if (!b->connection) {
        sl_stream_bridge_destroy(b);
        return NULL;
    }
    sl_remote_connection_set_bridge_mode(b->connection, true);
    return b;
}
bool sl_stream_bridge_queue(sl_stream_bridge *b, const uint8_t *data, size_t size) {
    return b && sl_signal_channel_queue(b->channel, data, size);
}
void sl_stream_bridge_update(sl_stream_bridge *b, uint64_t now, bool wants_cloud) {
    if (!b)
        return;
    bool needed = wants_cloud || sl_signal_channel_pending(b->channel);
    sl_remote_connection_set_active(b->connection, needed);
    if (needed) {
        sl_remote_connection_update(b->connection, now);
        sl_signal_channel_flush(b->channel, sl_remote_connection_protocol(b->connection));
    }
}
bool sl_stream_bridge_failed(const sl_stream_bridge *b) {
    return !b || sl_signal_channel_failed(b->channel);
}
void sl_stream_bridge_destroy(sl_stream_bridge *b) {
    if (!b)
        return;
    sl_remote_connection_destroy(b->connection);
    sl_signal_channel_destroy(b->channel);
    free(b);
}
