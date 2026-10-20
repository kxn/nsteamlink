#pragma once
#include <ihslib/client.h>

#define SL_REMOTE_PEERS     16
typedef struct sl_remote sl_remote;
typedef struct sl_remote_peer {
    uint64_t client_id, steam_id;
    uint8_t secret[32];
} sl_remote_peer;
typedef struct sl_remote_host {
    IHS_HostInfo info;
    uint64_t steam_id;
    /* Borrowed protobuf strings during host(), never a reachability proof.
     * No eight-address truncation or public-address de-duplication here: the
     * directory must observe original source flags and insertion order. */
    const char *const *addresses;
    const char *public_address;
    size_t address_count;
} sl_remote_host;
typedef struct sl_remote_material {
    uint64_t client_id, steam_id;
    int transport;
    uint16_t port;
    uint8_t key[128];
    size_t key_size;
    const char *cert, *stun_servers; /* Borrowed only during stream_result. */
} sl_remote_material;
typedef struct sl_remote_callbacks {
    void (*diagnostic)(const char *message, void *);
    /* A successful send means copied into the connection's bounded FIFO.
     * The provider must discard its FIFO on disconnect; never replay envelopes. */
    bool (*send)(const uint8_t *, size_t, void *);
    void (*connected)(bool, void *);
    void (*host)(const sl_remote_host *, void *);
    void (*offline)(uint64_t client_id, void *);
    void (*pair_code)(const char *four_digits, void *);
    /* Must persist atomically before returning true. Used both after pairing
     * and BEFORE replying to a ProofRequest that rotates the long-lived key. */
    bool (*save_key)(const sl_remote_peer *, void *);
    void (*paired)(const sl_remote_peer *, void *);
    void (*pair_failed)(IHS_AuthorizationResult, void *);
    void (*stream_result)(IHS_StreamingResult, const sl_remote_material *, void *);
    /* Framing and header have been parsed; body is borrowed for this callback.
     * Stream signal integrity/inner parsing belongs to the per-stream bridge. */
    void (*transport_signal)(uint64_t client_id, const uint8_t *body, size_t, void *);
} sl_remote_callbacks;

/* All methods and callbacks run on one owner thread. No sockets or threads are
 * created here. Wire/strategy evidence: NETWORKING §8–§13 and AUTH reference. */
sl_remote *sl_remote_create(const IHS_ClientConfig *, const sl_remote_callbacks *, void *);
void sl_remote_destroy(sl_remote *);
bool sl_remote_open(sl_remote *); /* New WebSocket; sends CreateSession. */
void sl_remote_close(sl_remote *);
bool sl_remote_ready(const sl_remote *);
bool sl_remote_failed(const sl_remote *);
bool sl_remote_watch(sl_remote *, const sl_remote_peer *, size_t);
bool sl_remote_receive(sl_remote *, const uint8_t *, size_t);
bool sl_remote_pair(sl_remote *);
void sl_remote_cancel(sl_remote *);
bool sl_remote_stream(sl_remote *, uint64_t client_id, const IHS_StreamingRequest *);
typedef struct sl_remote_stream_options {
    bool network_test;
    /* Explicit backend capability. The runtime leaves this false until its
     * SNS backend passes interop. Diagnostic probes can exercise it alone. */
    bool sns;
    bool udp; /* Advertise UDP alongside SNS when the caller can use both. */
} sl_remote_stream_options;
bool sl_remote_stream_ex(sl_remote *, uint64_t client_id, const IHS_StreamingRequest *,
                          const sl_remote_stream_options *);
void sl_remote_update(sl_remote *, int64_t wall_seconds);
/* Forward an already-framed discovery/control/signal to a known Steam account. */
bool sl_remote_packet(sl_remote *, uint64_t steam_id, const uint8_t *, size_t);
/* Wrap a type-12 body with this session's local client identity. The bridge
 * retains inner messages, never an envelope containing an old cloud ID. */
bool sl_remote_send_signal(sl_remote *, uint64_t steam_id, const uint8_t *, size_t);
