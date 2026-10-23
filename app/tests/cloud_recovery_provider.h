/* Local CM service and SDK datagram adapters. Only this private receiver links
 * these wrappers. No real certificates, ICE/SNP, SDR POPs or NAT are exercised. */
#include "remote_wire.h"
static sl_remote *cm_protocol;
static char cm_connection;
static pthread_t cm_owner;
static unsigned cm_creates, cm_subscriptions, cm_packets, cm_notifications, cm_outer_tokens;
static bool cm_opened, cm_destroyed;
static uint8_t cm_queue[8][4096];
static size_t cm_sizes[8];
static unsigned cm_head, cm_tail;
static sl_proto_field cm_field(const uint8_t *wire, size_t size, unsigned number) {
    sl_proto_reader reader = {wire, size, 0, false};
    sl_proto_field f, result = {0};
    while (sl_proto_next(&reader, &f)) if (f.number == number) result = f;
    assert(sl_proto_done(&reader));
    return result;
}
static bool cm_send(const uint8_t *wire, size_t size, void *context) {
    (void)context;
    assert(pthread_equal(cm_owner, pthread_self()));
    if (cm_field(wire, size, 1).number) ++cm_creates;
    if (cm_field(wire, size, 5).number) ++cm_subscriptions;
    sl_proto_field remote = cm_field(wire, size, 7);
    if (remote.number) {
        assert(cm_field(remote.bytes, remote.size, 1).value == 1001);
        assert(cm_field(remote.bytes, remote.size, 2).value == UINT64_C(76561198000000001));
        sl_proto_field raw = cm_field(remote.bytes, remote.size, 4);
        assert(raw.size >= 16 && raw.size <= sizeof(cm_queue[0]) && cm_head-cm_tail < 8);
        uint32_t hs; IHS_ReadUInt32LE(raw.bytes+8, &hs); assert(hs <= raw.size-16);
        CMsgRemoteClientBroadcastHeader *h = cmsg_remote_client_broadcast_header__unpack(NULL, hs, raw.bytes+12);
        assert(h && h->has_device_token && h->device_token.len == 32);
        uint8_t plain[64], secret[32] = {0}; size_t count = sizeof(plain); uint64_t id;
        assert(!IHS_CryptoSymmetricDecrypt(h->device_token.data, h->device_token.len,
                                          secret, sizeof(secret), plain, &count) && count == 8);
        IHS_ReadUInt64LE(plain, &id); assert(id == 1); ++cm_outer_tokens;
        cmsg_remote_client_broadcast_header__free_unpacked(h, NULL);
        /* Service replies on a later manager update, never recursively from
         * SendRemote's final send while the old transaction is being visited. */
        memcpy(cm_queue[cm_head%8], raw.bytes, raw.size); cm_sizes[cm_head++%8] = raw.size;
        ++cm_packets;
    }
    return true;
}
static sl_remote_connection *cloud_fixture_create(const IHS_ClientConfig *config,
                                                  const sl_remote_callbacks *cb, void *ctx) {
    assert(!cm_protocol);
    cm_owner = pthread_self();
    sl_remote_callbacks callbacks = *cb; callbacks.send = cm_send;
    cm_protocol = sl_remote_create(config, &callbacks, ctx); assert(cm_protocol);
    return (sl_remote_connection *)&cm_connection;
}
sl_remote *__wrap_sl_remote_connection_protocol(sl_remote_connection *connection) {
    assert(connection == (sl_remote_connection *)&cm_connection);
    return cm_protocol;
}
static void cm_response(unsigned tag, const uint8_t *bytes, size_t size) {
    uint8_t envelope[4096]; sl_proto_writer writer = {envelope, 0, sizeof(envelope), false};
    sl_proto_uint(&writer, 1, 1); sl_proto_bytes(&writer, tag, bytes, size);
    assert(!writer.invalid && sl_remote_receive(cm_protocol, envelope, writer.size));
}
static void cloud_fixture_notify(const uint8_t *bytes, size_t size) {
    assert(pthread_equal(cm_owner, pthread_self()));
    uint8_t body[3072]; sl_proto_writer writer = {body, 0, sizeof(body), false};
    sl_proto_bytes(&writer, 1, bytes, size); assert(!writer.invalid);
    cm_response(6, body, writer.size); ++cm_notifications;
}
static void cloud_fixture_update(sl_remote_connection *connection, uint64_t now) {
    assert(connection == (sl_remote_connection *)&cm_connection && pthread_equal(cm_owner, pthread_self()));
    if (!cm_opened) {
        assert(sl_remote_open(cm_protocol));
        uint8_t body[32]; sl_proto_writer writer = {body, 0, sizeof(body), false};
        sl_proto_fixed64(&writer, 1, 1001); sl_proto_uint(&writer, 2, 1);
        cm_response(2, body, writer.size); assert(sl_remote_ready(cm_protocol));
        CMsgRemoteClientBroadcastStatus status = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
        status.hostname = "Cloud fixture host"; status.has_euniverse = true; status.euniverse = 1;
        CMsgRemoteClientBroadcastStatus__User user = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__USER__INIT;
        user.has_steamid = true; user.steamid = UINT64_C(76561198000000001);
        CMsgRemoteClientBroadcastStatus__User *users[] = {&user}; status.n_users = 1; status.users = users;
        control_reply(NULL, k_ERemoteClientBroadcastMsgStatus, &status.base);
        ++control_discoveries; cm_opened = true;
    }
    unsigned boundary = cm_head;
    while (cm_tail != boundary) {
        unsigned index = cm_tail++%8;
        control_receive_bytes(cm_queue[index], cm_sizes[index], NULL);
    }
    sl_remote_update(cm_protocol, now);
}
void __wrap_sl_remote_connection_describe(const sl_remote_connection *c, uint64_t now, char *out, size_t size) {
    (void)c; (void)now; snprintf(out, size, "controlled CM service");
}
void __wrap_sl_remote_connection_destroy(sl_remote_connection *c) {
    if (!c) return;
    assert(c == (sl_remote_connection *)&cm_connection && pthread_equal(cm_owner, pthread_self()));
    assert(cm_head == cm_tail);
    sl_remote_close(cm_protocol); sl_remote_destroy(cm_protocol); cm_protocol = NULL;
    cm_destroyed = true;
}

static unsigned sdk_creates, sdk_starts, sdk_destroys, sdk_sent, sdk_received;
static bool sdk_joins_clean = true;
#ifndef NSL_RECOVERY_REAL_SDK
typedef struct local_sdk {
    int fd;
    struct sockaddr_in peer;
    atomic_bool started;
    atomic_uint calls, sent, received;
} local_sdk;
sl_sns *__wrap_sl_sns_create_configured(const IHS_ClientConfig *c, const sl_remote_material *m,
    bool share, char *error, size_t error_size, const char *config, size_t config_size) {
    (void)error; (void)error_size; (void)config; (void)config_size;
    assert(pthread_equal(cm_owner, pthread_self()) && share && c->deviceId == 1);
    assert(m->client_id == 7 && m->steam_id == UINT64_C(76561198000000001) &&
           m->transport == k_EStreamTransportSDR && m->key_size == 32 && m->port == endpoint.port);
    assert(!strcmp(m->cert, "controlled-test-certificate") && !strcmp(m->stun_servers, "stun:fixture.invalid:3478"));
    assert(sdk_creates == sdk_destroys);
    local_sdk *s = calloc(1, sizeof(*s)); assert(s);
    s->fd = __real_socket(AF_INET, SOCK_DGRAM, 0); assert(s->fd >= 0);
    struct sockaddr_in bind_address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(s->fd, (void *)&bind_address, sizeof(bind_address)));
    assert(!fcntl(s->fd, F_SETFL, O_NONBLOCK));
    s->peer = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(m->port)};
    atomic_init(&s->started, false); atomic_init(&s->calls, 0); atomic_init(&s->sent, 0); atomic_init(&s->received, 0);
    ++sdk_creates; return (sl_sns *)s;
}
bool __wrap_sl_sns_start_session(sl_sns *opaque) {
    local_sdk *s = (void *)opaque;
    assert(pthread_equal(cm_owner, pthread_self()) && atomic_load(&launched));
    assert(!atomic_exchange(&s->started, true)); ++sdk_starts; return true;
}
bool __wrap_sl_sns_session_ready(const sl_sns *s) { assert(s); return true; }
sl_sns_state __wrap_sl_sns_get_state(const sl_sns *opaque) {
    const local_sdk *s = (const void *)opaque;
    return atomic_load(&s->started) ? SL_SNS_CONNECTED : SL_SNS_CONNECTING;
}
void __wrap_sl_sns_update(sl_sns *s, uint64_t now) { (void)s; (void)now; assert(pthread_equal(cm_owner, pthread_self())); }
int __wrap_sl_sns_end_reason(const sl_sns *s) { (void)s; return 0; }
void __wrap_sl_sns_get_stats(const sl_sns *opaque, sl_sns_stats *out) {
    const local_sdk *s = (const void *)opaque; *out = (sl_sns_stats){0};
    if (s) { out->datagrams_sent = atomic_load(&s->sent); out->datagrams_received = atomic_load(&s->received); }
    /* No authenticated/relayed SDK claim for an unencrypted local provider. */
}
static bool local_send(void *ctx, const uint8_t *bytes, size_t size) {
    local_sdk *s = ctx; atomic_fetch_add(&s->calls, 1);
    bool ok = atomic_load(&s->started) && sendto(s->fd, bytes, size, MSG_DONTWAIT,
                  (const void *)&s->peer, sizeof(s->peer)) == (ssize_t)size;
    if (ok) atomic_fetch_add(&s->sent, 1);
    atomic_fetch_sub(&s->calls, 1); return ok;
}
static int local_wait(void *ctx, uint32_t timeout_us) {
    local_sdk *s = ctx; atomic_fetch_add(&s->calls, 1);
    struct pollfd p = {.fd = s->fd, .events = POLLIN};
    int result = poll(&p, 1, (int)(((uint64_t)timeout_us+999)/1000));
    if (result < 0 && errno == EINTR) result = 0;
    atomic_fetch_sub(&s->calls, 1); return result;
}
static int local_receive(void *ctx, uint8_t *bytes, size_t capacity, size_t *received, uint32_t timeout_us) {
    local_sdk *s = ctx; (void)timeout_us; atomic_fetch_add(&s->calls, 1);
    ssize_t size = recv(s->fd, bytes, capacity, MSG_DONTWAIT | MSG_TRUNC);
    int result = size < 0 ? ((errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? 0 : -1)
                         : (size > (ssize_t)capacity ? -1 : 1);
    if (result == 1) { *received = (size_t)size; atomic_fetch_add(&s->received, 1); }
    atomic_fetch_sub(&s->calls, 1); return result;
}
const IHS_DatagramTransport *__wrap_sl_sns_datagram_transport(void) {
    static const IHS_DatagramTransport transport = {.send = local_send, .wait = local_wait,
        .receive = local_receive, .receiveCapacity = 65536};
    return &transport;
}
void __wrap_sl_sns_destroy(sl_sns *opaque) {
    if (!opaque) return;
    assert(pthread_equal(cm_owner, pthread_self()) && !atomic_load(&launched));
    local_sdk *s = (void *)opaque;
    sdk_joins_clean &= atomic_load(&s->calls) == 0;
    sdk_sent += atomic_load(&s->sent); sdk_received += atomic_load(&s->received);
    close(s->fd); free(s); ++sdk_destroys;
}
#else
bool loopback_sdk_session_live(void) { return atomic_load(&launched) != NULL; }
void loopback_sdk_counts(unsigned out[10]);
#endif
void cloud_fixture_projection(void) {
#ifdef NSL_RECOVERY_REAL_SDK
    unsigned counts[10]; loopback_sdk_counts(counts);
    sdk_creates=counts[0]; sdk_starts=counts[1]; sdk_destroys=counts[2];
    sdk_sent=counts[3]; sdk_received=counts[4]; sdk_joins_clean=counts[5] != 0;
    printf(",\"network_loopback_pairs\":%u,\"network_loopback_closed\":%u,\"network_peer_forwarded\":%u,\"network_client_delivered\":%u",
           counts[6], counts[7], counts[8], counts[9]);
#endif
    printf(",\"cm_creates\":%u,\"cm_subscriptions\":%u,\"cm_packets\":%u,\"cm_notifications\":%u,"
           "\"cm_outer_tokens\":%u,\"cm_destroyed\":%s,\"sdk_creates\":%u,\"sdk_starts\":%u,"
           "\"sdk_destroys\":%u,\"sdk_sent\":%u,\"sdk_received\":%u,\"sdk_joins_clean\":%s,"
           "\"cloud_ui_hosts\":%u,\"cloud_lan_hosts\":%u,\"cloud_udp_requests\":%u",
           cm_creates,cm_subscriptions,cm_packets,cm_notifications,cm_outer_tokens,cm_destroyed?"true":"false",
           sdk_creates,sdk_starts,sdk_destroys,sdk_sent,sdk_received,sdk_joins_clean?"true":"false",
           atomic_load(&cloud_ui_hosts),atomic_load(&cloud_lan_hosts),atomic_load(&cloud_udp_requests));
}
