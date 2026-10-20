/* Production runtime directory + IHS threads/parser/transaction + CM framing.
 * UDP syscalls, CM connection/service and the final SNS constructor are explicit
 * providers. No real Steam, NAT, TLS, SDK connection or physical Switch runs. */
#include "../platforms/common/runtime.c"
#include "crypto.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "remote_wire.h"
#include <assert.h>
#include <dirent.h>
#include <sys/stat.h>

typedef struct recorded {
    unsigned kind;
    bool cloud;
    uint64_t session;
    struct sockaddr_in destination;
    size_t size;
    uint8_t wire[4096];
} recorded;
static recorded records[128];
static size_t record_count;
static pthread_mutex_t record_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_long wall = 1000;
static atomic_bool pending;
static uint8_t incoming_wire[4096];
static size_t incoming_size;
static const char *incoming_ip;
static uint16_t incoming_port;
static atomic_bool fresh_discovery;
static sl_remote *protocol;
static char opaque_connection;
static unsigned sns_calls;
static pthread_t owner;
static uint8_t media_key[16] = {7, 8, 9};
static uint64_t incoming_peer = 123;
time_t __wrap_time(time_t *out) {
    time_t now = atomic_load(&wall);
    if (out)
        *out = now;
    return now;
}
static sl_proto_field field(const void *data, size_t size, unsigned number) {
    sl_proto_reader reader = {data, size, 0, false};
    sl_proto_field f, found = {0};
    while (sl_proto_next(&reader, &f))
        if (f.number == number)
            found = f;
    assert(sl_proto_done(&reader));
    return found;
}
static void capture(const uint8_t *wire, size_t size, const struct sockaddr_in *to,
                    uint64_t session) {
    uint32_t hs;
    assert(size >= 16 && size <= sizeof(records[0].wire));
    IHS_ReadUInt32LE(wire + 8, &hs);
    assert(hs <= size - 16);
    unsigned kind = (unsigned)field(wire + 12, hs, 2).value;
    if (!kind) {
        struct in_addr expected;
        assert(inet_pton(AF_INET, "10.0.0.8", &expected) == 1);
        if (to && to->sin_addr.s_addr == expected.s_addr)
            atomic_store(&fresh_discovery, true);
        return;
    }
    pthread_mutex_lock(&record_lock);
    assert(record_count < 128);
    recorded *r = &records[record_count++];
    *r = (recorded){.kind = kind, .cloud = to == NULL, .session = session, .size = size};
    if (to)
        r->destination = *to;
    memcpy(r->wire, wire, size);
    pthread_mutex_unlock(&record_lock);
}
ssize_t __wrap_sendto(int fd, const void *wire, size_t size, int flags, const struct sockaddr *to,
                      socklen_t length) {
    (void)fd;
    (void)flags;
    assert(length == sizeof(struct sockaddr_in) && to->sa_family == AF_INET);
    capture(wire, size, (const struct sockaddr_in *)to, 0);
    return (ssize_t)size;
}
ssize_t __wrap_recvfrom(int fd, void *wire, size_t capacity, int flags, struct sockaddr *from,
                        socklen_t *length) {
    (void)fd;
    (void)flags;
    if (!atomic_exchange_explicit(&pending, false, memory_order_acquire)) {
        errno = EAGAIN;
        return -1;
    }
    assert(capacity >= incoming_size && *length >= sizeof(struct sockaddr_in));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(incoming_port)};
    assert(inet_pton(AF_INET, incoming_ip, &address.sin_addr) == 1);
    memcpy(from, &address, sizeof(address));
    *length = sizeof(address);
    memcpy(wire, incoming_wire, incoming_size);
    return (ssize_t)incoming_size;
}
static bool send_rpc(const uint8_t *wire, size_t size, void *ctx) {
    (void)ctx;
    assert(pthread_equal(owner, pthread_self())); /* CM is touched only by its owner. */
    sl_proto_field request = field(wire, size, 7);
    if (request.number) {
        assert(field(request.bytes, request.size, 2).value == 789);
        sl_proto_field packet = field(request.bytes, request.size, 4);
        capture(packet.bytes, packet.size, NULL, field(request.bytes, request.size, 1).value);
    }
    return true;
}
sl_remote_connection *__wrap_sl_remote_connection_create(const IHS_ClientConfig *config,
                                                         const sl_remote_callbacks *callbacks,
                                                         void *ctx) {
    assert(!protocol);
    sl_remote_callbacks cb = *callbacks;
    cb.send = send_rpc;
    protocol = sl_remote_create(config, &cb, ctx);
    assert(protocol);
    return (sl_remote_connection *)&opaque_connection;
}
sl_remote *__wrap_sl_remote_connection_protocol(sl_remote_connection *connection) {
    assert(connection == (sl_remote_connection *)&opaque_connection);
    return protocol;
}
void __wrap_sl_remote_connection_destroy(sl_remote_connection *connection) {
    assert(connection == (sl_remote_connection *)&opaque_connection);
    sl_remote_close(protocol);
    sl_remote_destroy(protocol);
    protocol = NULL;
}
#if NSL_HAVE_SNS
sl_sns *__wrap_sl_sns_create(const IHS_ClientConfig *config, const sl_remote_material *m,
                             bool allow_ice, char *error, size_t size) {
    (void)error;
    (void)size;
    assert(pthread_equal(owner, pthread_self()) && config->deviceId == 42 && allow_ice);
    assert(m->client_id == 123 && m->steam_id == 789 && m->transport == 4 &&
           m->key_size == sizeof(media_key) && !memcmp(m->key, media_key, sizeof(media_key)));
    assert(!strcmp(m->cert, "fixture-certificate") &&
           !strcmp(m->stun_servers, "stun:fixture.invalid:3478"));
    ++sns_calls;
    return NULL; /* Stop at material delivery, before SDK/socket creation. */
}
#endif
static bool response(unsigned kind, const uint8_t *body, size_t size) {
    uint8_t envelope[4608];
    sl_proto_writer out = {envelope, 0, sizeof(envelope), false};
    sl_proto_uint(&out, 1, 1);
    sl_proto_bytes(&out, kind, body, size);
    assert(!out.invalid);
    return sl_remote_receive(protocol, envelope, out.size);
}
static void open_cm(uint64_t session) {
    assert(sl_remote_open(protocol));
    uint8_t body[32];
    sl_proto_writer out = {body, 0, sizeof(body), false};
    sl_proto_fixed64(&out, 1, session);
    sl_proto_uint(&out, 2, 1);
    assert(response(2, body, out.size) && sl_remote_ready(protocol));
}
static size_t frame(uint8_t *wire, unsigned kind, const ProtobufCMessage *message) {
    static const uint8_t magic[] = {255, 255, 255, 255, 33, 76, 95, 160};
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_instance_id = header.has_msg_type = true;
    header.client_id = incoming_peer;
    header.instance_id = 456;
    header.msg_type = kind;
    memcpy(wire, magic, 8);
    size_t hs = protobuf_c_message_pack(&header.base, wire + 12);
    IHS_WriteUInt32LE(wire + 8, (uint32_t)hs);
    size_t ms = protobuf_c_message_pack(message, wire + 16 + hs);
    IHS_WriteUInt32LE(wire + 12 + hs, (uint32_t)ms);
    return hs + ms + 16;
}
static void cloud(unsigned kind, const ProtobufCMessage *message) {
    uint8_t wire[4096], body[4200];
    size_t size = frame(wire, kind, message);
    sl_proto_writer out = {body, 0, sizeof(body), false};
    sl_proto_bytes(&out, 1, wire, size);
    assert(response(6, body, out.size));
}
static void udp(unsigned kind, const ProtobufCMessage *message, const char *ip, uint16_t port) {
    assert(!atomic_load(&pending));
    incoming_size = frame(incoming_wire, kind, message);
    incoming_ip = ip;
    incoming_port = port;
    atomic_store_explicit(&pending, true, memory_order_release);
}
static void pump(sl_runtime *r) {
    IHS_ClientPumpAuthorization(r->client, 32);
    flush_control(r);
}
static size_t count(unsigned kind) {
    size_t n = 0;
    pthread_mutex_lock(&record_lock);
    for (size_t i = 0; i < record_count; ++i)
        n += records[i].kind == kind;
    pthread_mutex_unlock(&record_lock);
    return n;
}
static size_t queued_control(sl_runtime *r) {
    pthread_mutex_lock(&r->lock);
    size_t n = r->control_count;
    pthread_mutex_unlock(&r->lock);
    return n;
}
static recorded wait_send(sl_runtime *r, unsigned kind, size_t previous) {
    for (unsigned n = 0; n < 4000; ++n) {
        pump(r);
        pthread_mutex_lock(&record_lock);
        size_t seen = 0;
        for (size_t i = 0; i < record_count; ++i)
            if (records[i].kind == kind && ++seen > previous) {
                recorded out = records[i];
                pthread_mutex_unlock(&record_lock);
                return out;
            }
        pthread_mutex_unlock(&record_lock);
        usleep(1000);
    }
    fprintf(stderr, "missing send kind=%u previous=%zu wall=%ld\n", kind, previous,
            atomic_load(&wall));
    assert(!"control send timed out");
    return (recorded){0};
}
static sl_proto_field body(const recorded *r, sl_proto_field *header) {
    uint32_t hs, ms;
    IHS_ReadUInt32LE(r->wire + 8, &hs);
    IHS_ReadUInt32LE(r->wire + 12 + hs, &ms);
    assert(ms == r->size - 16 - hs);
    *header = (sl_proto_field){.bytes = r->wire + 12, .size = hs};
    return (sl_proto_field){.bytes = r->wire + 16 + hs, .size = ms};
}
static void decrypt_id(sl_proto_field token, const uint8_t key[32]) {
    uint8_t plain[64];
    size_t size = sizeof(plain);
    uint64_t id;
    assert(token.size == 32 &&
           !IHS_CryptoSymmetricDecrypt(token.bytes, token.size, key, 32, plain, &size));
    assert(size == 8);
    IHS_ReadUInt64LE(plain, &id);
    assert(id == 42);
}
static uint32_t request(const recorded *r, const uint8_t secret[32], const uint8_t *pin_cipher) {
    sl_proto_field h, b = body(r, &h);
    assert(field(h.bytes, h.size, 1).value == 42);
    sl_proto_field token = field(h.bytes, h.size, 5);
    if (r->cloud)
        decrypt_id(token, secret);
    else
        assert(!token.number);
    CMsgRemoteDeviceStreamingRequest *m =
        cmsg_remote_device_streaming_request__unpack(NULL, b.size, b.bytes);
    assert(m && m->request_id && m->client_id == 123 && m->device_token.len == 32);
    decrypt_id((sl_proto_field){.bytes = m->device_token.data, .size = m->device_token.len},
               secret);
    assert(m->n_supported_transport == (NSL_HAVE_SNS ? 2u : 1u) && m->supported_transport[0] == 1);
    if (NSL_HAVE_SNS)
        assert(m->supported_transport[1] == 4);
    assert(m->pin.len == 32);
    if (pin_cipher)
        assert(!memcmp(pin_cipher, m->pin.data, 32));
    uint32_t id = m->request_id;
    cmsg_remote_device_streaming_request__free_unpacked(m, NULL);
    return id;
}
static void destination(const recorded *r, const char *ip, uint16_t port) {
    struct in_addr expected;
    assert(inet_pton(AF_INET, ip, &expected) == 1);
    assert(!r->cloud && r->destination.sin_addr.s_addr == expected.s_addr &&
           ntohs(r->destination.sin_port) == port);
}
static void status(CMsgRemoteClientBroadcastStatus *s) {
    *s = (CMsgRemoteClientBroadcastStatus)CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
    s->hostname = "route fixture";
    s->has_euniverse = true;
    s->euniverse = IHS_SteamUniversePublic;
    static char *ips[] = {"192.0.2.11"};
    s->n_ip_addresses = 1;
    s->ip_addresses = ips;
}
static void wait_address(sl_runtime *r, const char *ip, uint16_t port) {
    IHS_IPAddress expected;
    assert(IHS_IPAddressFromString(&expected, ip));
    for (unsigned n = 0; n < 4000; ++n) {
        IHS_HostInfo host;
        if (local_host(r, 123, &host) && host.address.port == port &&
            !IHS_IPAddressCompare(&host.address.ip, &expected)) {
            pump(r);
            return;
        }
        pump(r);
        usleep(1000);
    }
    assert(!"status source was not published");
}
static void remove_fixture(const char *dir) {
    DIR *d = opendir(dir);
    assert(d);
    struct dirent *e;
    while ((e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            struct stat st;
            assert(!lstat(path, &st));
            if (S_ISDIR(st.st_mode))
                remove_fixture(path);
            else
                assert(!unlink(path));
        }
    assert(!closedir(d) && !rmdir(dir));
}
int main(void) {
    owner = pthread_self();
    char dir[] = "/tmp/nsl-control-route-XXXXXX";
    assert(mkdtemp(dir) && !setenv("NSL_DATA_DIR", dir, 1));
    IHS_Init();
    sl_runtime r = {0};
    assert(!pthread_mutex_init(&r.lock, NULL) && !pthread_cond_init(&r.wake, NULL));
    sl_host_registry_init(&r.store.registry);
    r.store.device_id = 42;
    uint8_t secret[32];
    for (unsigned i = 0; i < 32; ++i) {
        secret[i] = (uint8_t)(i + 3);
        r.store.secret[i] = (uint8_t)(i + 90);
    }
    strcpy(r.store.device_name, "route fixture");
    sl_host profile = {
        .client_id = 123, .instance_id = 456, .account = 789, .paired = true, .has_secret = true};
    memcpy(profile.secret, secret, 32);
    strcpy(profile.address, "203.0.113.99");
    sl_host *stored = sl_host_observe(&r.store.registry, &profile, 0);
    assert(stored);
    /* Observe cannot import pairing credentials; install persisted fields as
     * the actual profile loader does, separately from discovery metadata. */
    stored->paired = stored->has_secret = true;
    stored->account = profile.account;
    memcpy(stored->secret, secret, 32);
    r.active =
        (sl_command){.type = SL_CMD_STREAM, .generation = 1, .host = r.store.registry.hosts[0]};
    strcpy(r.active.text, "5678");
    r.config = (IHS_ClientConfig){
        .deviceId = 42, .secretKey = r.store.secret, .deviceName = "route fixture"};
    assert(sl_stream_settings_init(&r.settings, &r.store) && start_client(&r));
    start_cloud(&r);
    assert(r.control_peer_count == 1);
    open_cm(1001);
    CMsgRemoteClientBroadcastStatus s;
    status(&s);
    cloud(1, &s.base);
    IHS_HostInfo direct;
    assert(!local_host(&r, 123, &direct));
    assert(request_stream(&r, false));
    recorded first = wait_send(&r, 5, 0);
    uint32_t id = request(&first, secret, NULL);
    assert(first.cloud && first.session == 1001);
    sl_proto_field h, b = body(&first, &h), pin = field(b.bytes, b.size, 8);
    uint8_t pin_cipher[32];
    assert(pin.size == 32);
    memcpy(pin_cipher, pin.bytes, 32);
    CMsgRemoteDeviceStreamingResponse a = CMSG_REMOTE_DEVICE_STREAMING_RESPONSE__INIT;
    a.request_id = id;
    a.result = k_ERemoteDeviceStreamingBusy;
    cloud(6, &a.base);
    atomic_store(&wall, 1001);
    recorded retry = wait_send(&r, 5, 1);
    assert(retry.cloud && request(&retry, secret, pin_cipher) == id);
    a.result = k_ERemoteDeviceStreamingUnauthorized;
    cloud(6, &a.base);
    recorded auth = wait_send(&r, 3, 0);
    b = body(&auth, &h);
    assert(auth.cloud && field(b.bytes, b.size, 5).value == id);
    decrypt_id(field(h.bytes, h.size, 5), secret);
    CMsgRemoteDeviceAuthorizationResponse authorized =
        CMSG_REMOTE_DEVICE_AUTHORIZATION_RESPONSE__INIT;
    authorized.result = k_ERemoteDeviceAuthorizationInProgress;
    authorized.has_steamid = true;
    authorized.steamid = 789;
    cloud(4, &authorized.base);
    pump(&r);
    atomic_store(&wall, 1004);
    auth = wait_send(&r, 3, 1);
    b = body(&auth, &h);
    assert(field(b.bytes, b.size, 5).value == id);
    authorized.result = k_ERemoteDeviceAuthorizationSuccess;
    cloud(4, &authorized.base);
    retry = wait_send(&r, 5, 2);
    assert(request(&retry, secret, pin_cipher) == id);
    assert(IHS_ClientTriggerDiscovery(r.client));
    udp(1, &s.base, "10.0.0.8", 31000);
    wait_address(&r, "10.0.0.8", 31000);
    for (unsigned n = 0; n < 4000 && !atomic_load(&fresh_discovery); ++n) {
        pump(&r);
        usleep(1000);
    }
    assert(atomic_load(&fresh_discovery)); /* No actor sync published this address. */
    atomic_store(&wall, 1005);
    retry = wait_send(&r, 5, 3);
    destination(&retry, "10.0.0.8", 31000);
    assert(request(&retry, secret, pin_cipher) == id);
    udp(1, &s.base, "10.0.0.7", 32000);
    wait_address(&r, "10.0.0.7", 32000);
    atomic_store(&wall, 1006);
    retry = wait_send(&r, 5, 4);
    destination(&retry, "10.0.0.7", 32000);
    assert(request(&retry, secret, pin_cipher) == id);
    uint8_t challenge[] = {2, 7, 1, 8}, source[36], rotated[32];
    memcpy(source, secret, 32);
    memcpy(source + 32, challenge, 4);
    assert(!IHS_CryptoSHA256(source, sizeof(source), rotated));
    CMsgRemoteDeviceProofRequest proof = CMSG_REMOTE_DEVICE_PROOF_REQUEST__INIT;
    proof.challenge = (ProtobufCBinaryData){sizeof(challenge), challenge};
    proof.has_request_id = proof.has_update_secret = true;
    proof.request_id = id;
    proof.update_secret = true;
    udp(7, &proof.base, "10.0.0.9", 35000);
    recorded answer = wait_send(&r, 8, 0);
    destination(&answer, "10.0.0.9", 35000);
    uint8_t saved[32];
    assert(!sl_host_key_load(dir, 123, 789, saved) && !memcmp(saved, rotated, 32));
    atomic_store(&wall, 1007);
    retry = wait_send(&r, 5, 5);
    assert(request(&retry, rotated, pin_cipher) == id);
    /* Controlled empty-cache provider input, not an invented NAT/TTL policy. */
    pthread_mutex_lock(&r.lock);
    sl_addresses_destroy(&sl_directory_find(r.directory, 123)->addresses);
    sl_directory_disconnect(r.directory); /* Cloud membership is not send eligibility. */
    pthread_mutex_unlock(&r.lock);
    atomic_store(&wall, 1008);
    retry = wait_send(&r, 5, 6);
    assert(retry.cloud && request(&retry, rotated, pin_cipher) == id);
    atomic_store(&wall, 1009);
    for (unsigned n = 0; n < 4000 && !queued_control(&r); ++n) {
        IHS_ClientPumpAuthorization(r.client, 32);
        usleep(1000);
    }
    assert(queued_control(&r) == 1);
    size_t before = count(5);
    sl_remote_close(protocol);
    assert(!r.control_count);
    open_cm(1002);
    flush_control(&r);
    assert(count(5) == before);
    atomic_store(&wall, 1010);
    retry = wait_send(&r, 5, before);
    assert(retry.cloud && retry.session == 1002 && request(&retry, rotated, pin_cipher) == id);
    uint8_t encrypted[64];
    size_t encrypted_size = sizeof(encrypted);
    assert(!IHS_CryptoSymmetricEncrypt(media_key, sizeof(media_key), rotated, 32, encrypted,
                                       &encrypted_size));
    a.result = k_ERemoteDeviceStreamingSuccess;
    a.has_port = a.has_encrypted_session_key = true;
    a.port = 27031;
    a.encrypted_session_key = (ProtobufCBinaryData){encrypted_size, encrypted};
    /* Original success admission uses request_id, while the session's account
     * and physical endpoint come from the actual reply, not the selected host. */
    sl_host reply_peer = {.client_id = 321};
    stored = sl_host_observe(&r.store.registry, &reply_peer, 0);
    assert(stored);
    stored->account = 987;
    incoming_peer = 321;
    udp(6, &a.base, "10.0.0.9", 35001);
    for (unsigned n = 0; n < 4000 && !r.session_ready; ++n) {
        pump(&r);
        usleep(1000);
    }
    assert(r.session_ready && r.session_info.address.port == 27031 &&
           r.session_info.sessionKeyLen == 16 && r.session_info.steamId == 987);
    incoming_peer = 123;
    IHS_IPAddress actual;
    assert(IHS_IPAddressFromString(&actual, "10.0.0.9"));
    assert(!IHS_IPAddressCompare(&r.session_info.address.ip, &actual));
    IHS_ClientStreamingCancel(r.client);
    pump(&r);
    r.session_ready = false;
    udp(1, &s.base, "10.0.0.7", 32000);
    wait_address(&r, "10.0.0.7", 32000);
    before = count(5);
    assert(request_stream(&r, false));
    retry = wait_send(&r, 5, before);
    uint32_t next = request(&retry, rotated, NULL);
    assert(next != id && !retry.cloud);
    a.request_id = next;
    a.has_transport = true;
    a.transport = k_EStreamTransportSDR;
    a.cert = "fixture-certificate";
    a.relay_server = "stun:fixture.invalid:3478";
    cloud(6, &a.base);
    pump(&r);
    assert(sns_calls == (NSL_HAVE_SNS ? 1u : 0u) && !r.session_ready);
#if NSL_HAVE_SNS
    assert(!r.sns_waiting);
#endif
    cloud_offline(123, &r);
    before = count(10);
    IHS_ClientStreamingCancel(r.client);
    pump(&r);
    assert(count(10) == before); /* Invisible target/hint absence suppresses cancel. */
    /* Late InProgress is an explicit response to this source, even without a
     * selected/visible/cached peer and even for zero request_id. */
    incoming_peer = 999;
    a.request_id = 0;
    a.result = k_ERemoteDeviceStreamingInProgress;
    udp(6, &a.base, "192.0.2.99", 35099);
    recorded late = wait_send(&r, 10, before);
    destination(&late, "192.0.2.99", 35099);
    b = body(&late, &h);
    assert(field(b.bytes, b.size, 1).value == 0);
    incoming_peer = 123;
    /* Standalone authorization really produces from the timer thread. Do not
     * pump the actor until its copied frame exists; send_rpc still asserts that
     * only this actor touches the actual CM/service boundary. */
    cloud(1, &s.base);
    pthread_mutex_lock(&r.lock);
    sl_addresses_destroy(&sl_directory_find(r.directory, 123)->addresses);
    pthread_mutex_unlock(&r.lock);
    IHS_HostInfo authorization_host;
    assert(control_host(r.client, 123, &authorization_host, &r));
    before = count(3);
    assert(IHS_ClientAuthorizationRequest(r.client, &authorization_host, "1234"));
    for (unsigned n = 0; n < 4000 && !queued_control(&r); ++n)
        usleep(1000);
    assert(queued_control(&r) == 1 && count(3) == before);
    auth = wait_send(&r, 3, before);
    assert(auth.cloud);
    b = body(&auth, &h);
    decrypt_id(field(h.bytes, h.size, 5), rotated);
    before = count(9);
    assert(IHS_ClientAuthorizationCancel(r.client));
    recorded canceled_authorization = wait_send(&r, 9, before);
    assert(canceled_authorization.cloud);
    stop_client(&r);
    flush_control(&r);
    __wrap_sl_remote_connection_destroy(r.remote);
    r.remote = NULL;
    clear_control_locked(&r);
    sl_stream_settings_destroy(&r.settings);
    sl_directory_destroy(&r.directory);
    pthread_cond_destroy(&r.wake);
    pthread_mutex_destroy(&r.lock);
    IHS_Quit();
    remove_fixture(dir);
    puts("PASS one control owner: CM/UDP retries, reauthorization, live discovery/source, proof "
         "key/PIN, CM epoch, reply identity, explicit late cancel and SDR material");
    return 0;
}
