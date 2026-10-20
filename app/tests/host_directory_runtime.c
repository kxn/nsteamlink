/* Actual IHS receive/protobuf dispatch/thread lifecycle -> production directory
 * -> UI events. recvfrom is the packet/source provider; no Steam or physical
 * reachability is proved. Cloud status enters through the production callback. */
#include "../platforms/common/runtime.c"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "client/discovery_pri.h"
#include "ui/ui_events.h"
#include <assert.h>
static bool test_cloud_online(sl_runtime *r, uint64_t id) {
    pthread_mutex_lock(&r->lock);
    const sl_directory_host *h = sl_directory_find(r->directory, id);
    bool cloud = h && h->cloud;
    pthread_mutex_unlock(&r->lock);
    return cloud;
}

static uint8_t packet[2048];
static size_t packet_size;
static atomic_bool pending;
static uint16_t source_port;
static atomic_bool stream_sent;
static atomic_bool directed_ids_sent;
static struct sockaddr_in stream_destination;
time_t __wrap_time(time_t *out) {
    if (out) *out = 1000;
    return 1000; /* Controlled wall clock, independent of receive-worker pacing. */
}
typedef struct { bool quiet; int64_t full, fast; uint32_t seq; } round_clock;
static void read_round(IHS_TimerTask *task, void *context) {
    round_clock *out = context;
    IHS_DiscoveryContext *d = IHS_TimerTaskGetContext(task);
    IHS_BaseLock(&d->client->base);
    *out = (round_clock){.quiet = !d->cycleActive && !d->commandCount && d->full != 0,
        .full = d->full, .fast = d->fast, .seq = d->client->discoverySeq};
    IHS_BaseUnlock(&d->client->base);
}
static round_clock settled(sl_runtime *r) {
    for (unsigned n = 0; n < 3000; ++n) {
        IHS_ClientPumpAuthorization(r->client, 32);
        round_clock snapshot = {0};
        IHS_TimerTaskVisitOwned(r->client->timers, &r->client->discoveryTimer, read_round, &snapshot);
        if (snapshot.quiet) return snapshot;
        usleep(1000);
    }
    assert(!"discovery owner did not settle");
    return (round_clock){0};
}
ssize_t __wrap_sendto(int fd, const void *data, size_t size, int flags,
                      const struct sockaddr *to, socklen_t length) {
    (void)fd; (void)flags;
    if (size >= 16) {
        const uint8_t *bytes = data;
        uint32_t hs;
        IHS_ReadUInt32LE(bytes+8, &hs);
        assert(hs <= size-16);
        CMsgRemoteClientBroadcastHeader *h =
            cmsg_remote_client_broadcast_header__unpack(NULL, hs, bytes+12);
        assert(h);
        if (h->msg_type == k_ERemoteDeviceStreamingRequest) {
            assert(length == sizeof(stream_destination) && to->sa_family == AF_INET);
            memcpy(&stream_destination, to, sizeof(stream_destination));
            atomic_store_explicit(&stream_sent, true, memory_order_release);
        } else if (h->msg_type == k_ERemoteClientBroadcastMsgDiscovery) {
            uint32_t length;
            IHS_ReadUInt32LE(bytes+12+hs, &length);
            assert(length == size-16-hs);
            CMsgRemoteClientBroadcastDiscovery *d =
                cmsg_remote_client_broadcast_discovery__unpack(NULL, length, bytes+16+hs);
            assert(d);
            if (d->n_client_ids == 3) {
                assert(d->client_ids[0] == 123 && d->client_ids[1] == 999 && d->client_ids[2] == 777);
                atomic_store_explicit(&directed_ids_sent, true, memory_order_release);
            }
            cmsg_remote_client_broadcast_discovery__free_unpacked(d, NULL);
        }
        cmsg_remote_client_broadcast_header__free_unpacked(h, NULL);
    }
    return (ssize_t)size; /* No actual traffic to synthetic candidate addresses. */
}
ssize_t __wrap_recvfrom(int fd, void *data, size_t capacity, int flags,
                        struct sockaddr *from, socklen_t *length) {
    (void)fd; (void)flags;
    if (!atomic_exchange_explicit(&pending, false, memory_order_acquire)) {
        errno = EAGAIN;
        return -1;
    }
    assert(capacity >= packet_size && *length >= sizeof(struct sockaddr_in));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(source_port)};
    assert(inet_pton(AF_INET, "10.0.0.8", &address.sin_addr) == 1);
    memcpy(from, &address, sizeof(address)); *length = sizeof(address);
    memcpy(data, packet, packet_size);
    return (ssize_t)packet_size;
}
static void send_status(bool offline) {
    assert(!atomic_load(&pending));
    static const uint8_t magic[] = {255,255,255,255,33,76,95,160};
    IHS_Buffer buffer = IHS_BUFFER_WRAP(packet, sizeof(packet));
    buffer.size = 0;
    IHS_BufferAppendMem(&buffer, magic, sizeof(magic));
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_instance_id = header.has_msg_type = true;
    header.client_id = 123; header.instance_id = 456;
    header.msg_type = offline ? k_ERemoteClientBroadcastMsgOffline : k_ERemoteClientBroadcastMsgStatus;
    size_t size = cmsg_remote_client_broadcast_header__get_packed_size(&header);
    IHS_BufferAppendUInt32LE(&buffer, size);
    buffer.size += cmsg_remote_client_broadcast_header__pack(&header, packet+buffer.size);
    char texts[20][24]; char *ips[22];
    for (int i = 0; i < 20; ++i) {
        snprintf(texts[i], sizeof(texts[i]), "192.0.2.%d", i+1);
        ips[i] = texts[i];
    }
    ips[20] = "0.0.0.0"; ips[21] = "::"; /* Parseable, but original HasIP rejects both. */
    CMsgRemoteClientBroadcastStatus status = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
    status.hostname = "directory fixture";
    status.n_ip_addresses = 22; status.ip_addresses = ips;
    status.public_ip_address = texts[0]; /* Same IP still gets the public marker. */
    size = offline ? 0 : cmsg_remote_client_broadcast_status__get_packed_size(&status);
    IHS_BufferAppendUInt32LE(&buffer, size);
    if (!offline) buffer.size += cmsg_remote_client_broadcast_status__pack(&status, packet+buffer.size);
    packet_size = buffer.size;
    atomic_store_explicit(&pending, true, memory_order_release);
}
static void wait_event(sl_runtime *r, sl_event_type type) {
    for (unsigned n = 0; n < 3000; ++n) {
        /* Same deferred update owner as the real runtime loop: draining the
         * authorization queue also completes the current discovery cycle. */
        IHS_ClientPumpAuthorization(r->client, 32);
        sl_runtime_event event;
        while (sl_runtime_poll(r, &event)) if (event.type == type) return;
        usleep(1000);
    }
    fprintf(stderr, "missing event=%d pending=%d size=%zu\n", (int)type,
            (int)atomic_load(&pending), packet_size);
    assert(!"missing parsed discovery event");
}
int main(void) {
    char data_dir[] = "/tmp/nsl-directory-XXXXXX";
    assert(mkdtemp(data_dir) && !setenv("NSL_DATA_DIR", data_dir, 1));
    IHS_Init();
    sl_runtime r = {0};
    assert(!pthread_mutex_init(&r.lock, NULL));
    assert(!pthread_cond_init(&r.wake, NULL));
    sl_host_registry_init(&r.store.registry);
    sl_host profile = {.client_id = 123, .instance_id = 456};
    strcpy(profile.address, "203.0.113.99");
    assert(sl_host_observe(&r.store.registry, &profile, 0));
    r.config = (IHS_ClientConfig){.deviceId = 42, .secretKey = r.store.secret,
                                 .deviceName = "directory fixture"};
    assert(sl_directory_ensure(&r.directory, 999)); /* Record order is not watch/send order. */
    assert(sl_directory_seed(&r.directory, 123, "203.0.113.99"));
    IHS_HostInfo direct;
    assert(!local_host(&r, 123, &direct)); /* Reloaded saved IP is not verified. */
    assert(start_client(&r));
    source_port = 31000;
    send_status(false);
    wait_event(&r, SL_EVENT_HOST);
    pthread_mutex_lock(&r.lock);
    sl_directory_host *h = sl_directory_find(r.directory, 123);
    assert(h && h->visible && !h->cloud && h->addresses.count == 21);
    /* First status removed the stale saved-only seed. All 20 announcements
     * survived, a duplicate public/private address retained its marker, and
     * only the actual source is verified. */
    size_t verified = 0, public_count = 0;
    for (size_t i = 0; i < h->addresses.count; ++i) {
        const sl_address_record *a = &h->addresses.entries[i];
        verified += a->verified; public_count += a->remote;
        char text[64]; sl_address_text(&a->address.ip, text);
        assert(strcmp(text, "203.0.113.99"));
    }
    assert(verified == 1 && public_count == 1);
    int64_t first = h->last_status;
    pthread_mutex_unlock(&r.lock);
    assert(local_host(&r, 123, &direct) && direct.address.port == 31000);
    round_clock before = settled(&r);
    assert(sync_discovery_targets(&r) && r.discovery_target_count == 21);
    round_clock after = settled(&r);
    assert(before.seq == after.seq && before.full == after.full && before.fast == after.fast);
    assert(sl_directory_seed(&r.directory, 999, "198.51.100.99"));
    profile.client_id = 999;
    strcpy(profile.address, "198.51.100.99");
    assert(sl_host_observe(&r.store.registry, &profile, 0));
    assert(sync_discovery_targets(&r));
    assert(r.discovery_targets[0].clientId == 123 &&
           r.discovery_targets[r.discovery_target_count-1].clientId == 999);
    after = settled(&r);
    assert(after.seq == before.seq+1); /* AddClientDiscovery, unlike an address update. */
    /* A watched device with no numeric address must still be carried in the
     * directed-client list, independently of all address entries. */
    profile.client_id = 777;
    profile.address[0] = 0;
    assert(sl_host_observe(&r.store.registry, &profile, 0));
    assert(sync_discovery_targets(&r));
    after = settled(&r);
    IHS_BaseLock(&r.client->base);
    assert(r.client->discoveryClientIdCount == 3);
    assert(r.client->discoveryClientIds[2] == 777);
    IHS_BaseUnlock(&r.client->base);
    assert(pause_discovery(&r));
    settled(&r);
    assert(IHS_ClientTriggerDiscovery(r.client));
    settled(&r);
    assert(atomic_load_explicit(&directed_ids_sent, memory_order_acquire));
    refresh_presence(&r, 5000, first+29);
    assert(local_host(&r, 123, &direct));
    pthread_mutex_lock(&r.lock); assert(h->visible); pthread_mutex_unlock(&r.lock);
    refresh_presence(&r, 10000, first+30);
    pthread_mutex_lock(&r.lock); assert(!h->visible); pthread_mutex_unlock(&r.lock);
    assert(local_host(&r, 123, &direct)); /* Visible expiry is not address expiry. */

    const char *cloud_ips[] = {"198.51.100.4", "198.51.100.5"};
    sl_remote_host cloud = {.info = {.clientId = 123, .instanceId = 456},
        .steam_id = 789, .addresses = cloud_ips, .address_count = 2,
        .public_address = cloud_ips[0]};
    strcpy(cloud.info.hostname, "cloud fixture");
    cloud_observed(&cloud, &r);
    pthread_mutex_lock(&r.lock); int64_t seen = h->last_status; pthread_mutex_unlock(&r.lock);
    refresh_presence(&r, 15000, seen+300);
    assert(test_cloud_online(&r, 123));
    pthread_mutex_lock(&r.lock); assert(h->visible); pthread_mutex_unlock(&r.lock);
    cloud_connected(false, &r);
    refresh_presence(&r, 20000, seen+29);
    pthread_mutex_lock(&r.lock); assert(h->visible); pthread_mutex_unlock(&r.lock);
    refresh_presence(&r, 25000, seen+30);
    pthread_mutex_lock(&r.lock); assert(!h->visible); pthread_mutex_unlock(&r.lock);

    cloud_observed(&cloud, &r);
    /* Discard earlier UI events, then exercise the actual parsed type2 path. */
    sl_runtime_event event;
    while (sl_runtime_poll(&r, &event)) {}
    send_status(true);
    wait_event(&r, SL_EVENT_HOST_OFFLINE);
    assert(!test_cloud_online(&r, 123) && local_host(&r, 123, &direct));
    source_port = 32000;
    send_status(false);
    wait_event(&r, SL_EVENT_HOST);
    assert(local_host(&r, 123, &direct) && direct.address.port == 32000);
    /* Exercise the actual request producer, not just the cache getter. An
     * obsolete UI address must not override either the selected IP or port. */
    r.active.type = SL_CMD_STREAM;
    r.active.host = (sl_host){.client_id = 123, .instance_id = 456, .account = 789};
    strcpy(r.active.host.address, "203.0.113.99");
    assert(sl_stream_settings_init(&r.settings, &r.store));
    assert(request_stream(&r, true));
    for (unsigned n = 0; n < 3000 && !atomic_load_explicit(&stream_sent, memory_order_acquire); ++n) {
        IHS_ClientPumpAuthorization(r.client, 32);
        usleep(1000);
    }
    assert(atomic_load_explicit(&stream_sent, memory_order_acquire));
    assert(ntohs(stream_destination.sin_port) == 32000);
    struct in_addr expected;
    assert(inet_pton(AF_INET, "10.0.0.8", &expected) == 1);
    assert(stream_destination.sin_addr.s_addr == expected.s_addr);
    uint64_t addressless = 777;
    assert(IHS_ClientSetDiscoveryDirectory(r.client, NULL, 0, &addressless, 1));
    settled(&r);
    IHS_BaseLock(&r.client->base);
    assert(!r.client->discoveryTargetCount && r.client->discoveryClientIdCount == 1 &&
           r.client->discoveryClientIds[0] == addressless);
    IHS_BaseUnlock(&r.client->base);
    stop_client(&r); /* Stop/join before directory/target storage destruction. */
    sl_stream_settings_destroy(&r.settings);
    sl_directory_destroy(&r.directory);
    pthread_cond_destroy(&r.wake);
    pthread_mutex_destroy(&r.lock);
    IHS_Quit();
    assert(!rmdir(data_dir));
    puts("PASS directory: raw status/Offline, 20 candidates, source port, first cleanup, 30s expiry, cloud exemption/disconnect, retained direct address");
    return 0;
}
