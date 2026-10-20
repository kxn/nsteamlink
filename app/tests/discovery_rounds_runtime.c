#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "client/discovery_pri.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "protobuf/discovery.pb-c.h"
#include "protobuf/pb_utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Real client/RX/timer/owned task/UDP/protobuf/cleanup. Only wall time, RNG
 * boundary choices, broadcast enumeration and sendto outcomes are adapters.
 * No fixture datagram can leave for a LAN. */
static atomic_llong wall = 1000;
static atomic_uint time_reads;
static unsigned minimum_reads;
static bool upper, failure;
static _Thread_local bool target_alloc_fault;
static unsigned allocation_failures;
static bool nested_case, external_case, deferred_case, initial_receive;
static const char *mode;
static atomic_int client_fd = -1;
static atomic_bool received_status;
static atomic_bool callback_entered, release_callback;
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size) {
    if (target_alloc_fault) { ++allocation_failures; return NULL; }
    return __real_malloc(size);
}
/* Test-only barrier holds the real receive worker before its first Update.
 * No substitute timer/receiver is used, and the owned thread is still joined. */
static bool order_case;
static atomic_bool release_watcher;
static IHS_ThreadFunction *watcher_function;
static void *watcher_context;
IHS_Thread *__real_IHS_ThreadCreate(IHS_ThreadFunction *, const char *, void *);
static void held_watcher(void *unused) {
    (void)unused;
    while (!atomic_load(&release_watcher)) usleep(1000);
    watcher_function(watcher_context);
}
IHS_Thread *__wrap_IHS_ThreadCreate(IHS_ThreadFunction *function, const char *name, void *context) {
    if (order_case && !strcmp(name, "IHSClient")) {
        watcher_function = function;
        watcher_context = context;
        return __real_IHS_ThreadCreate(held_watcher, name, NULL);
    }
    return __real_IHS_ThreadCreate(function, name, context);
}
/* Bind the real first UDP socket before the held worker starts; this lets a
 * real Status already be queued when Enable's first read begins. */
int __real_socket(int, int, int);
int __wrap_socket(int family, int type, int protocol) {
    int fd = __real_socket(family, type, protocol);
    if (initial_receive && atomic_load(&client_fd) < 0 && family == AF_INET && type == SOCK_DGRAM) {
        struct sockaddr_in local = {.sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
        if (fd < 0 || bind(fd, (void *)&local, sizeof(local))) abort();
        atomic_store(&client_fd, fd);
    }
    return fd;
}
static unsigned sends;
static char wires[128][4096];
static uint32_t destinations[128];
static void require(bool value, const char *why) {
    if (!value) { fprintf(stderr, "round probe: %s\n", why); abort(); }
}
time_t __wrap_time(time_t *out) {
    time_t value = (time_t)atomic_load(&wall);
    if (out) *out = value;
    atomic_fetch_add(&time_reads, 1);
    return value;
}
pid_t __wrap_getpid(void) { return 77; }
int __real_IHS_DiscoveryRandomInt(IHS_DiscoveryRandom *, int, int);
int __wrap_IHS_DiscoveryRandomInt(IHS_DiscoveryRandom *random, int low, int high) {
    (void)random;
    require((low == 1 && (high == 3 || high == 5)) || (low == 4 && high == 7),
            "official discovery random ranges");
    return upper ? high : low;
}
size_t __wrap_IHS_UDPBroadcastAddresses(IHS_IPAddress *out, size_t capacity) {
    (void)out; (void)capacity;
    return 0;
}
ssize_t __wrap_sendto(int fd, const void *data, size_t size, int flags,
                     const struct sockaddr *to, socklen_t length) {
    if (nested_case && atomic_load(&client_fd) < 0) {
        struct sockaddr_in local = {.sin_family = AF_INET};
        socklen_t local_size = sizeof(local);
        require(!getsockname(fd, (void *)&local, &local_size), "actual client socket endpoint");
        if (!local.sin_port) {
            local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            require(!bind(fd, (void *)&local, sizeof(local)), "actual loopback receive binding");
        }
        atomic_store(&client_fd, fd);
    }
    const struct sockaddr_in *address = (const void *)to;
    require(length == sizeof(*address) && address->sin_family == AF_INET &&
                ntohs(address->sin_port) == 27036 && (flags & MSG_DONTWAIT),
            "bounded discovery send to official port");
    require(sends < 128 && size * 2 + 1 <= sizeof(wires[0]), "bounded wire capture");
    for (size_t i = 0; i < size; ++i)
        snprintf(wires[sends] + 2 * i, 3, "%02x", ((const unsigned char *)data)[i]);
    destinations[sends++] = ntohl(address->sin_addr.s_addr);
    if (failure) { errno = EIO; return -1; }
    return (ssize_t)size;
}

typedef struct Snapshot {
    IHS_Client *client;
    unsigned tries, owners, sends;
    uint32_t sequence;
    int64_t full, fast;
    bool pending;
} Snapshot;
static void inspect(IHS_TimerTask *task, void *opaque) {
    Snapshot *snapshot = opaque;
    const IHS_DiscoveryContext *context = IHS_TimerTaskGetContext(task);
    IHS_BaseLock(&snapshot->client->base);
    snapshot->full = context->full;
    snapshot->fast = context->fast;
    snapshot->tries = context->tries;
    snapshot->owners = context->broadcastOwners;
    snapshot->sequence = snapshot->client->discoverySeq;
    snapshot->sends = sends;
    snapshot->pending = context->commandCount || context->cycleActive ||
                        snapshot->client->discoveryTargetsChanged;
    IHS_BaseUnlock(&snapshot->client->base);
}
/* Native-only backlog/resource contracts; not claimed as official queue size. */
static void inspect_full_backlog(IHS_TimerTask *task, void *opaque) {
    IHS_Client *client = opaque;
    const IHS_DiscoveryContext *context = IHS_TimerTaskGetContext(task);
    IHS_BaseLock(&client->base);
    require(context->commandCount == IHS_DISCOVERY_COMMAND_CAPACITY &&
            context->acceptedOwners == 1 && !context->broadcastOwners &&
            context->queuedTargets == IHS_DISCOVERY_COMMAND_CAPACITY / 2 &&
            !client->discoveryTargets && !client->discoveryTargetCount &&
            !client->discoveryTargetsChanged && !context->cycleActive,
            "full backlog rejection preserves accepted refs and committed targets");
    unsigned targets = 0;
    for (unsigned i=0; i<context->commandCount; ++i) {
        const IHS_DiscoveryCommand *command = &context->commands[
            (context->commandHead+i) % IHS_DISCOVERY_COMMAND_CAPACITY];
        if (command->operation != IHS_DiscoveryTargets) continue;
        ++targets;
        require(command->count == 1 && command->idCount == 1 &&
                command->targets[0].clientId == targets,
                "queued target bytes owned independently from caller");
    }
    require(context->desiredCount == 1 && context->desiredTargets[0].clientId == targets,
            "desired snapshot aliases last owned queue entry");
    IHS_BaseUnlock(&client->base);
}
static void inspect_wrapped_backlog(IHS_TimerTask *task, void *opaque) {
    IHS_Client *client = opaque;
    const IHS_DiscoveryContext *context = IHS_TimerTaskGetContext(task);
    IHS_BaseLock(&client->base);
    require(!context->commandCount && !context->queuedTargets &&
            context->acceptedOwners == 1 && context->broadcastOwners == 1 &&
            client->discoverySeq == IHS_DISCOVERY_COMMAND_CAPACITY+10,
            "wrapped ring preserves command identity and owner count");
    IHS_BaseUnlock(&client->base);
}
static void fill_backlog(IHS_Client *client) {
    require(IHS_ClientEnableDiscovery(client), "initial queued Enable");
    IHS_DiscoveryTarget target = {.clientId=1};
    require(IHS_IPAddressFromString(&target.ip, "127.0.0.1"), "backlog target");
    target_alloc_fault = true;
    require(!IHS_ClientSetDiscoveryTargets(client, &target, 1), "queued snapshot allocation failure");
    target_alloc_fault = false;
    require(allocation_failures == 1, "queued target allocator actually failed");
    for (unsigned n=1; n<=IHS_DISCOVERY_COMMAND_CAPACITY/2; ++n) {
        target.clientId = n;
        require(IHS_ClientSetDiscoveryTargets(client, &target, 1), "owned queued target accepted");
        if (n<IHS_DISCOVERY_COMMAND_CAPACITY/2)
            require(IHS_ClientTriggerDiscovery(client), "independent queued Trigger accepted");
    }
    require(IHS_ClientSetDiscoveryTargets(client, &target, 1), "identical desired snapshot needs no queue slot");
    ++target.clientId;
    require(!IHS_ClientSetDiscoveryTargets(client, &target, 1) &&
            !IHS_ClientEnableDiscovery(client) && !IHS_ClientDisableDiscovery(client) &&
            !IHS_ClientTriggerDiscovery(client), "all full-backlog mutations rejected atomically");
    require(IHS_TimerTaskVisitOwned(client->timers, &client->discoveryTimer,
            inspect_full_backlog, client), "inspect live backlog before cancellation");
}
static bool first = true;
static void snapshot(IHS_Client *client, bool wait) {
    Snapshot row = {.client = client};
    for (unsigned poll = 0;; ++poll) {
        require(poll < 5000, "bounded accepted operation drain");
        if (deferred_case) IHS_ClientPumpAuthorization(client, 1);
        require(IHS_TimerTaskVisitOwned(client->timers, &client->discoveryTimer, inspect, &row),
                "live task snapshot after actual callback completion");
        if (!row.pending && (!wait || atomic_load(&time_reads) >= minimum_reads)) break;
        usleep(1000);
    }
    printf("%s{\"sequence\":%u,\"next_status\":%lld,\"fast_status\":%lld,"
           "\"status_tries\":%u,\"broadcast_owners\":%u,\"wires\":[",
           first ? "" : ",", row.sequence, (long long)row.full, (long long)row.fast,
           row.tries, row.owners);
    for (unsigned i = 0; i < row.sends; ++i) printf("%s\"%s\"", i ? "," : "", wires[i]);
    printf("],\"destinations\":[");
    for (unsigned i = 0; i < row.sends; ++i) printf("%s%u", i ? "," : "", destinations[i]);
    printf("]}");
    first = false;
}
static void update(IHS_Client *client, int64_t now) {
    minimum_reads = atomic_load(&time_reads) + 1;
    atomic_store(&wall, now);
    snapshot(client, true);
}
static void enable(IHS_Client *client) {
    minimum_reads = atomic_load(&time_reads) + 1;
    require(IHS_ClientEnableDiscovery(client), "Enable owned manager");
    snapshot(client, true);
}
static void trigger(IHS_Client *client) {
    minimum_reads = atomic_load(&time_reads) + 1;
    require(IHS_ClientTriggerDiscovery(client), "Trigger existing manager");
    snapshot(client, true);
}
static void disable(IHS_Client *client) {
    require(IHS_ClientDisableDiscovery(client), "balanced Disable");
    snapshot(client, false);
}
static void nested_status(IHS_Client *client, const IHS_HostInfo *host, void *unused) {
    (void)unused;
    require(host->clientId == 123 && host->instanceId == 456 &&
            host->hasGamesRunning && !host->gamesRunning, "actual parsed loopback Status");
    if (initial_receive && !strcmp(mode, "first_receive_disables_owner")) {
        require(IHS_ClientDisableDiscovery(client), "nested Disable sees current applied Enable");
    } else if (initial_receive && !strcmp(mode, "first_receive_adds_targets")) {
        IHS_DiscoveryTarget targets[2] = {{.clientId=123}, {.clientId=123}};
        require(IHS_IPAddressFromString(&targets[0].ip, "127.0.0.1") &&
                IHS_IPAddressFromString(&targets[1].ip, "127.0.0.2"), "nested targets");
        require(IHS_ClientSetDiscoveryTargets(client, targets, 2), "nested targets applied in current Update");
    } else if (external_case) {
        atomic_store(&callback_entered, true);
        while (!atomic_load(&release_callback)) usleep(1000);
    } else {
        require(IHS_ClientTriggerDiscovery(client) && IHS_ClientTriggerDiscovery(client),
                "two accepted triggers in one actual RX callback");
    }
    atomic_store(&received_status, true);
}
void __real_IHS_ClientStreamingCallback(IHS_Client *, const IHS_SocketAddress *,
    CMsgRemoteClientBroadcastHeader *, ProtobufCMessage *);
void __wrap_IHS_ClientStreamingCallback(IHS_Client *client, const IHS_SocketAddress *address,
    CMsgRemoteClientBroadcastHeader *header, ProtobufCMessage *message) {
    __real_IHS_ClientStreamingCallback(client, address, header, message);
    if (deferred_case) {
        require(header->msg_type == k_ERemoteDeviceStreamingProgress &&
                ((CMsgRemoteDeviceStreamingProgress *)message)->request_id == 1,
                "actual parsed/dequeued StreamingProgress handler");
        require(IHS_ClientTriggerDiscovery(client) && IHS_ClientTriggerDiscovery(client),
                "two accepted triggers inside actual deferred dispatch");
        atomic_store(&received_status, true);
    }
}
ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static void deliver_status(IHS_Client *client) {
    minimum_reads = atomic_load(&time_reads) + 1;
    int peer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    require(peer >= 0, "actual status peer");
    struct sockaddr_in destination;
    socklen_t length = sizeof(destination);
    require(!getsockname(atomic_load(&client_fd), (void *)&destination, &length) &&
            destination.sin_port, "actual bound client port");
    destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_instance_id = header.has_msg_type = true;
    header.client_id = 123; header.instance_id = 456; header.msg_type = k_ERemoteClientBroadcastMsgStatus;
    CMsgRemoteClientBroadcastStatus status = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
    status.hostname = "nested fixture"; status.has_games_running = true; status.games_running = false;
    CMsgRemoteDeviceStreamingProgress progress = CMSG_REMOTE_DEVICE_STREAMING_PROGRESS__INIT;
    progress.request_id = 1;
    ProtobufCMessage *payload = (void *)&status;
    if (deferred_case) {
        header.msg_type = k_ERemoteDeviceStreamingProgress;
        payload = (void *)&progress;
    }
    unsigned char bytes[512];
    IHS_Buffer packet = IHS_BUFFER_WRAP(bytes, sizeof(bytes));
    packet.size = 0;
    const unsigned char magic[] = {255,255,255,255,0x21,0x4c,0x5f,0xa0};
    IHS_BufferAppendMem(&packet, magic, sizeof(magic));
    IHS_BufferAppendUInt32LE(&packet, cmsg_remote_client_broadcast_header__get_packed_size(&header));
    IHS_BufferAppendMessage(&packet, (void *)&header);
    IHS_BufferAppendUInt32LE(&packet, protobuf_c_message_get_packed_size(payload));
    IHS_BufferAppendMessage(&packet, payload);
    require(__real_sendto(peer, bytes, packet.size, 0, (void *)&destination, sizeof(destination)) ==
            (ssize_t)packet.size, "actual loopback Status sent");
    bool ready = initial_receive;
    for (unsigned i = 0; i < 3000 && !ready; ++i) {
        if (deferred_case) {
            IHS_BaseLock(&client->base);
            ready = client->authorizationCount != 0;
            IHS_BaseUnlock(&client->base);
        } else ready = atomic_load(external_case ? &callback_entered : &received_status);
        if (!ready) usleep(1000);
    }
    require(ready, "actual parsed callback/queue reached controlled boundary");
    close(peer);
}
static void rng(void) {
    const int32_t seeds[] = {1, 17, 1234567, 0, -1, INT32_MAX, INT32_MIN};
    printf("{\"random\":[");
    for (unsigned i = 0; i < sizeof(seeds)/sizeof(seeds[0]); ++i) {
        IHS_DiscoveryRandom random = {0};
        IHS_DiscoveryRandomSeed(&random, seeds[i]);
        printf("%s{\"explicit_seed\":%d,\"samples\":[", i ? "," : "", seeds[i]);
        const int lows[] = {1, 1, 4}, highs[] = {5, 3, 7};
        for (unsigned j = 0; j < 3; ++j) {
            printf("%s{\"range\":[%d,%d],\"values\":[", j ? "," : "", lows[j], highs[j]);
            for (unsigned k = 0; k < 128; ++k)
                printf("%s%d", k ? "," : "", __real_IHS_DiscoveryRandomInt(&random, lows[j], highs[j]));
            printf("]}");
        }
        printf("]}");
    }
    printf("],\"forced\":[");
    bool first_case = true;
    const int bounds[] = {3, 5};
    for (unsigned i = 0; i < 2; ++i) {
        int high = bounds[i];
        uint32_t limit = INT32_MAX - (0x80000000u % (unsigned)high);
        for (unsigned offset = 0; offset < 2; ++offset) {
            IHS_DiscoveryRandom random = {.seed = 1, .previous = 1};
            random.shuffle[0] = (int32_t)(limit + offset);
            random.shuffle[31] = 7;
            int value = __real_IHS_DiscoveryRandomInt(&random, 1, high);
            printf("%s{\"high\":%d,\"first\":%u,\"result\":%d,\"seed\":%d,"
                   "\"previous\":%d,\"table0\":%d,\"table31\":%d}",
                   first_case ? "" : ",", high, limit + offset, value, random.seed,
                   random.previous, random.shuffle[0], random.shuffle[31]);
            first_case = false;
        }
    }
    printf("]}\n");
}
int main(int argc, char **argv) {
    require(argc == 2, "named program");
    if (!strcmp(argv[1], "random")) { rng(); return 0; }
    alarm(20);
    mode = argv[1];
    initial_receive = !strncmp(mode, "first_receive_", 14);
    order_case = initial_receive || !strcmp(mode, "backlog_cancel") || !strcmp(argv[1], "enable_disable_before_watch") ||
                 !strcmp(argv[1], "owner_flip_before_watch") ||
                 !strcmp(argv[1], "enable_targets_before_watch");
    IHS_Init();
    unsigned char secret[32] = {0};
    IHS_ClientConfig config = {.deviceId = 42, .deviceName = "round fixture", .secretKey = secret};
    IHS_Client *client = IHS_ClientCreate(&config);
    require(client != NULL, "actual client and workers");
    printf("{\"stages\":[");
    external_case = !strcmp(mode, "external_trigger_during_receive");
    deferred_case = !strcmp(mode, "nested_deferred_trigger");
    nested_case = initial_receive || external_case || deferred_case || !strcmp(mode, "nested_receive_trigger");
    const IHS_ClientDiscoveryCallbacks callbacks = {.discovered = nested_status};
    if (nested_case) IHS_ClientSetDiscoveryCallbacks(client, &callbacks, NULL);
    if (!strcmp(mode, "backlog_cancel")) {
        fill_backlog(client);
    } else if (!strcmp(mode, "backlog_wrap")) {
        enable(client);
        for (unsigned i=0; i<IHS_DISCOVERY_COMMAND_CAPACITY+8; ++i) trigger(client);
        require(sends == IHS_DISCOVERY_COMMAND_CAPACITY+9, "ring wrap preserves every full round");
        require(IHS_TimerTaskVisitOwned(client->timers, &client->discoveryTimer,
                inspect_wrapped_backlog, client), "inspect wrapped live ring");
    } else if (order_case) {
        minimum_reads = atomic_load(&time_reads) + 1;
        require(IHS_ClientEnableDiscovery(client), "accepted Enable before watcher");
        if (initial_receive) {
            if (!strcmp(mode, "first_receive_triggers_before_queued_disable"))
                require(IHS_ClientDisableDiscovery(client), "future Disable queued after first Enable");
            deliver_status(client);
        } else if (!strcmp(mode, "enable_targets_before_watch")) {
            IHS_DiscoveryTarget targets[2] = {{.clientId=123}, {.clientId=123}};
            require(IHS_IPAddressFromString(&targets[0].ip, "127.0.0.1") &&
                    IHS_IPAddressFromString(&targets[1].ip, "127.0.0.2"), "ordered target input");
            require(IHS_ClientSetDiscoveryTargets(client, targets, 2), "accepted target update after Enable");
        } else {
            require(IHS_ClientDisableDiscovery(client), "accepted Disable after Enable");
            if (!strcmp(mode, "owner_flip_before_watch"))
                require(IHS_ClientTriggerDiscovery(client) && IHS_ClientEnableDiscovery(client),
                        "accepted Trigger then re-Enable");
        }
        atomic_store(&release_watcher, true);
        if (initial_receive) {
            for (unsigned i=0; i<3000 && !atomic_load(&received_status); ++i) usleep(1000);
            require(atomic_load(&received_status), "actual first receive callback completed");
        }
        snapshot(client, true);
    } else if (!strcmp(mode, "wall_backwards_same_tick_and_fast_cap")) {
        enable(client); update(client,999); update(client,1000); update(client,1001);
        update(client,1001); update(client,1005); update(client,1012); update(client,1013);
    } else if (!strcmp(mode, "late_fast_is_single_and_reschedules_from_now")) {
        enable(client); update(client,1004); update(client,1004); update(client,1007); update(client,1008);
    } else if (!strcmp(mode, "full_priority_and_large_forward_jump_no_catchup")) {
        enable(client); update(client,1040); update(client,1040); update(client,1041);
    } else if (!strcmp(mode, "same_tick_trigger_forces_full_without_owner_increment")) {
        enable(client); trigger(client); trigger(client);
    } else if (!strcmp(mode, "independent_trigger_burst")) {
        enable(client);
        require(IHS_ClientTriggerDiscovery(client) && IHS_ClientTriggerDiscovery(client),
                "two independent triggers accepted before another timer tick");
        snapshot(client, true);
    } else if (nested_case) {
        if (deferred_case) IHS_ClientSetAuthorizationDeferred(client, true);
        enable(client); deliver_status(client);
        if (external_case) {
            require(IHS_ClientTriggerDiscovery(client) && IHS_ClientTriggerDiscovery(client),
                    "external thread refreshes during a live RX callback");
            atomic_store(&release_callback, true);
        }
        if (deferred_case)
            require(IHS_ClientPumpAuthorization(client, 1) == 1 && atomic_load(&received_status),
                    "actual one queued Progress callback pumped");
        snapshot(client, true);
    } else if (!strcmp(mode, "trigger_without_owner_updates_schedule_but_no_broadcast")) {
        /* Trigger activates a manager without adding a broadcast subscriber. */
        trigger(client); enable(client);
    } else if (!strcmp(mode, "balanced_owner_disable_does_not_stop_wall_schedule")) {
        require(IHS_ClientEnableDiscovery(client), "first Enable");
        /* Wait without emitting a snapshot: Source's first Enable sent once. */
        unsigned before = atomic_load(&time_reads);
        while (atomic_load(&time_reads) == before) usleep(1000);
        enable(client);
        disable(client); update(client,1001); disable(client); update(client,1005);
    } else if (!strcmp(mode, "sequence_wrap_only_on_full_round")) {
        IHS_BaseLock(&client->base); client->discoverySeq = UINT32_MAX; IHS_BaseUnlock(&client->base);
        enable(client); update(client,1001); update(client,1005); update(client,1013);
    } else if (!strcmp(mode, "failed_broadcast_does_not_force_extra_same_tick_round")) {
        failure = true; enable(client); update(client,1000);
    } else if (!strcmp(mode,"lower") || !strcmp(mode,"upper")) {
        upper = !strcmp(mode,"upper");
        enable(client);
        const int low[] = {1000,1001,1005,1009,1013}, high[] = {1002,1003,1010,1016,1017};
        for (unsigned i = 0; i < 5; ++i) update(client, upper ? high[i] : low[i]);
    } else if (!strcmp(mode,"targets") || !strcmp(mode,"target-oom")) {
        IHS_DiscoveryTarget targets[3] = {{.clientId=123},{.clientId=123},{.clientId=456}};
        require(IHS_IPAddressFromString(&targets[0].ip,"127.0.0.1") &&
                IHS_IPAddressFromString(&targets[1].ip,"127.0.0.2") &&
                IHS_IPAddressFromString(&targets[2].ip,"127.0.0.3"), "saved addresses");
        require(IHS_ClientSetDiscoveryTargets(client,targets,3), "owned target snapshot");
        enable(client);
        if (!strcmp(mode, "target-oom")) {
            IHS_DiscoveryTarget changed[3];
            memcpy(changed, targets, sizeof(changed));
            changed[0].clientId = 789;
            target_alloc_fault = true;
            require(!IHS_ClientSetDiscoveryTargets(client, changed, 3), "target allocation failure");
            target_alloc_fault = false;
            require(allocation_failures == 1, "actual allocation failed once");
            require(!IHS_ClientSetDiscoveryTargets(client, targets, SIZE_MAX), "overflow rejected before access");
            changed[0].ip.family = (IHS_IPAddressFamily)99;
            require(!IHS_ClientSetDiscoveryTargets(client, changed, 3), "invalid family rejected");
            require(IHS_ClientSetDiscoveryTargets(client, targets, 3), "identical snapshot preserves deadline");
        }
        disable(client); update(client,1001);
        require(!IHS_ClientDisableDiscovery(client), "no reference underflow");
        require(IHS_ClientSetDiscoveryTargets(client,NULL,0), "clear targets while manager lives");
        snapshot(client,true);
    } else require(false, "known mode");
    require(IHS_ClientStopDiscovery(client), "retire owned manager");
    require(!IHS_ClientDisableDiscovery(client), "no dangling task after StopDiscovery");
    atomic_store(&release_watcher, true);
    IHS_ClientStop(client);
    IHS_ClientThreadedJoin(client);
    require(!IHS_ClientTriggerDiscovery(client) && !IHS_ClientEnableDiscovery(client),
            "stopped client cannot publish new manager tasks");
    IHS_ClientDestroy(client);
    IHS_Quit();
    printf("],\"cleanup\":true}\n");
    alarm(0);
    return 0;
}
