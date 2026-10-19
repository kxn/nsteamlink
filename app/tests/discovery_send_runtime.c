/* Actual client/UDP/protobuf/RX/cleanup. sendto error and loopback destination
 * adapters model a poisoned descriptor generation, not an observed Switch bug. */
#include "client/client_pri.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "ihslib.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int peer, client_fd = -1;
static struct sockaddr_in peer_address;
static atomic_uint opens, closes, attempts, delivered, forwarded;
static bool poisoned, cadence, all_fail, short_host, multiple, partial_host;
static bool reopen_failure, nonblock_failure, read_gate, dispatch_gate, stop_after_reopen;
static bool manual_read, nonblock_initial;
static atomic_bool arm_read;
static atomic_bool allow_factory, read_entered, release_read, handler_entered, release_handler,
    handler_done;
static atomic_bool fallback_seen;
static atomic_bool read_callback_entered, release_read_callback;
static IHS_Client *active_client;
static atomic_bool last_broadcast_result;
static atomic_uint target_queries;
static uint64_t send_times[8];
static unsigned char send_history[8][2048];
static size_t send_sizes[8];
static int error_mode = EIO;
static unsigned char captured[2048];
static size_t captured_size;
static void require(bool condition, const char *why) {
    if (!condition) {
        fprintf(stderr, "send probe: %s\n", why);
        abort();
    }
}
bool __real_IHS_ClientBroadcast(IHS_Client *, ERemoteClientBroadcastMsg, ProtobufCMessage *);
bool __wrap_IHS_ClientBroadcast(IHS_Client *client, ERemoteClientBroadcastMsg type,
                                ProtobufCMessage *message) {
    unsigned before = atomic_load(&target_queries);
    bool result = __real_IHS_ClientBroadcast(client, type, message);
    require(atomic_load(&target_queries) == before + 1,
            "retry retains one fixed target enumeration");
    atomic_store(&last_broadcast_result, result);
    return result;
}
int __real_socket(int, int, int);
int __wrap_socket(int family, int type, int protocol) {
    if (reopen_failure && atomic_load(&opens) && !atomic_load(&allow_factory)) {
        errno = EMFILE;
        return -1;
    }
    int fd = __real_socket(family, type, protocol);
    require(family == AF_INET && type == SOCK_DGRAM, "client IPv4 socket intent");
    if (fd >= 0) {
        require(client_fd == -1, "one active descriptor");
        client_fd = fd;
        atomic_fetch_add(&opens, 1);
    }
    return fd;
}
int __real_close(int);
int __wrap_close(int fd) {
    require(fd >= 0, "never close an invalid descriptor");
    if (fd == client_fd && read_gate)
        require(atomic_load(&delivered) == 1, "read callback before descriptor close");
    if (fd == client_fd && dispatch_gate)
        require(atomic_load(&handler_done), "dispatch complete before descriptor close");
    if (fd == client_fd) {
        client_fd = -1;
        atomic_fetch_add(&closes, 1);
    }
    return __real_close(fd);
}
size_t __wrap_IHS_UDPBroadcastAddresses(IHS_IPAddress *out, size_t count) {
    atomic_fetch_add(&target_queries, 1);
    if (multiple && count) {
        require(IHS_IPAddressFromString(out, "127.0.0.255"), "controlled second broadcast target");
        return 1;
    }
    return 0;
}
ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t __wrap_sendto(int fd, const void *bytes, size_t length, int flags,
                      const struct sockaddr *to, socklen_t size) {
    (void)size;
    const struct sockaddr_in *a = (void *)to;
    require(a->sin_family == AF_INET &&
                (a->sin_addr.s_addr == INADDR_BROADCAST ||
                 (multiple && a->sin_addr.s_addr == htonl(0x7f0000ff))) &&
                ntohs(a->sin_port) == 27036,
            "only a controlled broadcast is admitted");
    require(length <= sizeof(captured), "wire capture budget before any copy");
    if (read_gate)
        require(atomic_load(&delivered) == 1, "full read dispatch precedes automatic send");
    if (dispatch_gate)
        require(atomic_load(&handler_done) && active_client->authorizationDispatching == 0,
                "popped callback completes before automatic send");
    unsigned count = atomic_fetch_add(&attempts, 1);
    require(count < 8, "bounded cadence history");
    struct timespec now;
    require(!clock_gettime(CLOCK_MONOTONIC, &now), "monotonic send sample");
    send_times[count] = (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
    memcpy(send_history[count], bytes, length);
    send_sizes[count] = length;
    require(length <= sizeof(captured), "wire capture budget");
    memcpy(captured, bytes, length);
    captured_size = length;
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (short_host) {
        errno = EHOSTUNREACH;
        return (ssize_t)length - 1;
    }
    if (partial_host && count % 2) {
        errno = EHOSTUNREACH;
        return -1;
    }
    if (all_fail || (reopen_failure && !atomic_load(&allow_factory)) ||
        (!cadence && (count == 0 || (poisoned && atomic_load(&opens) == 1)))) {
        errno = error_mode;
        return -1;
    }
    ssize_t sent =
        __real_sendto(fd, bytes, length, flags, (void *)&peer_address, sizeof(peer_address));
    if (sent == (ssize_t)length)
        atomic_fetch_add(&forwarded, 1);
    return sent;
}
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int command, ...) {
    if (command == F_GETFL)
        return __real_fcntl(fd, command);
    require(command == F_SETFL, "known fcntl operation");
    va_list args;
    va_start(args, command);
    int flags = va_arg(args, int);
    va_end(args);
    if (nonblock_failure && (nonblock_initial || atomic_load(&opens) > 1)) {
        errno = EIO;
        return -1;
    }
    return __real_fcntl(fd, command, flags);
}
ssize_t __real_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t __wrap_recvfrom(int fd, void *bytes, size_t length, int flags, struct sockaddr *from,
                        socklen_t *size) {
    if (fd != peer && (read_gate || manual_read) && atomic_load(&arm_read) &&
        !atomic_load(&release_read)) {
        atomic_store(&read_entered, true);
        while (!atomic_load(&release_read))
            usleep(1000);
    }
    if (fd != peer && fd >= 0 && nonblock_failure &&
        (nonblock_initial || atomic_load(&opens) > 1)) {
        require(flags & MSG_DONTWAIT, "failed O_NONBLOCK has bounded per-call receive");
        atomic_store(&fallback_seen, true);
    }
    return __real_recvfrom(fd, bytes, length, flags, from, size);
}
static void found(IHS_Client *c, const IHS_HostInfo *h, void *unused) {
    (void)c;
    (void)unused;
    require(h->clientId == 123 && h->instanceId == 456 && !strcmp(h->hostname, "send fixture"),
            "actual parsed status");
    require(h->hasGamesRunning && h->gamesRunning == 0, "zero games still discovered");
    if (read_gate) {
        atomic_store(&read_callback_entered, true);
        while (!atomic_load(&release_read_callback))
            usleep(1000);
    }
    atomic_fetch_add(&delivered, 1);
}
static void send_status(const struct sockaddr_in *to) {
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_instance_id = header.has_msg_type = true;
    header.client_id = 123;
    header.instance_id = 456;
    header.msg_type = k_ERemoteClientBroadcastMsgStatus;
    CMsgRemoteClientBroadcastStatus status = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
    status.hostname = "send fixture";
    status.has_games_running = true;
    unsigned char bytes[256];
    IHS_Buffer b = IHS_BUFFER_WRAP(bytes, sizeof(bytes));
    b.size = 0;
    const unsigned char magic[] = {255, 255, 255, 255, 0x21, 0x4c, 0x5f, 0xa0};
    IHS_BufferAppendMem(&b, magic, sizeof(magic));
    IHS_BufferAppendUInt32LE(&b, cmsg_remote_client_broadcast_header__get_packed_size(&header));
    IHS_BufferAppendMessage(&b, (void *)&header);
    IHS_BufferAppendUInt32LE(&b, cmsg_remote_client_broadcast_status__get_packed_size(&status));
    IHS_BufferAppendMessage(&b, (void *)&status);
    require(__real_sendto(peer, bytes, b.size, 0, (void *)to, sizeof(*to)) == (ssize_t)b.size,
            "actual peer status reply");
}
static void reply_if_delivered(void) {
    if (atomic_load(&forwarded)) {
        struct pollfd p = {.fd = peer, .events = POLLIN};
        require(poll(&p, 1, 2000) == 1, "forwarded loopback datagram reaches peer");
    }
    unsigned char request[2048];
    struct sockaddr_in from;
    socklen_t size = sizeof(from);
    ssize_t count = recvfrom(peer, request, sizeof(request), MSG_DONTWAIT, (void *)&from, &size);
    if (count < 0) {
        require(errno == EAGAIN || errno == EWOULDBLOCK, "no unexpected peer receive error");
        return;
    }
    require(count == (ssize_t)captured_size && !memcmp(request, captured, captured_size),
            "actual complete loopback datagram");
    if (read_gate)
        return; /* A real Status was consumed before the broadcast. */
    send_status(&from);
    for (unsigned i = 0; i < 2000 && !atomic_load(&delivered); ++i)
        usleep(1000);
    require(atomic_load(&delivered) == 1, "actual client RX and callback");
}
static struct sockaddr_in bound_client_address(void) {
    bool completed = false;
    for (unsigned i = 0; i < 2000 && !completed; ++i) {
        IHS_BaseLock(&active_client->base);
        completed = active_client->receiveGeneration != 0;
        IHS_BaseUnlock(&active_client->base);
        if (!completed)
            usleep(1000);
    }
    require(completed, "completed idle receive generation before boundary gate");
    unsigned char warm = 0;
    require(__real_sendto(client_fd, &warm, 1, 0, (void *)&peer_address, sizeof(peer_address)) == 1,
            "explicit native fixture UDP-bind precondition");
    struct pollfd p = {.fd = peer, .events = POLLIN};
    require(poll(&p, 1, 2000) == 1 && recvfrom(peer, &warm, 1, 0, NULL, NULL) == 1,
            "drain bind fixture");
    struct sockaddr_in address;
    socklen_t size = sizeof(address);
    require(!getsockname(client_fd, (void *)&address, &size), "bound client endpoint");
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return address;
}
static void delayed_streaming(IHS_Client *client, const IHS_SocketAddress *address,
                              CMsgRemoteClientBroadcastHeader *header, ProtobufCMessage *message) {
    IHS_ClientStreamingCallback(client, address, header, message);
    atomic_store(&handler_entered, true);
    while (!atomic_load(&release_handler))
        usleep(1000);
    atomic_store(&handler_done, true);
}
static void *pump_one(void *client) {
    require(IHS_ClientPumpAuthorization(client, 1) == 1,
            "actual single deferred callback dispatch");
    return NULL;
}
static void *send_one(void *client) {
    CMsgRemoteClientBroadcastDiscovery message = CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
    message.has_seq_num = true;
    message.seq_num = 2;
    return (void *)(uintptr_t)IHS_ClientBroadcast(client, k_ERemoteClientBroadcastMsgDiscovery,
                                                  (void *)&message);
}
static void send_progress(const struct sockaddr_in *to) {
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_instance_id = header.has_msg_type = true;
    header.client_id = 123;
    header.instance_id = 456;
    header.msg_type = k_ERemoteDeviceStreamingProgress;
    CMsgRemoteDeviceStreamingProgress progress = CMSG_REMOTE_DEVICE_STREAMING_PROGRESS__INIT;
    progress.request_id = 1;
    unsigned char bytes[256];
    IHS_Buffer b = IHS_BUFFER_WRAP(bytes, sizeof(bytes));
    b.size = 0;
    const unsigned char magic[] = {255, 255, 255, 255, 0x21, 0x4c, 0x5f, 0xa0};
    IHS_BufferAppendMem(&b, magic, sizeof(magic));
    IHS_BufferAppendUInt32LE(&b, cmsg_remote_client_broadcast_header__get_packed_size(&header));
    IHS_BufferAppendMessage(&b, (void *)&header);
    IHS_BufferAppendUInt32LE(&b, cmsg_remote_device_streaming_progress__get_packed_size(&progress));
    IHS_BufferAppendMessage(&b, (void *)&progress);
    require(__real_sendto(peer, bytes, b.size, 0, (void *)to, sizeof(*to)) == (ssize_t)b.size,
            "actual queued Progress datagram");
}
int main(int argc, char **argv) {
    require(argc == 2, "one sender mode");
    poisoned = !strcmp(argv[1], "poisoned");
    cadence = !strcmp(argv[1], "cadence");
    all_fail = !strcmp(argv[1], "all-fail") || !strcmp(argv[1], "multi-fail");
    short_host = !strcmp(argv[1], "short");
    partial_host = !strcmp(argv[1], "partial-host");
    multiple = partial_host || !strcmp(argv[1], "partial") || !strcmp(argv[1], "multi-fail");
    stop_after_reopen = !strcmp(argv[1], "reopen-stop");
    reopen_failure = stop_after_reopen || !strcmp(argv[1], "reopen");
    nonblock_initial = !strcmp(argv[1], "nonblock-init");
    nonblock_failure = nonblock_initial || !strcmp(argv[1], "nonblock");
    manual_read = !strcmp(argv[1], "manual-read");
    read_gate = !strcmp(argv[1], "read-order");
    dispatch_gate = !strcmp(argv[1], "dispatch-order");
    bool host = !strcmp(argv[1], "host");
    if (host)
        error_mode = EHOSTUNREACH;
    require(cadence || poisoned || all_fail || short_host || multiple || reopen_failure ||
                nonblock_failure || read_gate || dispatch_gate || manual_read || host ||
                !strcmp(argv[1], "transient"),
            "known mode");
    alarm(18);
    peer = __real_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    require(peer >= 0, "peer socket");
    peer_address =
        (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    require(!bind(peer, (void *)&peer_address, sizeof(peer_address)), "peer bind");
    socklen_t size = sizeof(peer_address);
    require(!getsockname(peer, (void *)&peer_address, &size), "peer endpoint");
    IHS_Init();
    unsigned char secret[32] = {0};
    IHS_ClientConfig config = {.deviceId = 42, .deviceName = "send fixture", .secretKey = secret};
    IHS_Client *client = IHS_ClientCreate(&config);
    require(client != NULL, "real client");
    active_client = client;
    const IHS_ClientDiscoveryCallbacks callbacks = {.discovered = found};
    IHS_ClientSetDiscoveryCallbacks(client, &callbacks, NULL);
    if (cadence) {
        require(IHS_ClientStartDiscovery(client, 3000), "real periodic discovery task");
        for (unsigned i = 0; i < 12500 && atomic_load(&attempts) < 3; ++i)
            usleep(1000);
        require(IHS_ClientStopDiscovery(client), "stop actual discovery task");
        require(atomic_load(&attempts) == 3, "three actual timer broadcasts");
        IHS_ClientStop(client);
        IHS_ClientThreadedJoin(client);
        IHS_ClientDestroy(client);
        IHS_Quit();
        require(client_fd == -1 && atomic_load(&closes) == atomic_load(&opens),
                "cadence descriptors closed after join");
        __real_close(peer);
        alarm(0);
        printf("{\"mode\":\"cadence\",\"cleanup\":true,\"sends\":[");
        for (unsigned i = 0; i < 3; ++i) {
            printf("%s{\"after_ns\":%llu,\"wire\":\"", i ? "," : "",
                   (unsigned long long)(send_times[i] - send_times[0]));
            for (size_t j = 0; j < send_sizes[i]; ++j) {
                printf("%02x", send_history[i][j]);
            }
            printf("\"}");
        }
        puts("]}");
        return 0;
    }
    IHS_UDPSocket *owner = client->base.socket;
    CMsgRemoteClientBroadcastDiscovery message = CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
    message.has_seq_num = true;
    message.seq_num = 2;
    bool result;
    if (manual_read) {
        (void)bound_client_address();
        atomic_store(&arm_read, true);
        for (unsigned i = 0; i < 2000 && !atomic_load(&read_entered); ++i)
            usleep(1000);
        require(atomic_load(&read_entered), "manual send boundary holds an actual receive");
        pthread_t sender;
        require(!pthread_create(&sender, NULL, send_one, client), "create manual sender");
        usleep(150000);
        require(!atomic_load(&attempts), "manual sender cannot replace fd during a receive");
        atomic_store(&release_read, true);
        void *returned;
        require(!pthread_join(sender, &returned), "join manual sender");
        result = (uintptr_t)returned != 0;
    } else if (read_gate || dispatch_gate) {
        struct sockaddr_in address = bound_client_address();
        pthread_t pump;
        if (dispatch_gate) {
            IHS_ClientSetAuthorizationDeferred(client, true);
            client->privCallbacks.streaming = delayed_streaming;
            send_progress(&address);
            bool queued = false;
            for (unsigned i = 0; i < 2000 && !queued; ++i) {
                IHS_BaseLock(&client->base);
                queued = client->authorizationCount == 1;
                IHS_BaseUnlock(&client->base);
                if (!queued)
                    usleep(1000);
            }
            require(queued && !pthread_create(&pump, NULL, pump_one, client),
                    "queued callback/pump");
            for (unsigned i = 0; i < 2000 && !atomic_load(&handler_entered); ++i)
                usleep(1000);
            require(atomic_load(&handler_entered), "real callback reached delayed return boundary");
        } else {
            atomic_store(&arm_read, true);
            for (unsigned i = 0; i < 2000 && !atomic_load(&read_entered); ++i)
                usleep(1000);
            require(atomic_load(&read_entered), "actual receive is held before kernel read");
            send_status(&address);
        }
        client->discoverySeq = 2; /* Match the controlled original status-round input. */
        require(IHS_ClientStartDiscovery(client, 0), "automatic one-shot broadcast");
        usleep(150000);
        require(!atomic_load(&attempts),
                "automatic broadcast waits for complete processing boundary");
        if (dispatch_gate) {
            atomic_store(&release_handler, true);
            require(!pthread_join(pump, NULL), "join callback owner");
        } else {
            atomic_store(&release_read, true);
            for (unsigned i = 0; i < 2000 && !atomic_load(&read_callback_entered); ++i)
                usleep(1000);
            require(atomic_load(&read_callback_entered), "actual discovery callback entered");
            usleep(150000);
            require(!atomic_load(&attempts), "automatic sender waits through callback execution");
            atomic_store(&release_read_callback, true);
        }
        for (unsigned i = 0; i < 2000 && atomic_load(&attempts) < 2; ++i)
            usleep(1000);
        IHS_ClientStopDiscovery(client); /* Acquires task mutex even after one-shot retirement. */
        require(atomic_load(&attempts) == 2, "automatic recovery after processing");
        result = atomic_load(&last_broadcast_result);
    } else {
        result =
            IHS_ClientBroadcast(client, k_ERemoteClientBroadcastMsgDiscovery, (void *)&message);
    }
    if (reopen_failure) {
        require(!result && client_fd == -1 && atomic_load(&opens) == 1 &&
                    atomic_load(&closes) == 1 && atomic_load(&attempts) == 3,
                "bounded failed reopen leaves an inert, retained owner");
        if (!stop_after_reopen) {
            atomic_store(&allow_factory, true);
            result =
                IHS_ClientBroadcast(client, k_ERemoteClientBroadcastMsgDiscovery, (void *)&message);
            require(result && atomic_load(&attempts) == 5,
                    "later broadcast recovers the same owner");
        }
    }
    reply_if_delivered();
    if (nonblock_failure)
        require(atomic_load(&fallback_seen), "per-call nonblocking receive exercised");
    require(client->base.socket == owner && client->base.worker, "owner retained");
    unsigned before_closes = atomic_load(&closes), before_opens = atomic_load(&opens),
             before_attempts = atomic_load(&attempts), before_delivered = atomic_load(&delivered);
    IHS_ClientStop(client);
    IHS_ClientThreadedJoin(client);
    IHS_ClientDestroy(client);
    IHS_Quit();
    require(client_fd == -1 && atomic_load(&closes) == atomic_load(&opens),
            "all created descriptors closed after join");
    __real_close(peer);
    alarm(0);
    printf(
        "{\"mode\":\"%s\",\"result\":%s,\"opens_before_cleanup\":%u,\"closes_before_cleanup\":%u,"
        "\"attempts\":%u,\"delivered\":%u,\"owner_retained\":true,\"cleanup\":true,\"wire\":\"",
        argv[1], result ? "true" : "false", before_opens, before_closes, before_attempts,
        before_delivered);
    for (size_t i = 0; i < captured_size; ++i) {
        printf("%02x", captured[i]);
    }
    puts("\"}");
    return 0;
}
