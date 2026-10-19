/* Actual client/Base/pthread/POSIX receive/protobuf/callback/stop/join/destroy.
 * Only recvfrom is adapted: a controlled error, then a valid status datagram.
 * No real Steam, network change, DNS or Switch error occurrence is proved. */
#include "ihslib.h"
#include "client/client_pri.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static atomic_bool ready;
static atomic_uint reads, delivered;
static int injected_error;
static unsigned char wire[2][256];
static size_t wire_size[2];
static unsigned failures;
static bool persistent;
static atomic_bool waiting, stop_requested;
static atomic_uint joins, destroys, signals;
static IHS_Thread *receive_worker;
static IHS_Cond *receive_cond;
static _Thread_local bool receive_thread;
static unsigned waits, spurious, injected_spurious;
static uint64_t read_ns[64], cpu_start, cpu_used;
static bool nonblocking;
static bool fail_condition;
static const int *program;
static unsigned program_size, expected_deliveries = 1, current_cycle;
static int logical_reads[64];
static unsigned callback_labels[64][2];
static const int negative_program[] = {-1,-1,-1,-1,-1,9,-1,7,0};
static const int zero_program[] = {0,0,0,0,0,9,-1,7,0};
static const int positive_program[] = {9,7,-1,-1,0,-1,9,-1};
static const int alternating_program[] = {-1,0,9,0,-1,7,-1};

static void require(bool condition, const char *reason) {
    if (!condition) {
        fprintf(stderr, "discovery fixture: %s\n", reason);
        abort();
    }
}

static uint64_t nanos(clockid_t clock) {
    struct timespec time;
    require(clock_gettime(clock, &time) == 0, "clock");
    return (uint64_t)time.tv_sec * 1000000000 + time.tv_nsec;
}

IHS_Cond *__real_IHS_CondCreate(void);
IHS_Cond *__wrap_IHS_CondCreate(void) {
    return fail_condition ? NULL : __real_IHS_CondCreate();
}

bool __real_IHS_UDPSocketSetBlocking(IHS_UDPSocket *, bool);
bool __wrap_IHS_UDPSocketSetBlocking(IHS_UDPSocket *socket, bool blocking) {
    bool result = __real_IHS_UDPSocketSetBlocking(socket, blocking);
    /* Gate initialization before the first cycle samples its deadline. Main
     * installs callbacks and publishes fixture handles while this waits. */
    while (!atomic_load(&ready)) usleep(1000);
    return result;
}

bool __real_IHS_CondWaitTimeout(IHS_Cond *, IHS_Mutex *, uint32_t);
bool __wrap_IHS_CondWaitTimeout(IHS_Cond *cond, IHS_Mutex *mutex, uint32_t ms) {
    if (!receive_thread) return __real_IHS_CondWaitTimeout(cond, mutex, ms);
    require(cond == receive_cond && ms > 0 && ms <= 100, "receive wait identity/deadline");
    ++waits;
    if (spurious) {
        --spurious;
        ++injected_spurious;
        return true; /* deliberate early wake, no artificial clock advance */
    }
    atomic_store(&waiting, true);
    if (persistent && atomic_load(&reads) >= 4) {
        /* Test gate holds the real Base mutex until main requests Stop.
         * The forwarded wait then atomically releases it to the real Stop. */
        while (!atomic_load(&stop_requested)) usleep(1000);
    }
    bool result = __real_IHS_CondWaitTimeout(cond, mutex, ms);
    cpu_used = nanos(CLOCK_THREAD_CPUTIME_ID) - cpu_start;
    atomic_store(&waiting, false);
    return result;
}

void __real_IHS_CondSignal(IHS_Cond *);
void __wrap_IHS_CondSignal(IHS_Cond *cond) {
    if (cond == receive_cond) atomic_fetch_add(&signals, 1);
    __real_IHS_CondSignal(cond);
}
void __real_IHS_ThreadJoin(IHS_Thread *);
void __wrap_IHS_ThreadJoin(IHS_Thread *thread) {
    __real_IHS_ThreadJoin(thread);
    if (thread && thread == receive_worker) atomic_fetch_add(&joins, 1);
}
void __real_IHS_CondDestroy(IHS_Cond *);
void __wrap_IHS_CondDestroy(IHS_Cond *cond) {
    if (cond && cond == receive_cond) {
        require(atomic_load(&joins) == 1, "condition destroy after actual join");
        atomic_fetch_add(&destroys, 1);
    }
    __real_IHS_CondDestroy(cond);
}

ssize_t __wrap_recvfrom(int fd, void *buffer, size_t size, int flags,
                        struct sockaddr *from, socklen_t *from_size) {
    (void)flags;
    while (!atomic_load(&ready)) usleep(1000);
    receive_thread = true;
    unsigned step = atomic_fetch_add(&reads, 1);
    require(size == 2048, "discovery receive budget unchanged");
    if (!step) {
        int fd_flags = fcntl(fd, F_GETFL);
        require(fd_flags >= 0, "live receive socket");
        nonblocking = (fd_flags & O_NONBLOCK) != 0;
        cpu_start = nanos(CLOCK_THREAD_CPUTIME_ID);
    }
    if (step < 64) read_ns[step] = nanos(CLOCK_MONOTONIC);
    int code = program ? (step < program_size ? program[step] : -1)
                       : (step < failures ? (injected_error ? -1 : 0) : (step == failures ? 9 : -1));
    if (step < 64) logical_reads[step] = code;
    if (code <= 0) {
        ++current_cycle;
        errno = injected_error ? injected_error : EAGAIN;
        return code;
    }
    {
        unsigned slot = code == 7;
        require(size >= wire_size[slot] && *from_size >= sizeof(struct sockaddr_in), "receive capacity");
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(27036),
                                      .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        memcpy(from, &address, sizeof(address));
        *from_size = sizeof(address);
        memcpy(buffer, wire[slot], wire_size[slot]);
        return (ssize_t)wire_size[slot];
    }
}

static void discovered(IHS_Client *client, const IHS_HostInfo *host, void *context) {
    (void)client;
    (void)context;
    require(host->clientId == 123 && host->instanceId == 456, "identity");
    require(!strcmp(host->hostname, "fixture") && host->hasGamesRunning && host->gamesRunning == 0,
            "status fields");
    require(host->hasTimestamp && (host->timestamp == 9 || host->timestamp == 7), "packet label");
    unsigned n = atomic_load(&delivered);
    require(n < 64, "callback budget");
    callback_labels[n][0] = current_cycle;
    callback_labels[n][1] = (unsigned)host->timestamp;
    atomic_fetch_add(&delivered, 1);
}

int main(int argc, char **argv) {
    require(argc >= 2 && argc <= 4, "errno [failure count|persistent] [spurious wakes]");
    if (!strcmp(argv[1], "condfail")) {
        IHS_Init();
        const uint8_t secret[32] = {0};
        IHS_ClientConfig config = {.deviceId = 42, .deviceName = "fixture", .secretKey = secret};
        fail_condition = true;
        require(IHS_ClientCreate(&config) == NULL, "failed condition must not create a client worker");
        IHS_Quit();
        printf("{\"condition_failure\":true,\"client_rejected\":true}\n");
        return 0;
    }
    char *end;
    long number = strtol(argv[1], &end, 10);
    require(*argv[1] && !*end && number >= 0 && number <= 4095, "errno range");
    injected_error = (int)number;
    failures = injected_error ? 1 : 0;
    if (argc >= 3) {
        persistent = !strcmp(argv[2], "persistent");
        if (!strcmp(argv[2], "negative_then_recovery")) { program = negative_program; program_size = 9; }
        if (!strcmp(argv[2], "zero_then_recovery")) { program = zero_program; program_size = 9; }
        if (!strcmp(argv[2], "positive_before_error")) { program = positive_program; program_size = 8; }
        if (!strcmp(argv[2], "alternating")) { program = alternating_program; program_size = 7; }
        if (program) {
            failures = 0;
            expected_deliveries = 0;
            for (unsigned n = 0; n < program_size; ++n) expected_deliveries += program[n] > 0;
        } else {
            number = persistent ? UINT_MAX : strtol(argv[2], &end, 10);
            require(persistent || (*argv[2] && !*end && number >= 0 && number <= 10), "failure count");
            failures = (unsigned)number;
        }
    }
    if (argc == 4) {
        number = strtol(argv[3], &end, 10);
        require(*argv[3] && !*end && number >= 0 && number <= 10, "spurious count");
        spurious = (unsigned)number;
    }
    alarm(5);
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_instance_id = header.has_msg_type = true;
    header.client_id = 123;
    header.instance_id = 456;
    header.msg_type = k_ERemoteClientBroadcastMsgStatus;
    CMsgRemoteClientBroadcastStatus status = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
    status.hostname = "fixture";
    status.has_games_running = true;
    status.games_running = 0;
    const unsigned char magic[8] = {0xff, 0xff, 0xff, 0xff, 0x21, 0x4c, 0x5f, 0xa0};
    status.has_timestamp = true;
    for (unsigned slot = 0; slot < 2; ++slot) {
        status.timestamp = slot ? 7 : 9;
        IHS_Buffer buffer = IHS_BUFFER_WRAP(wire[slot], sizeof(wire[slot]));
        buffer.size = 0;
        IHS_BufferAppendMem(&buffer, magic, sizeof(magic));
        size_t length = cmsg_remote_client_broadcast_header__get_packed_size(&header);
        IHS_BufferAppendUInt32LE(&buffer, length);
        buffer.size += cmsg_remote_client_broadcast_header__pack(&header, wire[slot] + buffer.size);
        length = cmsg_remote_client_broadcast_status__get_packed_size(&status);
        IHS_BufferAppendUInt32LE(&buffer, length);
        buffer.size += cmsg_remote_client_broadcast_status__pack(&status, wire[slot] + buffer.size);
        wire_size[slot] = buffer.size;
    }
    IHS_Init();
    const uint8_t secret[32] = {0};
    IHS_ClientConfig config = {.deviceId = 42, .deviceName = "fixture", .secretKey = secret};
    IHS_Client *client = IHS_ClientCreate(&config);
    require(client != NULL, "client create");
    const IHS_ClientDiscoveryCallbacks callbacks = {.discovered = discovered};
    IHS_ClientSetDiscoveryCallbacks(client, &callbacks, NULL);
    receive_worker = client->base.worker;
    receive_cond = client->receiveWake;
    atomic_store(&ready, true);
    bool socket_live = false;
    for (unsigned n = 0; n < 2000; ++n) {
        if (persistent) {
            if (atomic_load(&reads) >= 4 && atomic_load(&waiting)) break;
            usleep(1000);
            continue; /* the Stop gate deliberately holds Base, don't lock it */
        }
        IHS_BaseLock(&client->base);
        socket_live = client->base.socket != NULL;
        IHS_BaseUnlock(&client->base);
        if ((atomic_load(&delivered) >= expected_deliveries && (!program || atomic_load(&reads) >= program_size)) || (atomic_load(&reads) && !socket_live) ||
            (persistent && atomic_load(&reads) >= 4 && atomic_load(&waiting))) break;
        usleep(1000);
    }
    unsigned received = atomic_load(&delivered);
    IHS_ClientStopDiscovery(client);
    uint64_t stop_start = nanos(CLOCK_MONOTONIC);
    atomic_store(&stop_requested, true);
    if (persistent) {
        IHS_BaseLock(&client->base);
        socket_live = client->base.socket != NULL;
        IHS_BaseUnlock(&client->base);
    }
    IHS_ClientStop(client);
    IHS_ClientThreadedJoin(client);
    uint64_t stop_ns = nanos(CLOCK_MONOTONIC) - stop_start;
    require(client->base.socket == NULL && client->base.worker == NULL, "joined/closed");
    IHS_ClientDestroy(client);
    IHS_Quit();
    alarm(0);
    uint64_t min_gap = UINT64_MAX;
    unsigned count = program ? program_size - 1 : (persistent ? atomic_load(&reads) - 1 : failures);
    for (unsigned i = 1; i <= count && i < 64; ++i) {
        if (!read_ns[i]) break;
        if (logical_reads[i - 1] > 0) continue;
        uint64_t gap = read_ns[i] - read_ns[i - 1];
        if (gap < min_gap) min_gap = gap;
    }
    printf("{\"errno\":%d,\"reads\":%u,\"delivered\":%u,\"socket_live_before_stop\":%s,"
           "\"joined_closed_destroyed\":true,\"nonblocking\":%s,\"persistent\":%s,"
           "\"failures\":%u,\"min_read_gap_ns\":%llu,\"waits\":%u,\"spurious\":%u,"
           "\"signals\":%u,\"joins\":%u,\"destroys\":%u,\"stop_ns\":%llu,\"cpu_ns\":%llu,\"callbacks\":[",
           injected_error, atomic_load(&reads), received, socket_live ? "true" : "false",
           nonblocking ? "true" : "false", persistent ? "true" : "false", failures,
           (unsigned long long)min_gap, waits, injected_spurious, atomic_load(&signals),
           atomic_load(&joins), atomic_load(&destroys), (unsigned long long)stop_ns,
           (unsigned long long)cpu_used);
    for (unsigned n = 0; n < received; ++n)
        printf("%s[%u,%u]", n ? "," : "", callback_labels[n][0], callback_labels[n][1]);
    printf("]}\n");
    return 0;
}
