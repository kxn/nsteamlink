/* Real public runtime create/submit/poll/destroy, outer pthread worker,
 * polled client, protobuf/directory/UI events and joined teardown. UDP results,
 * one initial local-resource failure and cloud network pumping are providers.
 * Real cloud objects are constructed/destroyed; no DNS/TLS/Steam requests run.
 * Debug UDP is disabled in the fixture, and sendto never leaves the process. */
#include "../platforms/common/runtime.c"
#include "client/client_pri.h"
#include "fixture_cleanup.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include <stdatomic.h>

static atomic_uint attempts, opens, closes, rx_workers, timer_joins, runtime_joins;
static atomic_uint cloud_creates, early_cloud_creates, cloud_destroys, cloud_pumps;
static atomic_uint cond_creates, cond_destroys, reads_done, callbacks_done;
static atomic_uint fail_hits;
static atomic_int client_fd = -1;
static _Thread_local bool opening;
static const char *mode;
static int injected_errno;
static pthread_t runtime_thread;
static atomic_bool runtime_thread_known;
static IHS_Thread *timer_threads[4];
static unsigned timer_count, cycle;
static unsigned callback_labels[64][2];
static int read_labels[128];
static uint64_t read_times[128];
static const int negative_program[] = {-1,-1,-1,-1,-1,9,-1,7,0};
static const int zero_program[] = {0,0,0,0,0,9,-1,7,0};
static const int positive_program[] = {9,7,-1,-1,0,-1,9,-1};
static const int alternating_program[] = {-1,0,9,0,-1,7,-1};
static const int error_program[] = {-1,9,-1}, control_program[] = {9,-1};
static const int *program;
static unsigned program_size, expected_callbacks;
static uint8_t wire[2][256];
static size_t wire_size[2];

static void require(bool value, const char *why) {
    if (!value) { fprintf(stderr, "discovery worker fixture: %s\n", why); abort(); }
}
static uint64_t now_ns(void) {
    struct timespec value;
    require(!clock_gettime(CLOCK_MONOTONIC, &value), "actual monotonic clock");
    return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}
IHS_UDPSocket *__real_IHS_UDPSocketOpen(bool);
IHS_UDPSocket *__wrap_IHS_UDPSocketOpen(bool broadcast) {
    unsigned call = atomic_fetch_add(&attempts, 1);
    if (!call && !strncmp(mode, "socket", 6)) {
        atomic_fetch_add(&fail_hits, 1);
        errno = EMFILE;
        return NULL;
    }
    opening = true;
    IHS_UDPSocket *socket = __real_IHS_UDPSocketOpen(broadcast);
    opening = false;
    require(socket != NULL, "real socket construction after fixture failure");
    return socket;
}
bool __real_IHS_ClientEnableDiscovery(IHS_Client *);
bool __wrap_IHS_ClientEnableDiscovery(IHS_Client *client) {
    if (!strncmp(mode, "subscription", 12) && !atomic_load(&fail_hits)) {
        atomic_fetch_add(&fail_hits, 1);
        return false;
    }
    return __real_IHS_ClientEnableDiscovery(client);
}
int __real_socket(int, int, int);
int __wrap_socket(int family, int type, int protocol) {
    if (!opening && family == AF_INET && type == SOCK_DGRAM) {
        errno = EACCES; /* Disable only the debug UDP listener. */
        return -1;
    }
    int fd = __real_socket(family, type, protocol);
    if (opening && fd >= 0) {
        require(atomic_load(&client_fd) == -1, "one live discovery descriptor");
        atomic_store(&client_fd, fd);
        atomic_fetch_add(&opens, 1);
    }
    return fd;
}
int __real_close(int);
int __wrap_close(int fd) {
    if (fd == atomic_load(&client_fd)) {
        atomic_store(&client_fd, -1);
        atomic_fetch_add(&closes, 1);
    }
    return __real_close(fd);
}
ssize_t __wrap_sendto(int fd, const void *data, size_t size, int flags,
                     const struct sockaddr *to, socklen_t length) {
    (void)data; (void)flags; (void)to; (void)length;
    require(fd >= 0 && fd == atomic_load(&client_fd), "outbound discovery owner");
    return (ssize_t)size;
}
ssize_t __wrap_recvfrom(int fd, void *data, size_t capacity, int flags,
                       struct sockaddr *from, socklen_t *length) {
    (void)flags;
    require(fd >= 0 && fd == atomic_load(&client_fd) && capacity == 2048, "actual polled receiver");
    int descriptor_flags = fcntl(fd, F_GETFL);
    require(descriptor_flags >= 0 && (descriptor_flags & O_NONBLOCK), "actual nonblocking fd");
    unsigned step = atomic_load(&reads_done);
    require(step < 128, "bounded read observations");
    int label = step < program_size ? program[step] : -1;
    read_labels[step] = label;
    read_times[step] = now_ns();
    atomic_store_explicit(&reads_done, step + 1, memory_order_release);
    if (label <= 0) { ++cycle; errno = injected_errno; return label; }
    unsigned slot = label == 7;
    struct sockaddr_in source = {.sin_family = AF_INET, .sin_port = htons(27036),
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    require(capacity >= wire_size[slot] && *length >= sizeof(source), "wire capacity");
    memcpy(data, wire[slot], wire_size[slot]);
    memcpy(from, &source, sizeof(source));
    *length = sizeof(source);
    return (ssize_t)wire_size[slot];
}
IHS_Cond *__real_IHS_CondCreate(void);
IHS_Cond *__wrap_IHS_CondCreate(void) {
    IHS_Cond *cond = __real_IHS_CondCreate();
    if (cond) atomic_fetch_add(&cond_creates, 1);
    return cond;
}
void __real_IHS_CondDestroy(IHS_Cond *);
void __wrap_IHS_CondDestroy(IHS_Cond *cond) {
    if (cond) atomic_fetch_add(&cond_destroys, 1);
    __real_IHS_CondDestroy(cond);
}
IHS_Thread *__real_IHS_ThreadCreate(IHS_ThreadFunction *, const char *, void *);
IHS_Thread *__wrap_IHS_ThreadCreate(IHS_ThreadFunction *fn, const char *name, void *ctx) {
    if (!strcmp(name, "IHSClient")) atomic_fetch_add(&rx_workers, 1);
    IHS_Thread *thread = __real_IHS_ThreadCreate(fn, name, ctx);
    if (!strcmp(name, "IHS.Timer")) {
        require(timer_count < 4, "bounded timer generations");
        timer_threads[timer_count++] = thread;
    }
    return thread;
}
void __real_IHS_ThreadJoin(IHS_Thread *);
void __wrap_IHS_ThreadJoin(IHS_Thread *thread) {
    __real_IHS_ThreadJoin(thread);
    for (unsigned i = 0; i < timer_count; ++i)
        if (thread && thread == timer_threads[i]) { atomic_fetch_add(&timer_joins, 1); break; }
}
int __real_pthread_join(pthread_t, void **);
int __wrap_pthread_join(pthread_t thread, void **result) {
    int status = __real_pthread_join(thread, result);
    if (!status && atomic_load_explicit(&runtime_thread_known, memory_order_acquire) && pthread_equal(thread, runtime_thread))
        atomic_fetch_add(&runtime_joins, 1);
    return status;
}
sl_remote_connection *__real_sl_remote_connection_create(const IHS_ClientConfig *, const sl_remote_callbacks *, void *);
sl_remote_connection *__wrap_sl_remote_connection_create(const IHS_ClientConfig *config,
                                                         const sl_remote_callbacks *cb, void *ctx) {
    sl_runtime *r = ctx;
    atomic_fetch_add(&cloud_creates, 1);
    if (!r->client || !r->client->base.socket || !r->discovery_subscription)
        atomic_fetch_add(&early_cloud_creates, 1);
    sl_remote_connection *remote = __real_sl_remote_connection_create(config, cb, ctx);
    require(remote != NULL, "real cloud object construction, without network pumping");
    return remote;
}
void __wrap_sl_remote_connection_update(sl_remote_connection *remote, uint64_t now) {
    (void)now;
    if (remote) atomic_fetch_add(&cloud_pumps, 1);
    /* Only network pumping is stopped; do not run DNS/TLS/Steam requests. */
}
void __real_sl_remote_connection_destroy(sl_remote_connection *);
void __wrap_sl_remote_connection_destroy(sl_remote_connection *remote) {
    if (remote) atomic_fetch_add(&cloud_destroys, 1);
    __real_sl_remote_connection_destroy(remote);
}
static void collect_status(IHS_Client *client, const IHS_HostInfo *host,
                           const IHS_DiscoveryAddressHints *hints, void *ctx) {
    unsigned index = atomic_load(&callbacks_done);
    require(index < 64 && host->hasTimestamp && (host->timestamp == 9 || host->timestamp == 7), "parsed status label");
    callback_labels[index][0] = cycle;
    callback_labels[index][1] = (unsigned)host->timestamp;
    discovered_status(client, host, hints, ctx);
    atomic_store_explicit(&callbacks_done, index + 1, memory_order_release);
}
void __real_IHS_ClientSetDiscoveryCallbacks(IHS_Client *, const IHS_ClientDiscoveryCallbacks *, void *);
void __wrap_IHS_ClientSetDiscoveryCallbacks(IHS_Client *client, const IHS_ClientDiscoveryCallbacks *cb, void *ctx) {
    static IHS_ClientDiscoveryCallbacks observed;
    observed = *cb;
    observed.status = collect_status;
    __real_IHS_ClientSetDiscoveryCallbacks(client, &observed, ctx);
}
static void make_wires(void) {
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_instance_id = header.has_msg_type = true;
    header.client_id = 123; header.instance_id = 456;
    header.msg_type = k_ERemoteClientBroadcastMsgStatus;
    CMsgRemoteClientBroadcastStatus status = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
    status.hostname = "worker fixture";
    status.has_games_running = status.has_timestamp = true;
    for (unsigned slot = 0; slot < 2; ++slot) {
        status.timestamp = slot ? 7 : 9;
        IHS_Buffer buffer = IHS_BUFFER_WRAP(wire[slot], sizeof(wire[slot]));
        buffer.size = 0;
        const uint8_t magic[] = {255,255,255,255,33,76,95,160};
        IHS_BufferAppendMem(&buffer, magic, sizeof(magic));
        IHS_BufferAppendUInt32LE(&buffer, cmsg_remote_client_broadcast_header__get_packed_size(&header));
        IHS_BufferAppendMessage(&buffer, (void *)&header);
        IHS_BufferAppendUInt32LE(&buffer, cmsg_remote_client_broadcast_status__get_packed_size(&status));
        IHS_BufferAppendMessage(&buffer, (void *)&status);
        wire_size[slot] = buffer.size;
    }
}

int main(int argc, char **argv) {
    require(argc == 4, "mode errno program");
    mode = argv[1];
    require(!strcmp(mode, "receive") || !strcmp(mode, "socket") || !strcmp(mode, "subscription") ||
                !strcmp(mode, "socket-exit") || !strcmp(mode, "subscription-exit"), "known mode");
    bool exit_after_failure = strstr(mode, "-exit") != NULL;
    char *end;
    long number = strtol(argv[2], &end, 10);
    require(*argv[2] && !*end && number >= 0 && number < 4096, "errno range");
    injected_errno = (int)number;
    const char *name = argv[3];
#define SELECT(text, array) if (!strcmp(name, text)) { program = array; program_size = sizeof(array)/sizeof(array[0]); }
    SELECT("negative_then_recovery", negative_program)
    SELECT("zero_then_recovery", zero_program)
    SELECT("positive_before_error", positive_program)
    SELECT("alternating", alternating_program)
    SELECT("single_error", error_program)
    SELECT("control", control_program)
#undef SELECT
    require(program != NULL, "known program");
    for (unsigned i = 0; i < program_size; ++i) expected_callbacks += program[i] > 0;
    alarm(8);
    require(!setenv("SDL_VIDEODRIVER", "dummy", 1) && !setenv("SDL_AUDIODRIVER", "dummy", 1) &&
                !setenv("SDL_RENDER_DRIVER", "software", 1), "headless SDL environment");
    char directory[] = "/tmp/nsl-worker-discovery-XXXXXX";
    require(mkdtemp(directory) && !setenv("NSL_DATA_DIR", directory, 1), "fixture-owned data root");
    require(stream_media_init(NULL), "actual media root");
    make_wires();
    sl_auth_store store = {.device_id = 42};
    strcpy(store.device_name, "worker fixture");
    sl_host_registry_init(&store.registry);
    sl_runtime *r = sl_runtime_create(&store);
    require(r != NULL, "actual public runtime start");
    runtime_thread = r->worker;
    atomic_store_explicit(&runtime_thread_known, true, memory_order_release);
    bool got_failure = false;
    unsigned failure_attempts = 0, failure_cloud = 0, failure_reads = 0;
    if (strcmp(mode, "receive")) {
        for (unsigned i = 0; i < 3000 && !got_failure; ++i) {
            sl_runtime_event event;
            while (sl_runtime_poll(r, &event)) if (event.type == SL_EVENT_FAILURE) got_failure = true;
            usleep(1000);
        }
        require(got_failure && atomic_load(&fail_hits) == 1, "initial failure actually surfaced");
        usleep(350000); /* Observe several real outer worker/timer iterations. */
        failure_attempts = atomic_load(&attempts);
        failure_cloud = atomic_load(&cloud_creates);
        failure_reads = atomic_load(&reads_done);
        if (!exit_after_failure) {
            sl_command command = {.type = SL_CMD_MANUAL, .generation = 1};
            strcpy(command.text, "127.0.0.1");
            require(sl_runtime_submit(r, &command, &store), "explicit public retry command");
        }
    }
    unsigned host_events = 0;
    for (unsigned i = 0; !exit_after_failure && i < 4000; ++i) {
        sl_runtime_event event;
        while (sl_runtime_poll(r, &event)) {
            if (event.type == SL_EVENT_HOST) {
                require(event.host.client_id == 123 && event.discovery_source == SL_DISCOVERY_LAN, "actual LAN UI event");
                ++host_events;
            }
        }
        if (host_events && atomic_load_explicit(&callbacks_done, memory_order_acquire) >= expected_callbacks &&
                atomic_load_explicit(&reads_done, memory_order_acquire) >= program_size) break;
        usleep(1000);
    }
    require(exit_after_failure || (host_events && atomic_load(&callbacks_done) >= expected_callbacks), "worker delivers recovery status");
    uint64_t stop = now_ns();
    sl_runtime_destroy(r);
    uint64_t stop_ns = now_ns() - stop;
    stream_media_shutdown();
    unsigned reads = atomic_load(&reads_done), callbacks = atomic_load(&callbacks_done);
    unsigned observed_size = exit_after_failure ? 0 : program_size;
    require((exit_after_failure || reads >= program_size) && callbacks <= 64, "complete bounded program");
    uint64_t min_gap = UINT64_MAX;
    for (unsigned i = 1; i < observed_size; ++i)
        if (read_labels[i-1] <= 0 && read_times[i] - read_times[i-1] < min_gap)
            min_gap = read_times[i] - read_times[i-1];
    sl_fixture_remove_tree(directory);
    alarm(0);
    printf("{\"mode\":\"%s\",\"errno\":%d,\"program\":\"%s\",\"failure_attempts\":%u,\"failure_cloud\":%u,\"failure_reads\":%u,"
           "\"attempts\":%u,\"opens\":%u,\"closes\":%u,\"rx_workers\":%u,\"timer_joins\":%u,\"runtime_joins\":%u,"
           "\"cond_creates\":%u,\"cond_destroys\":%u,\"cloud_creates\":%u,\"early_cloud_creates\":%u,\"cloud_destroys\":%u,"
           "\"cloud_pumps\":%u,\"host_events\":%u,\"stop_ns\":%llu,\"min_read_gap_ns\":%llu,\"reads\":[",
           mode, injected_errno, name, failure_attempts, failure_cloud, failure_reads,
           atomic_load(&attempts), atomic_load(&opens), atomic_load(&closes), atomic_load(&rx_workers),
           atomic_load(&timer_joins), atomic_load(&runtime_joins), atomic_load(&cond_creates), atomic_load(&cond_destroys),
           atomic_load(&cloud_creates), atomic_load(&early_cloud_creates), atomic_load(&cloud_destroys),
           atomic_load(&cloud_pumps), host_events, (unsigned long long)stop_ns, (unsigned long long)min_gap);
    for (unsigned i = 0; i < observed_size; ++i) printf("%s%d", i ? "," : "", read_labels[i]);
    printf("],\"callbacks\":[");
    for (unsigned i = 0; i < callbacks; ++i) printf("%s[%u,%u]", i ? "," : "", callback_labels[i][0], callback_labels[i][1]);
    printf("]}\n");
    return 0;
}
