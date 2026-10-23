/* Production start_client/update_control/stop_client and polled SDK receive,
 * parsing, application directory/events and cleanup. Only recvfrom outcomes,
 * wall time and outbound send acceptance are providers. The fixture drives
 * actor timestamps; it is not the outer worker, Qt, a Steam peer or Switch. */
#include "../platforms/common/runtime.c"
#include "client/client_pri.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

static int owned_fd = -1, injected_errno;
static unsigned opens, closes, rx_workers, timer_joins, cond_destroys;
static IHS_Thread *timer_worker;
static IHS_Cond *receive_cond;
static const int negative_program[] = {-1,-1,-1,-1,-1,9,-1,7,0};
static const int zero_program[] = {0,0,0,0,0,9,-1,7,0};
static const int positive_program[] = {9,7,-1,-1,0,-1,9,-1};
static const int alternating_program[] = {-1,0,9,0,-1,7,-1};
static const int error_program[] = {-1,9,-1}, control_program[] = {9,-1};
static const int *program;
static unsigned program_size, step, cycle, callbacks, pumps, early_pumps;
static int read_labels[128];
static unsigned callback_labels[64][2];
static uint8_t wire[2][256];
static size_t wire_size[2];

static void require(bool value, const char *why) {
    if (!value) { fprintf(stderr, "polled discovery fixture: %s\n", why); abort(); }
}
time_t __wrap_time(time_t *out) {
    if (out) *out = 1000;
    return 1000; /* Protocol wall only; timer/condition clocks remain real. */
}
int __real_socket(int, int, int);
int __wrap_socket(int family, int type, int protocol) {
    require(family == AF_INET && type == SOCK_DGRAM && owned_fd == -1,
            "one IPv4 discovery descriptor");
    int fd = __real_socket(family, type, protocol);
    require(fd >= 0, "real socket creation");
    owned_fd = fd;
    ++opens;
    return fd;
}
int __real_close(int);
int __wrap_close(int fd) {
    if (fd == owned_fd) { owned_fd = -1; ++closes; }
    return __real_close(fd);
}
ssize_t __wrap_sendto(int fd, const void *data, size_t size, int flags,
                     const struct sockaddr *to, socklen_t length) {
    (void)data; (void)flags; (void)to; (void)length;
    require(fd == owned_fd && fd >= 0, "send uses retained live discovery descriptor");
    return (ssize_t)size; /* No fixture traffic leaves for a LAN. */
}
IHS_Thread *__real_IHS_ThreadCreate(IHS_ThreadFunction *, const char *, void *);
IHS_Thread *__wrap_IHS_ThreadCreate(IHS_ThreadFunction *fn, const char *name, void *ctx) {
    if (!strcmp(name, "IHSClient")) ++rx_workers;
    IHS_Thread *thread = __real_IHS_ThreadCreate(fn, name, ctx);
    if (!strcmp(name, "IHS.Timer")) timer_worker = thread;
    return thread;
}
void __real_IHS_ThreadJoin(IHS_Thread *);
void __wrap_IHS_ThreadJoin(IHS_Thread *thread) {
    __real_IHS_ThreadJoin(thread);
    if (thread && thread == timer_worker) ++timer_joins;
}
void __real_IHS_CondDestroy(IHS_Cond *);
void __wrap_IHS_CondDestroy(IHS_Cond *cond) {
    if (cond && cond == receive_cond) {
        require(timer_joins == 1, "actual timer join before client dependency destruction");
        ++cond_destroys;
    }
    __real_IHS_CondDestroy(cond);
}
ssize_t __wrap_recvfrom(int fd, void *data, size_t capacity, int flags,
                       struct sockaddr *from, socklen_t *length) {
    (void)flags;
    require(fd == owned_fd && fd >= 0, "receive uses retained live descriptor");
    int descriptor_flags = fcntl(fd, F_GETFL);
    require(descriptor_flags >= 0 && (descriptor_flags & O_NONBLOCK) != 0, "real nonblocking fd");
    require(step < 128 && capacity == 2048, "bounded real receive storage");
    int label = step < program_size ? program[step] : -1;
    read_labels[step++] = label;
    if (label <= 0) {
        ++cycle;
        errno = injected_errno;
        return label;
    }
    unsigned slot = label == 7;
    require(capacity >= wire_size[slot] && *length >= sizeof(struct sockaddr_in), "wire capacity");
    struct sockaddr_in source = {.sin_family = AF_INET, .sin_port = htons(27036),
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    memcpy(data, wire[slot], wire_size[slot]);
    memcpy(from, &source, sizeof(source));
    *length = sizeof(source);
    return (ssize_t)wire_size[slot];
}
static void collect_status(IHS_Client *client, const IHS_HostInfo *host,
                           const IHS_DiscoveryAddressHints *hints, void *ctx) {
    require(callbacks < 64 && host->hasTimestamp &&
                (host->timestamp == 9 || host->timestamp == 7), "parsed callback label");
    callback_labels[callbacks][0] = cycle;
    callback_labels[callbacks++][1] = (unsigned)host->timestamp;
    discovered_status(client, host, hints, ctx); /* Forward the production handler. */
}
static void make_wires(void) {
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_instance_id = header.has_msg_type = true;
    header.client_id = 123; header.instance_id = 456;
    header.msg_type = k_ERemoteClientBroadcastMsgStatus;
    CMsgRemoteClientBroadcastStatus status = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
    status.hostname = "polled fixture";
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
static void pump(sl_runtime *r, uint64_t now) {
    update_control(r, now);
    ++pumps;
    require(r->client && r->client->polled && !r->client->base.worker &&
                r->client->base.socket && opens == 1 && closes == 0 && rx_workers == 0,
            "polled owner and descriptor survive error");
}

int main(int argc, char **argv) {
    require(argc == 3, "errno and program");
    char *end;
    long number = strtol(argv[1], &end, 10);
    require(*argv[1] && !*end && number >= 0 && number < 4096, "errno input");
    injected_errno = (int)number;
    const char *name = argv[2];
#define SELECT(text, array) if (!strcmp(name, text)) { program = array; program_size = sizeof(array)/sizeof(array[0]); }
    SELECT("negative_then_recovery", negative_program)
    SELECT("zero_then_recovery", zero_program)
    SELECT("positive_before_error", positive_program)
    SELECT("alternating", alternating_program)
    SELECT("single_error", error_program)
    SELECT("control", control_program)
#undef SELECT
    require(program != NULL, "known program");
    alarm(5);
    make_wires();
    IHS_Init();
    sl_runtime r = {0};
    require(!pthread_mutex_init(&r.lock, NULL) && !pthread_cond_init(&r.wake, NULL), "runtime locks");
    sl_host_registry_init(&r.store.registry);
    r.config = (IHS_ClientConfig){.deviceId = 42, .secretKey = r.store.secret, .deviceName = "polled fixture"};
    require(start_client(&r), "production startup");
    IHS_Client *owner = r.client;
    IHS_UDPSocket *socket = owner->base.socket;
    receive_cond = owner->receiveWake;
    const IHS_ClientDiscoveryCallbacks callbacks_observer = {.status = collect_status};
    IHS_ClientSetDiscoveryCallbacks(owner, &callbacks_observer, &r);
    uint64_t now = 1000;
    while (step < program_size) {
        unsigned before = step, generation = (unsigned)owner->receiveGeneration;
        pump(&r, now);
        require(step > before && read_labels[step - 1] <= 0 &&
                    owner->receiveGeneration == generation + 1 && owner->base.socket == socket,
                "one complete batch per actor update");
        before = step;
        for (unsigned i = 0; i < 10; ++i) {
            pump(&r, now + (i ? 99 : 1));
            ++early_pumps;
        }
        require(step == before, "early actor pumps cannot receive or busy-retry");
        now += 100;
    }
    unsigned completed = cycle, count = step;
    /* A late tick starts just one batch; no catch-up burst at that timestamp. */
    now += 500;
    pump(&r, now);
    require(step == count + 1, "late update exactly one batch");
    pump(&r, now);
    pump(&r, now + 99);
    require(step == count + 1, "no catch-up reads");
    pump(&r, now + 100);
    require(step == count + 2, "next deadline permits one batch");
    unsigned visible = 0, events = 0;
    sl_directory_host *host = sl_directory_find(r.directory, 123);
    if (host && host->visible && !host->cloud && host->info.hasGamesRunning && !host->info.gamesRunning)
        visible = 1;
    sl_runtime_event event;
    while (sl_runtime_poll(&r, &event)) if (event.type == SL_EVENT_HOST) ++events;
    require(visible && events && callbacks, "production directory/UI event after recovery");
    IHS_ClientStop(owner);
    require(!IHS_ClientUpdate(owner, NULL, NULL, NULL) && step == count + 2,
            "stopped polled owner cannot read");
    stop_client(&r);
    require(!r.client && owned_fd == -1 && opens == closes && timer_joins == 1 &&
                cond_destroys == 1 && rx_workers == 0, "actual ownership cleanup");
    sl_directory_destroy(&r.directory);
    IHS_Quit();
    pthread_cond_destroy(&r.wake);
    pthread_mutex_destroy(&r.lock);
    alarm(0);
    printf("{\"errno\":%d,\"program\":\"%s\",\"polled\":true,\"cycles\":%u,\"reads\":[", injected_errno, name, completed);
    for (unsigned i = 0; i < count; ++i) printf("%s%d", i ? "," : "", read_labels[i]);
    printf("],\"callbacks\":[");
    for (unsigned i = 0; i < callbacks; ++i)
        printf("%s[%u,%u]", i ? "," : "", callback_labels[i][0], callback_labels[i][1]);
    printf("],\"actor_pumps\":%u,\"early_pumps\":%u,\"rx_workers\":%u,\"opens\":%u,\"closes\":%u,"
           "\"timer_joins\":%u,\"cond_destroys\":%u,\"directory_visible\":%u,\"host_events\":%u,"
           "\"late_no_catchup\":true,\"stopped_no_receive\":true,\"final_clean\":true}\n",
           pumps, early_pumps, rx_workers, opens, closes, timer_joins, cond_destroys, visible, events);
    return 0;
}
