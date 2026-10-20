/* Real client/Base/socket/timer/pthread cleanup and healthy UDP after a failed
 * construction. Resource-return failures are adapters; no Steam/Switch claim.
 * Include runtime to test its actual private registration/cleanup boundary. */
#include "../platforms/common/runtime.c"
#include "client/client_pri.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "ihs_queue.h"
#include "session/session_pri.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>

enum Fault { CLIENT_ALLOC, BASE_MUTEX, RECEIVE_COND, TIMER_NODE, TIMER_QUEUE,
             TIMER_MUTEX, TIMER_THREAD, SOCKET_ALLOC, SOCKET_FD, SOCKET_MUTEX,
             RX_THREAD, DISCOVERY_CONTEXT, DISCOVERY_TASK, SESSION_SEND_MUTEX,
             SESSION_RELIABLE_MUTEX, SESSION_SEND_QUEUE, SESSION_PENDING_QUEUE, NO_FAULT };
static const char *names[] = {"client_alloc", "base_mutex", "receive_cond", "timer_node",
    "timer_queue", "timer_mutex", "timer_thread", "socket_alloc", "socket_fd",
    "socket_mutex", "rx_thread", "discovery_context", "discovery_task",
    "send_mutex", "reliable_mutex", "send_queue", "pending_queue"};
static enum Fault fault = NO_FAULT;
static atomic_uint hits, receives, delivered;
static atomic_int live_mutex, live_cond, live_queue, live_rx, live_timer, live_socket, live_send;
static atomic_int owned_fd = -1;
static _Thread_local bool creating, in_timer, in_socket, in_discovery;
static _Atomic(IHS_Thread *) rx_thread, timer_thread, send_thread;
static IHS_Cond *associated_cond;
static bool app_mode, session_mode, reject_disable;
static unsigned pause_rejections;
static int baseline_mutex, baseline_cond, baseline_queue;
static unsigned session_mutex_calls, session_queue_calls;

static void require(bool value, const char *why) {
    if (!value) { fprintf(stderr, "startup fixture: %s\n", why); abort(); }
}
static bool inject(enum Fault mode) {
    if (fault != mode || atomic_load(&hits)) return false;
    atomic_fetch_add(&hits, 1);
    return true;
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size) {
    if ((creating && size == sizeof(IHS_Client) && inject(CLIENT_ALLOC)) ||
        (in_discovery && inject(DISCOVERY_CONTEXT))) return NULL;
    return __real_malloc(size);
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t size) {
    if (in_discovery && inject(DISCOVERY_CONTEXT)) return NULL;
    /* Release GCC folds malloc+memset into calloc (either argument order). */
    if (creating && ((n == 1 && size == sizeof(IHS_Client)) ||
                     (size == 1 && n == sizeof(IHS_Client))) && inject(CLIENT_ALLOC)) return NULL;
    if (creating && session_mode && n == 1 && size == sizeof(IHS_Session) && inject(CLIENT_ALLOC)) return NULL;
    if (in_socket && inject(SOCKET_ALLOC)) return NULL;
    return __real_calloc(n, size);
}
IHS_Mutex *__real_IHS_MutexCreate(void);
IHS_Mutex *__wrap_IHS_MutexCreate(void) {
    if (creating && session_mode && !in_timer && !in_socket) {
        unsigned call = ++session_mutex_calls;
        if ((call == 2 && inject(SESSION_SEND_MUTEX)) || (call == 3 && inject(SESSION_RELIABLE_MUTEX))) return NULL;
    }
    if ((in_socket && inject(SOCKET_MUTEX)) || (in_timer && inject(TIMER_MUTEX)) ||
        (creating && !in_socket && !in_timer && inject(BASE_MUTEX))) return NULL;
    IHS_Mutex *m = __real_IHS_MutexCreate();
    if (m) atomic_fetch_add(&live_mutex, 1);
    return m;
}
void __real_IHS_MutexDestroy(IHS_Mutex *);
void __wrap_IHS_MutexDestroy(IHS_Mutex *m) {
    require(m != NULL && atomic_fetch_sub(&live_mutex, 1) > 0, "valid mutex destroy");
    __real_IHS_MutexDestroy(m);
}
IHS_Cond *__real_IHS_CondCreate(void);
IHS_Cond *__wrap_IHS_CondCreate(void) {
    if (creating && inject(RECEIVE_COND)) return NULL;
    IHS_Cond *c = __real_IHS_CondCreate();
    if (c) atomic_fetch_add(&live_cond, 1);
    return c;
}
void __real_IHS_CondDestroy(IHS_Cond *);
void __wrap_IHS_CondDestroy(IHS_Cond *c) {
    if (c == associated_cond) require(!atomic_load(&live_rx), "RX join before condition destroy");
    require(c != NULL && atomic_fetch_sub(&live_cond, 1) > 0, "valid condition destroy");
    __real_IHS_CondDestroy(c);
}
IHS_Queue *__real_IHS_QueueCreate(size_t);
IHS_Queue *__wrap_IHS_QueueCreate(size_t size) {
    if (creating && session_mode && !in_timer) {
        unsigned call = ++session_queue_calls;
        if ((call == 1 && inject(SESSION_SEND_QUEUE)) || (call == 2 && inject(SESSION_PENDING_QUEUE))) return NULL;
    }
    if (in_timer && inject(TIMER_QUEUE)) return NULL;
    IHS_Queue *q = __real_IHS_QueueCreate(size);
    if (q) atomic_fetch_add(&live_queue, 1);
    return q;
}
void __real_IHS_QueueDestroy(IHS_Queue *, IHS_QueueConsumerFunction *, void *);
void __wrap_IHS_QueueDestroy(IHS_Queue *q, IHS_QueueConsumerFunction *fn, void *ctx) {
    require(q && atomic_fetch_sub(&live_queue, 1) > 0, "valid queue destroy");
    __real_IHS_QueueDestroy(q, fn, ctx);
}
IHS_QueueItem *__real_IHS_QueueItemObtain(IHS_Queue *);
IHS_QueueItem *__wrap_IHS_QueueItemObtain(IHS_Queue *q) {
    if ((in_timer && inject(TIMER_NODE)) || (in_discovery && inject(DISCOVERY_TASK))) return NULL;
    return __real_IHS_QueueItemObtain(q);
}
IHS_Timer *__real_IHS_TimerCreate(void);
IHS_Timer *__wrap_IHS_TimerCreate(void) {
    in_timer = true;
    IHS_Timer *t = __real_IHS_TimerCreate();
    in_timer = false;
    return t;
}
IHS_UDPSocket *__real_IHS_UDPSocketOpen(bool);
IHS_UDPSocket *__wrap_IHS_UDPSocketOpen(bool broadcast) {
    in_socket = true;
    IHS_UDPSocket *s = __real_IHS_UDPSocketOpen(broadcast);
    in_socket = false;
    return s;
}
int __real_socket(int, int, int);
int __wrap_socket(int family, int type, int protocol) {
    if (in_socket && inject(SOCKET_FD)) { errno = EMFILE; return -1; }
    int fd = __real_socket(family, type, protocol);
    if (in_socket && fd >= 0) {
        require(atomic_exchange(&owned_fd, fd) == -1, "one live client descriptor");
        atomic_fetch_add(&live_socket, 1);
    }
    return fd;
}
int __real_close(int);
int __wrap_close(int fd) {
    if (fd == atomic_load(&owned_fd)) {
        require(fd >= 0, "no invalid descriptor close");
        atomic_store(&owned_fd, -1);
        require(atomic_fetch_sub(&live_socket, 1) == 1, "close descriptor once");
    }
    return __real_close(fd);
}
IHS_Thread *__real_IHS_ThreadCreate(IHS_ThreadFunction *, const char *, void *);
IHS_Thread *__wrap_IHS_ThreadCreate(IHS_ThreadFunction *fn, const char *name, void *ctx) {
    bool rx = !strcmp(name, "IHSClient") || !strcmp(name, "IHSSession");
    bool timer = !strcmp(name, "IHS.Timer"), send = !strcmp(name, "IHSSessSend");
    if ((rx && inject(RX_THREAD)) || (timer && inject(TIMER_THREAD))) return NULL;
    IHS_Thread *t = __real_IHS_ThreadCreate(fn, name, ctx);
    if (t && rx) { rx_thread = t; atomic_fetch_add(&live_rx, 1); }
    if (t && timer) { timer_thread = t; atomic_fetch_add(&live_timer, 1); }
    if (t && send) { send_thread = t; atomic_fetch_add(&live_send, 1); }
    return t;
}
void __real_IHS_ThreadJoin(IHS_Thread *t);
void __wrap_IHS_ThreadJoin(IHS_Thread *t) {
    bool rx = t && t == rx_thread, timer = t && t == timer_thread, send = t && t == send_thread;
    __real_IHS_ThreadJoin(t);
    if (rx) { atomic_fetch_sub(&live_rx, 1); rx_thread = NULL; }
    if (timer) { atomic_fetch_sub(&live_timer, 1); timer_thread = NULL; }
    if (send) { atomic_fetch_sub(&live_send, 1); send_thread = NULL; }
}
IHS_Client *__real_IHS_ClientCreate(const IHS_ClientConfig *);
IHS_Client *__wrap_IHS_ClientCreate(const IHS_ClientConfig *cfg) {
    creating = true;
    IHS_Client *c = __real_IHS_ClientCreate(cfg);
    creating = false;
    if (c) associated_cond = c->receiveWake;
    return c;
}
bool __real_IHS_ClientEnableDiscovery(IHS_Client *);
bool __wrap_IHS_ClientEnableDiscovery(IHS_Client *c) {
    in_discovery = true;
    bool result = __real_IHS_ClientEnableDiscovery(c);
    in_discovery = false;
    return result;
}
bool __real_IHS_ClientDisableDiscovery(IHS_Client *);
bool __wrap_IHS_ClientDisableDiscovery(IHS_Client *c) {
    if (reject_disable) { ++pause_rejections; return false; }
    return __real_IHS_ClientDisableDiscovery(c);
}
int __real_IHS_UDPSocketReceive(IHS_UDPSocket *, IHS_UDPPacket *);
int __wrap_IHS_UDPSocketReceive(IHS_UDPSocket *s, IHS_UDPPacket *p) {
    atomic_fetch_add(&receives, 1);
    return __real_IHS_UDPSocketReceive(s, p);
}
ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t __wrap_sendto(int fd, const void *bytes, size_t n, int flags,
                      const struct sockaddr *to, socklen_t size) {
    const struct sockaddr_in *a = (const void *)to;
    if (a->sin_family != AF_INET || a->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        require(app_mode, "no external fixture datagram");
        return (ssize_t)n; /* app periodic broadcast terminal, no network I/O */
    }
    return __real_sendto(fd, bytes, n, flags, to, size);
}
static void balanced(bool global_alive) {
    require(!atomic_load(&live_socket) && !atomic_load(&live_rx) &&
            !atomic_load(&live_timer) && !atomic_load(&live_send), "no socket/worker leak");
    require(atomic_load(&live_cond) == (global_alive ? baseline_cond : 0) &&
            atomic_load(&live_mutex) == (global_alive ? baseline_mutex : 0) &&
            atomic_load(&live_queue) == (global_alive ? baseline_queue : 0), "resource counts return to baseline");
}
static void found(IHS_Client *c, const IHS_HostInfo *h, void *ctx) {
    (void)c; (void)ctx;
    require(h->clientId == 123 && h->instanceId == 456 && !strcmp(h->hostname, "startup fixture") &&
            h->hasGamesRunning && h->gamesRunning == 0, "actual decoded Status fields");
    atomic_fetch_add(&delivered, 1);
}
static void exercise(IHS_Client *c) {
    int peer = __real_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    require(peer >= 0, "loopback peer socket");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    require(!bind(peer, (void *)&address, sizeof(address)), "loopback bind");
    socklen_t size = sizeof(address);
    require(!getsockname(peer, (void *)&address, &size), "loopback endpoint");
    struct timeval timeout = {.tv_sec = 2};
    require(!setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), "peer timeout");
    const IHS_ClientDiscoveryCallbacks callbacks = {.discovered = found};
    IHS_ClientSetDiscoveryCallbacks(c, &callbacks, NULL);
    IHS_SocketAddress destination = {.port = ntohs(address.sin_port)};
    require(IHS_IPAddressFromString(&destination.ip, "127.0.0.1"), "peer address");
    CMsgRemoteClientBroadcastDiscovery request = CMSG_REMOTE_CLIENT_BROADCAST_DISCOVERY__INIT;
    require(IHS_ClientSend(c, destination, k_ERemoteClientBroadcastMsgDiscovery, (void *)&request), "actual discovery send");
    uint8_t wire[512];
    struct sockaddr_in sender;
    size = sizeof(sender);
    require(recvfrom(peer, wire, sizeof(wire), 0, (void *)&sender, &size) > 16, "actual request received");
    CMsgRemoteClientBroadcastHeader header = CMSG_REMOTE_CLIENT_BROADCAST_HEADER__INIT;
    header.has_client_id = header.has_instance_id = header.has_msg_type = true;
    header.client_id = 123; header.instance_id = 456; header.msg_type = k_ERemoteClientBroadcastMsgStatus;
    CMsgRemoteClientBroadcastStatus status = CMSG_REMOTE_CLIENT_BROADCAST_STATUS__INIT;
    status.hostname = "startup fixture"; status.has_games_running = true;
    IHS_Buffer b = IHS_BUFFER_WRAP(wire, sizeof(wire)); b.size = 0;
    const uint8_t magic[] = {255,255,255,255,0x21,0x4c,0x5f,0xa0};
    IHS_BufferAppendMem(&b, magic, sizeof(magic));
    IHS_BufferAppendUInt32LE(&b, cmsg_remote_client_broadcast_header__get_packed_size(&header));
    IHS_BufferAppendMessage(&b, (void *)&header);
    IHS_BufferAppendUInt32LE(&b, cmsg_remote_client_broadcast_status__get_packed_size(&status));
    IHS_BufferAppendMessage(&b, (void *)&status);
    require(__real_sendto(peer, wire, b.size, 0, (void *)&sender, size) == (ssize_t)b.size, "actual Status reply");
    for (unsigned i = 0; i < 2000 && !atomic_load(&delivered); ++i) usleep(1000);
    require(atomic_load(&delivered) == 1, "healthy retry actually receives Status");
    __real_close(peer);
}
static atomic_uint session_initialized, session_finalized;
static void session_started(IHS_Session *s, void *unused) {
    (void)s; (void)unused;
    atomic_fetch_add(&session_initialized, 1);
}
static void session_finished(IHS_Session *s, void *unused) {
    (void)s; (void)unused;
    atomic_fetch_add(&session_finalized, 1);
}
static const IHS_StreamSessionCallbacks session_callbacks = {.initialized = session_started, .finalized = session_finished};
static IHS_Session *make_session(const IHS_ClientConfig *config, const IHS_SessionInfo *info) {
    session_mutex_calls = session_queue_calls = 0;
    creating = true;
    IHS_Session *s = IHS_SessionCreate(config, info);
    creating = false;
    return s;
}
static void exercise_session(unsigned mode, const IHS_ClientConfig *config) {
    int peer = __real_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    require(peer >= 0, "session peer socket");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    require(!bind(peer, (void *)&address, sizeof(address)), "session peer bind");
    socklen_t size = sizeof(address);
    require(!getsockname(peer, (void *)&address, &size), "session peer endpoint");
    struct timeval timeout = {.tv_sec = 2};
    require(!setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), "session peer timeout");
    IHS_SessionInfo info = {.address.port = ntohs(address.sin_port), .sessionKeyLen = 32};
    require(IHS_IPAddressFromString(&info.address.ip, "127.0.0.1"), "session peer address");
    bool construction_failure = mode < SOCKET_ALLOC || mode >= SESSION_SEND_MUTEX;
    IHS_Session *s = NULL;
    if (construction_failure) {
        s = make_session(config, &info);
        require(atomic_load(&hits) == 1 && !s, "session constructor propagates failed resource");
        balanced(true);
    } else {
        fault = NO_FAULT;
        s = make_session(config, &info);
        require(s != NULL && IHS_SessionConfigureNetworkTest(s, IHS_NetworkTestFixed, 20000), "session configuration");
        IHS_SessionSetSessionCallbacks(s, &session_callbacks, NULL);
        fault = (enum Fault)mode;
        require(!IHS_SessionConnect(s), "failed Connect reports false synchronously");
        IHS_NetworkTestResult result;
        IHS_SessionGetNetworkTestResult(s, &result);
        require(result.status == IHS_NetworkTestFailed && s->networkTest.phase == 0 &&
                result.frameSpan == 0 && result.samples == 0, "existing network-test finalization without completed samples");
        require(!s->base.worker && !s->base.socket && !s->sendThread &&
                !atomic_load(&live_socket) && !atomic_load(&live_rx) && !atomic_load(&live_send), "failed Connect has no workers/socket");
        require(!atomic_load(&session_initialized) && !atomic_load(&session_finalized) &&
                !atomic_load(&receives), "failed Connect executes no lifecycle or receive callbacks");
    }
    require(atomic_load(&hits) == 1, "one session fault consumed");
    unsigned before = atomic_load(&receives);
    usleep(300000);
    require(atomic_load(&receives) == before, "session failure does not implicitly retry");
    uint8_t wire[1024];
    require(recvfrom(peer, wire, sizeof(wire), MSG_DONTWAIT, NULL, NULL) < 0 &&
                (errno == EAGAIN || errno == EWOULDBLOCK), "no premature session datagram");
    fault = NO_FAULT;
    if (!s) s = make_session(config, &info);
    require(s != NULL, "session explicit construction retry");
    if (construction_failure) {
        require(IHS_SessionConfigureNetworkTest(s, IHS_NetworkTestFixed, 20000), "retry network-test configuration");
        IHS_SessionSetSessionCallbacks(s, &session_callbacks, NULL);
    }
    require(IHS_SessionConnect(s), "explicit Connect after resources recover");
    struct sockaddr_in from;
    size = sizeof(from);
    ssize_t count = recvfrom(peer, wire, sizeof(wire), 0, (void *)&from, &size);
    require(count >= 13 && (wire[0] & 127) == IHS_SessionPacketTypeConnect, "real session Connect datagram");
    uint8_t ack[17] = {0};
    IHS_Buffer b = IHS_BUFFER_WRAP(ack, sizeof(ack)); b.size = 0;
    IHS_SessionPacketHeader header = {.type = IHS_SessionPacketTypeConnectACK,
        .srcConnectionId = 34, .dstConnectionId = wire[2], .sendTimestamp = IHS_SessionPacketTimestamp()};
    IHS_SessionPacketHeaderSerialize(&header, &b);
    IHS_BufferAppendMem(&b, wire + 9, 4);
    require(__real_sendto(peer, ack, b.size, 0, (void *)&from, size) == (ssize_t)b.size, "real session ConnectACK");
    for (unsigned i = 0; i < 2000 && IHS_SessionTransportState(s) != IHS_TransportConnected; ++i) usleep(1000);
    require(IHS_SessionTransportState(s) == IHS_TransportConnected &&
                atomic_load(&session_initialized) == 1, "actual session transport accepts ACK after retry");
    IHS_SessionDisconnect(s);
    IHS_SessionThreadedJoin(s);
    require(atomic_load(&session_finalized) == 1 && !atomic_load(&live_send), "session stop joins send owner before final callback");
    IHS_SessionDestroy(s);
    __real_close(peer);
    balanced(true);
}
int main(int argc, char **argv) {
    require(argc == 2, "one resource-failure mode");
    bool pause_mode = !strcmp(argv[1], "pause_rejection");
    unsigned mode;
    session_mode = !strncmp(argv[1], "session_", 8);
    const char *mode_name = argv[1] + (session_mode ? 8 : 0);
    for (mode = 0; mode < NO_FAULT && strcmp(mode_name, names[mode]); ++mode) {}
    require(mode < NO_FAULT || pause_mode, "known resource mode");
    require(pause_mode || (session_mode ? (mode <= RX_THREAD || mode >= SESSION_SEND_MUTEX) : mode <= DISCOVERY_TASK), "owner resource mode");
    alarm(8);
    IHS_Init();
    baseline_mutex = atomic_load(&live_mutex);
    baseline_cond = atomic_load(&live_cond);
    baseline_queue = atomic_load(&live_queue);
    balanced(true);
    fault = (enum Fault)mode;
    uint8_t secret[32] = {0};
    IHS_ClientConfig config = {.deviceId = 42, .secretKey = secret, .deviceName = "startup fixture"};
    if (pause_mode) {
        sl_runtime r = {0};
        require(!pthread_mutex_init(&r.lock, NULL), "runtime mutex");
        r.config = config;
        require(start_client(&r) && r.discovery_subscription, "real runtime discovery subscription");
        reject_disable = true;
        require(!pause_discovery(&r) && r.discovery_subscription && pause_rejections == 1,
                "rejected Disable preserves runtime subscription for explicit retry");
        reject_disable = false;
        require(pause_discovery(&r) && !r.discovery_subscription, "explicit pause retry accepted");
        require(pause_discovery(&r) && !r.discovery_subscription, "already paused is idempotent");
        require(start_discovery(&r) && r.discovery_subscription, "resume adds fresh balanced reference");
        stop_client(&r);
        balanced(true);
        IHS_Quit(); balanced(false);
        pthread_mutex_destroy(&r.lock);
        alarm(0);
        printf("{\"pause_rejections\":%u,\"retry_balanced\":true,\"final_clean\":true}\n", pause_rejections);
        return 0;
    }
    if (session_mode) {
        exercise_session(mode, &config);
        IHS_Quit(); balanced(false);
        alarm(0);
        printf("{\"mode\":\"%s\",\"fault_hits\":%u,\"failure_clean\":true,\"no_implicit_retry\":true,"
               "\"explicit_retry_transport\":true,\"final_clean\":true}\n", argv[1], atomic_load(&hits));
        return 0;
    }
    sl_runtime r = {0};
    require(!pthread_mutex_init(&r.lock, NULL), "runtime mutex");
    r.config = config;
    app_mode = mode == DISCOVERY_CONTEXT || mode == DISCOVERY_TASK;
    if (app_mode) {
        require(!start_client(&r) && !r.client, "registration failure cleans actual runtime client");
    } else {
        IHS_Client *failed = IHS_ClientCreate(&config);
        require(atomic_load(&hits) == 1, "fault observed before constructor returns");
        require(!failed, "startup failure must return NULL");
    }
    require(atomic_load(&hits) == 1, "requested fault executed once");
    balanced(true);
    unsigned reads_before = atomic_load(&receives);
    usleep(300000);
    require(atomic_load(&receives) == reads_before, "failed startup never implicitly restarts RX");
    fault = NO_FAULT;
    IHS_Client *c;
    if (app_mode) { require(start_client(&r) && r.client, "explicit runtime retry"); c = r.client; }
    else { c = IHS_ClientCreate(&config); require(c != NULL, "explicit healthy retry"); }
    exercise(c);
    if (app_mode) stop_client(&r);
    else { IHS_ClientStop(c); IHS_ClientThreadedJoin(c); IHS_ClientDestroy(c); }
    balanced(true);
    IHS_Quit(); balanced(false);
    pthread_mutex_destroy(&r.lock);
    alarm(0);
    printf("{\"mode\":\"%s\",\"fault_hits\":%u,\"failure_clean\":true,\"no_implicit_retry\":true,"
           "\"explicit_retry_status\":%u,\"final_clean\":true}\n", argv[1], atomic_load(&hits), atomic_load(&delivered));
    return 0;
}
