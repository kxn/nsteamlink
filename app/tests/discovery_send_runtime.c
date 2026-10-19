/* Actual client/UDP/protobuf/RX/cleanup. sendto error and loopback destination
 * adapters model a poisoned descriptor generation, not an observed Switch bug. */
#include "client/client_pri.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include "ihslib.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
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
static bool poisoned, cadence;
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
int __real_socket(int, int, int);
int __wrap_socket(int family, int type, int protocol) {
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
    if (fd == client_fd) {
        client_fd = -1;
        atomic_fetch_add(&closes, 1);
    }
    return __real_close(fd);
}
size_t __wrap_IHS_UDPBroadcastAddresses(IHS_IPAddress *out, size_t count) {
    (void)out;
    (void)count;
    return 0;
}
ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t __wrap_sendto(int fd, const void *bytes, size_t length, int flags,
                      const struct sockaddr *to, socklen_t size) {
    (void)size;
    const struct sockaddr_in *a = (void *)to;
    require(a->sin_family == AF_INET && a->sin_addr.s_addr == INADDR_BROADCAST &&
                ntohs(a->sin_port) == 27036,
            "only a controlled broadcast is admitted");
    require(length <= sizeof(captured), "wire capture budget before any copy");
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
    if (!cadence && (count == 0 || (poisoned && atomic_load(&opens) == 1))) {
        errno = error_mode;
        return -1;
    }
    ssize_t sent =
        __real_sendto(fd, bytes, length, flags, (void *)&peer_address, sizeof(peer_address));
    if (sent == (ssize_t)length)
        atomic_fetch_add(&forwarded, 1);
    return sent;
}
static void found(IHS_Client *c, const IHS_HostInfo *h, void *unused) {
    (void)c;
    (void)unused;
    require(h->clientId == 123 && h->instanceId == 456 && !strcmp(h->hostname, "send fixture"),
            "actual parsed status");
    require(h->hasGamesRunning && h->gamesRunning == 0, "zero games still discovered");
    atomic_fetch_add(&delivered, 1);
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
    require(__real_sendto(peer, bytes, b.size, 0, (void *)&from, size) == (ssize_t)b.size,
            "actual peer status reply");
    for (unsigned i = 0; i < 2000 && !atomic_load(&delivered); ++i)
        usleep(1000);
    require(atomic_load(&delivered) == 1, "actual client RX and callback");
}
int main(int argc, char **argv) {
    require(argc == 2, "transient|poisoned|host|cadence mode");
    poisoned = !strcmp(argv[1], "poisoned");
    cadence = !strcmp(argv[1], "cadence");
    if (!strcmp(argv[1], "host"))
        error_mode = EHOSTUNREACH;
    require(cadence || poisoned || !strcmp(argv[1], "transient") || !strcmp(argv[1], "host"),
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
    bool result =
        IHS_ClientBroadcast(client, k_ERemoteClientBroadcastMsgDiscovery, (void *)&message);
    reply_if_delivered();
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
