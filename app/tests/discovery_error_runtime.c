/* Actual client/Base/pthread/POSIX receive/protobuf/callback/stop/join/destroy.
 * Only recvfrom is adapted: a controlled error, then a valid status datagram.
 * No real Steam, network change, DNS or Switch error occurrence is proved. */
#include "ihslib.h"
#include "client/client_pri.h"
#include "ihs_buffer.h"
#include "ihs_buffer_ext.h"
#include <arpa/inet.h>
#include <errno.h>
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
static unsigned char wire[256];
static size_t wire_size;

static void require(bool condition, const char *reason) {
    if (!condition) {
        fprintf(stderr, "discovery fixture: %s\n", reason);
        abort();
    }
}

ssize_t __wrap_recvfrom(int fd, void *buffer, size_t size, int flags,
                        struct sockaddr *from, socklen_t *from_size) {
    (void)fd;
    (void)flags;
    while (!atomic_load(&ready)) usleep(1000);
    unsigned step = atomic_fetch_add(&reads, 1);
    if (!step && injected_error) {
        errno = injected_error;
        return -1;
    }
    if (step == (unsigned)(injected_error != 0)) {
        require(size >= wire_size && *from_size >= sizeof(struct sockaddr_in), "receive capacity");
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(27036),
                                      .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        memcpy(from, &address, sizeof(address));
        *from_size = sizeof(address);
        memcpy(buffer, wire, wire_size);
        return (ssize_t)wire_size;
    }
    usleep(1000); /* adapter pacing, not proposed product policy */
    errno = EAGAIN;
    return -1;
}

static void discovered(IHS_Client *client, const IHS_HostInfo *host, void *context) {
    (void)client;
    (void)context;
    require(host->clientId == 123 && host->instanceId == 456, "identity");
    require(!strcmp(host->hostname, "fixture") && host->hasGamesRunning && host->gamesRunning == 0,
            "status fields");
    atomic_fetch_add(&delivered, 1);
}

int main(int argc, char **argv) {
    require(argc == 2, "one numeric errno argument required");
    char *end;
    long number = strtol(argv[1], &end, 10);
    require(*argv[1] && !*end && number >= 0 && number <= 4095, "errno range");
    injected_error = (int)number;
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
    IHS_Buffer buffer = IHS_BUFFER_WRAP(wire, sizeof(wire));
    buffer.size = 0;
    IHS_BufferAppendMem(&buffer, magic, sizeof(magic));
    size_t length = cmsg_remote_client_broadcast_header__get_packed_size(&header);
    IHS_BufferAppendUInt32LE(&buffer, length);
    buffer.size += cmsg_remote_client_broadcast_header__pack(&header, wire + buffer.size);
    length = cmsg_remote_client_broadcast_status__get_packed_size(&status);
    IHS_BufferAppendUInt32LE(&buffer, length);
    buffer.size += cmsg_remote_client_broadcast_status__pack(&status, wire + buffer.size);
    wire_size = buffer.size;
    IHS_Init();
    const uint8_t secret[32] = {0};
    IHS_ClientConfig config = {.deviceId = 42, .deviceName = "fixture", .secretKey = secret};
    IHS_Client *client = IHS_ClientCreate(&config);
    require(client != NULL, "client create");
    const IHS_ClientDiscoveryCallbacks callbacks = {.discovered = discovered};
    IHS_ClientSetDiscoveryCallbacks(client, &callbacks, NULL);
    atomic_store(&ready, true);
    bool socket_live = false;
    for (unsigned n = 0; n < 300; ++n) {
        IHS_BaseLock(&client->base);
        socket_live = client->base.socket != NULL;
        IHS_BaseUnlock(&client->base);
        if (atomic_load(&delivered) || (atomic_load(&reads) && !socket_live)) break;
        usleep(1000);
    }
    unsigned received = atomic_load(&delivered);
    IHS_ClientStopDiscovery(client);
    IHS_ClientStop(client);
    IHS_ClientThreadedJoin(client);
    require(client->base.socket == NULL && client->base.worker == NULL, "joined/closed");
    IHS_ClientDestroy(client);
    IHS_Quit();
    alarm(0);
    printf("{\"errno\":%d,\"reads\":%u,\"delivered\":%u,\"socket_live_before_stop\":%s,"
           "\"joined_closed_destroyed\":true}\n", injected_error, atomic_load(&reads), received,
           socket_live ? "true" : "false");
    return 0;
}
