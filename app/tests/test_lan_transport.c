/* Native UDP peer, without Steam, SNS, or the external transport vtable.
 * Wire expectations: STEAMLINK_PROTOCOL_RE connection/control packet format.
 * Also compiled against the pre-Anywhere IHS pin during regression diagnosis. */
#include "ihslib.h"
#include "ihslib/session.h"
#include "protobuf/remoteplay.pb-c.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static atomic_bool finalized;
/* Bitwise Castagnoli oracle, independent of the library's optimized CRC path. */
static uint32_t wire_crc(const uint8_t *bytes, size_t size) {
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < size; ++i) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((0u - (crc & 1)) & 0x82f63b78u);
    }
    return ~crc;
}
static void check_crc(const uint8_t *bytes, size_t size) {
    uint32_t actual = 0;
    for (unsigned i = 0; i < 4; ++i)
        actual |= (uint32_t)bytes[size - 4 + i] << (8 * i);
    assert(actual == wire_crc(bytes, size - 4));
}
static void finished(IHS_Session *session, void *context) {
    (void)session;
    (void)context;
    atomic_store(&finalized, true);
}
static void run(void) {
    int peer = socket(AF_INET, SOCK_DGRAM, 0);
    assert(peer >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(peer, (struct sockaddr *)&address, sizeof(address)));
    socklen_t size = sizeof(address);
    assert(!getsockname(peer, (struct sockaddr *)&address, &size));
    struct timeval timeout = {.tv_sec = 1};
    assert(!setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    uint8_t key[32] = {1};
    IHS_ClientConfig config = {.deviceId = 123, .deviceName = "native UDP test", .secretKey = key};
    IHS_SessionInfo info = {.address = {.port = ntohs(address.sin_port),
                                        .ip.v4 = {IHS_IPAddressFamilyIPv4, {127, 0, 0, 1}}},
                            .sessionKeyLen = sizeof(key)};
    memcpy(info.sessionKey, key, sizeof(key));
    atomic_store(&finalized, false);
    IHS_Session *session = IHS_SessionCreate(&config, &info);
    assert(session);
    IHS_StreamSessionCallbacks callbacks = {.finalized = finished};
    IHS_SessionSetSessionCallbacks(session, &callbacks, NULL);
    assert(IHS_SessionConnect(session));
    uint8_t bytes[2048];
    struct sockaddr_in client;
    size = sizeof(client);
    ssize_t n = recvfrom(peer, bytes, sizeof(bytes), 0, (struct sockaddr *)&client, &size);
    /* CRC flag, Connect=1, channel 0, fragment/packet 0, "Connect" CRC body. */
    assert(n == 21 && bytes[0] == 0x81 && bytes[1] == 0 && bytes[3] == 0 && bytes[4] == 0);
    assert(!memcmp(bytes + 5, "\0\0\0\0", 4));
    assert(!memcmp(bytes + 13, "\xc7\x3d\x8f\x3c", 4));
    check_crc(bytes, n);
    uint8_t local = bytes[2];
    /* Deliberately independent serialization: ConnectACK=2, no CRC, host ID 23. */
    uint8_t ack[13] = {2, 0, 23};
    ack[3] = local;
    assert(sendto(peer, ack, sizeof(ack), 0, (struct sockaddr *)&client, size) == sizeof(ack));
    bool handshake = false;
    for (unsigned i = 0; i < 20 && !handshake; ++i) {
        n = recv(peer, bytes, sizeof(bytes), 0);
        assert(n >= 13);
        if ((bytes[0] & 127) != 5 || bytes[4] != 1)
            continue;
        assert(bytes[2] == local && bytes[3] == 23 && (bytes[0] & 128));
        assert(n >= 18 && bytes[13] == k_EStreamControlClientHandshake);
        check_crc(bytes, n);
        CClientHandshakeMsg *message = cclient_handshake_msg__unpack(NULL, n - 18, bytes + 14);
        assert(message && message->info && !message->info->network_test);
        cclient_handshake_msg__free_unpacked(message, NULL);
        handshake = true;
    }
    assert(handshake);
    /* Neither a stale destination ID nor a corrupt CRC may close this session. */
    uint8_t invalid[17] = {0x89, 0, 23};
    invalid[3] = local;
    uint32_t bad_crc = wire_crc(invalid, 13) ^ 1;
    for (unsigned i = 0; i < 4; ++i)
        invalid[13 + i] = bad_crc >> (8 * i);
    assert(sendto(peer, invalid, sizeof(invalid), 0, (struct sockaddr *)&client, size) ==
           sizeof(invalid));
    uint8_t stop[13] = {9, 0, 23};
    stop[3] = local + 1;
    assert(sendto(peer, stop, sizeof(stop), 0, (struct sockaddr *)&client, size) == sizeof(stop));
    usleep(20000);
    assert(!atomic_load(&finalized));
    stop[3] = local;
    assert(sendto(peer, stop, sizeof(stop), 0, (struct sockaddr *)&client, size) == sizeof(stop));
    IHS_SessionThreadedJoin(session);
    assert(atomic_load(&finalized));
    assert(IHS_SessionHostRequestedStop(session));
    IHS_SessionDestroy(session);
    close(peer);
}
int main(void) {
    alarm(15);
    IHS_Init();
    for (unsigned i = 0; i < 16; ++i)
        run();
    IHS_Quit();
    puts("native UDP: 16 fresh Connect/ConnectACK/ClientHandshake/validated Disconnect cycles "
         "passed");
}
