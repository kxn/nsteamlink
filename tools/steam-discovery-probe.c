/* Standalone UDP discovery experiment for desktop/Android. No authorization or stream request.
 * Wire source: IHSlib src/client/client.c, protobuf/discovery.proto.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static size_t put_varint(uint8_t *out, uint64_t value) {
    size_t n = 0;
    while (value > 127) {
        out[n++] = (uint8_t)(value | 128);
        value >>= 7;
    }
    out[n++] = (uint8_t)value;
    return n;
}

static double seconds(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec + now.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    const char *target = argc > 1 ? argv[1] : "255.255.255.255";
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(27036)};
    if (argc > 2 || inet_pton(AF_INET, target, &address.sin_addr) != 1) {
        fprintf(stderr, "usage: steam-discovery-probe [numeric-ipv4]\n");
        return 2;
    }
    uint8_t packet[64] = {0xff, 0xff, 0xff, 0xff, 0x21, 0x4c, 0x5f, 0xa0};
    uint8_t header[20] = {0x08}; /* client_id: uint64, msg_type: discovery (0) */
    uint64_t client = UINT64_C(0x4e534c0000000000) ^ (uint64_t)time(NULL) ^ (uint64_t)getpid();
    size_t header_size = 1 + put_varint(header + 1, client);
    header[header_size++] = 0x10;
    header[header_size++] = 0;
    packet[8] = (uint8_t)header_size; /* length prefixes are little-endian uint32 */
    memcpy(packet + 12, header, header_size);
    packet[12 + header_size] = 2;
    packet[16 + header_size] = 0x08; /* discovery.seq_num = 1 */
    packet[17 + header_size] = 1;
    size_t size = 18 + header_size;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0 ||
        sendto(fd, packet, size, 0, (void *)&address, sizeof(address)) != (ssize_t)size) {
        printf("{\"stage\":\"send_failed\",\"errno\":%d}\n", errno);
        close(fd);
        return 1;
    }
    printf("{\"stage\":\"sent\",\"target\":\"%s\",\"bytes\":%zu}\n", target, size);
    fflush(stdout);
    double deadline = seconds() + 2;
    unsigned replies = 0;
    bool failed = false;
    while (seconds() < deadline) {
        double remaining = deadline - seconds();
        if (remaining <= 0)
            break;
        struct timeval timeout = {.tv_sec = (time_t)remaining,
                                  .tv_usec = (suseconds_t)((remaining - (time_t)remaining) * 1e6)};
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);
        int ready = select(fd + 1, &read_set, NULL, NULL, &timeout);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0) {
            failed = true;
            break;
        }
        if (!ready)
            break;
        uint8_t data[65536];
        socklen_t length = sizeof(address);
        ssize_t count = recvfrom(fd, data, sizeof(data), 0, (void *)&address, &length);
        if (count < 0) {
            failed = true;
            break;
        }
        if (count < 8 || memcmp(data, packet, 8) != 0)
            continue;
        char source[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, source, sizeof(source));
        printf("{\"stage\":\"reply\",\"source\":\"%s\",\"port\":%u,\"bytes\":%zd}\n", source,
               ntohs(address.sin_port), count);
        replies++;
    }
    close(fd);
    printf("{\"stage\":\"complete\",\"replies\":%u,\"socket_error\":%s}\n", replies,
           failed ? "true" : "false");
    /* No replies is a valid experiment result, not a successful discovery claim. */
    return failed ? 1 : 0;
}
