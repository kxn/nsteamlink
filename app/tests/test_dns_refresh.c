#include "dns_refresh.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static void put16(uint8_t *p, unsigned n) {
    p[0] = (uint8_t)(n >> 8);
    p[1] = (uint8_t)n;
}
static int server(struct sockaddr_in *address) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(fd >= 0);
    *address =
        (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(fd, (struct sockaddr *)address, sizeof(*address)) == 0);
    socklen_t size = sizeof(*address);
    assert(getsockname(fd, (struct sockaddr *)address, &size) == 0);
    struct timeval timeout = {.tv_usec = 100000};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    return fd;
}
static size_t query(int fd, struct sockaddr_in *client, uint8_t *out) {
    socklen_t size = sizeof(*client);
    ssize_t n = recvfrom(fd, out, 512, 0, (struct sockaddr *)client, &size);
    static const uint8_t question[] = {3,   'a', 'p', 'i', 12,  's', 't', 'e', 'a',
                                       'm', 'p', 'o', 'w', 'e', 'r', 'e', 'd', 3,
                                       'c', 'o', 'm', 0,   0,   1,   0,   1};
    assert(n == 12 + sizeof(question));
    assert(!memcmp(out + 12, question, sizeof(question)));
    assert(out[2] == 1 && out[3] == 0 && out[5] == 1);
    return (size_t)n;
}
static void send_reply(int fd, const struct sockaddr_in *client, const uint8_t *bytes, size_t n) {
    assert(sendto(fd, bytes, n, 0, (const struct sockaddr *)client, sizeof(*client)) == (ssize_t)n);
}
static size_t rr(uint8_t *p, unsigned name, unsigned type, const void *data, unsigned length) {
    put16(p, 0xc000 | name);
    put16(p + 2, type);
    put16(p + 4, 1);
    memset(p + 6, 0, 4);
    put16(p + 10, length);
    memcpy(p + 12, data, length);
    return 12 + length;
}
static size_t simple_answer(uint8_t *packet, size_t qsize) {
    put16(packet + 2, 0x8180);
    put16(packet + 6, 1);
    const uint8_t address[] = {198, 51, 100, 7};
    return qsize + rr(packet + qsize, 12, 1, address, sizeof(address));
}
static void invalid_replies(void) {
    sl_dns_config config = {.count = 1};
    int fd = server(&config.servers[0]);
    for (unsigned variant = 0; variant < 8; ++variant) {
        sl_dns_refresh d = {.fd = -1};
        assert(sl_dns_refresh_begin(&d, &config, "api.steampowered.com", 1000));
        int old_fd = d.fd;
        uint8_t packet[512], good[512];
        struct sockaddr_in client;
        size_t qsize = query(fd, &client, packet), size = simple_answer(packet, qsize);
        memcpy(good, packet, size);
        switch (variant) {
        case 0:
            packet[0] ^= 1;
            break; /* Wrong transaction. */
        case 1:
            packet[2] |= 2;
            break; /* Truncated response. */
        case 2:
            packet[qsize - 3] = 28;
            break; /* AAAA question. */
        case 3:
            put16(packet + qsize, 0xc000 | qsize);
            break; /* Compression loop. */
        case 4:
            put16(packet + qsize + 10, 511);
            break; /* RDATA beyond packet. */
        case 5:
            packet[7] = 33;
            break; /* Resource bound. */
        case 6:
            packet[3] |= 3;
            break; /* NXDOMAIN. */
        case 7:
            packet[qsize + 3] = 28;
            break; /* AAAA answer cannot provide an A. */
        }
        send_reply(fd, &client, packet, size);
        assert(sl_dns_refresh_poll(&d, 1001) == 0);
        /* A packet from a different source port is never accepted. */
        struct sockaddr_in other_address;
        int other = server(&other_address);
        send_reply(other, &client, good, size);
        close(other);
        assert(sl_dns_refresh_poll(&d, 1002) == 0);
        send_reply(fd, &client, good, size);
        assert(sl_dns_refresh_poll(&d, 1003) == 1);
        assert(!strcmp(d.addresses, "198.51.100.7"));
        assert(d.fd == -1 && fcntl(old_fd, F_GETFD) == -1 && errno == EBADF);
        sl_dns_refresh_cancel(&d);
    }
    close(fd);
}
static void cname_and_timeout(void) {
    sl_dns_config config = {.count = 2};
    int first = server(&config.servers[0]), second = server(&config.servers[1]);
    sl_dns_refresh d = {.fd = -1};
    assert(sl_dns_refresh_begin(&d, &config, "api.steampowered.com", 1000));
    uint8_t packet[512];
    struct sockaddr_in client;
    query(first, &client, packet);
    assert(sl_dns_refresh_poll(&d, 2499) == 0 && d.attempt == 1);
    assert(sl_dns_refresh_poll(&d, 2500) == 0 && d.attempt == 2);
    size_t qsize = query(second, &client, packet), p = qsize;
    put16(packet + 2, 0x8180);
    put16(packet + 6, 4);
    /* Answers deliberately precede the CNAME that authorizes their owner. */
    const uint8_t alias[] = {4, 'e', 'd', 'g', 'e', 4, 't', 'e', 's', 't', 0};
    memcpy(packet + p, alias, sizeof(alias));
    p += sizeof(alias);
    put16(packet + p, 1);
    put16(packet + p + 2, 1);
    memset(packet + p + 4, 0, 4);
    put16(packet + p + 8, 4);
    const uint8_t address[] = {198, 51, 100, 1}, address2[] = {198, 51, 100, 2};
    memcpy(packet + p + 10, address, 4);
    p += 14;
    p += rr(packet + p, (unsigned)qsize, 1, address2, 4);
    uint8_t target[2];
    put16(target, 0xc000 | (unsigned)qsize);
    p += rr(packet + p, 12, 5, target, sizeof(target));
    /* An unrelated additional A answer must not become a connection target. */
    p += rr(packet + p, (unsigned)qsize + 5, 1, address, 4);
    send_reply(second, &client, packet, p);
    assert(sl_dns_refresh_poll(&d, 2501) == 1);
    assert(!strcmp(d.addresses, "198.51.100.1,198.51.100.2"));
    assert(d.fd == -1);
    /* Two DNS servers, two rounds, no reply: six seconds total by owner ticks. */
    assert(sl_dns_refresh_begin(&d, &config, "api.steampowered.com", 3000));
    for (uint64_t now = 4500; now < 9000; now += 1500)
        assert(sl_dns_refresh_poll(&d, now) == 0);
    assert(sl_dns_refresh_poll(&d, 9000) == -1 && d.fd == -1 && d.attempt == 4);
    assert(sl_dns_refresh_begin(&d, &config, "api.steampowered.com", 10000));
    int old_fd = d.fd;
    sl_dns_refresh_cancel(&d);
    assert(fcntl(old_fd, F_GETFD) == -1 && errno == EBADF);
    assert(sl_dns_refresh_poll(&d, 10001) == -1);
    assert(sl_dns_refresh_begin(&d, &config, "api.steampowered.com", 10000));
    assert(sl_dns_refresh_poll(&d, 100000) == -1 && d.fd == -1);
    assert(!sl_dns_refresh_begin(&d, &config, "bad..test", 11000));
    assert(!sl_dns_refresh_begin(&d, &config, "api.steampowered.com.", 11000));
    assert(!sl_dns_refresh_begin(&d, &config, "bad\nname", 11000));
    close(first);
    close(second);
}
int main(void) {
    struct timespec begin, end;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    invalid_replies();
    cname_and_timeout();
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = end.tv_sec - begin.tv_sec + (end.tv_nsec - begin.tv_nsec) / 1e9;
    assert(elapsed < 1); /* Simulated deadlines must not become blocking waits. */
    puts("Connected DNS validation, compression/CNAME, secondary fallback, bounded ticks and "
         "cleanup pass");
}
