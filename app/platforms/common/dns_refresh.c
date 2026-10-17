#include "dns_refresh.h"
#include "crypto.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static uint16_t read16(const uint8_t *p) {
    return (uint16_t)((unsigned)p[0] << 8 | p[1]);
}
static void write16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}
/* DNS names may use compression, including in CNAME RDATA. Every offset and
 * jump is bounded; loops, reserved label types and oversized names fail shut. */
static bool name_read(const uint8_t *packet, size_t size, size_t *position, char out[254]) {
    size_t p = *position, used = 0;
    bool jumped = false;
    for (unsigned steps = 0; steps < 128; ++steps) {
        if (p >= size)
            return false;
        unsigned length = packet[p++];
        if ((length & 0xc0) == 0xc0) {
            if (p >= size)
                return false;
            size_t next = ((length & 0x3f) << 8) | packet[p++];
            if (!jumped)
                *position = p;
            jumped = true;
            p = next;
            continue;
        }
        if (length & 0xc0 || length > size - p)
            return false;
        if (!length) {
            if (!jumped)
                *position = p;
            out[used] = 0;
            return true;
        }
        if (used && used < 253)
            out[used++] = '.';
        if (used + length > 253)
            return false;
        for (unsigned i = 0; i < length; ++i) {
            unsigned c = packet[p++];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '-'))
                return false;
            out[used++] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
        }
    }
    return false;
}
static bool answer(sl_dns_refresh *d, const uint8_t *packet, size_t size) {
    if (size < 12 || size > 512 || read16(packet) != d->id ||
        (read16(packet + 2) & 0xfa0f) != 0x8000 || read16(packet + 4) != 1)
        return false; /* QR, opcode, TC and RCODE. */
    char question[254];
    size_t p = 12;
    if (!name_read(packet, size, &p, question) || strcmp(question, d->host) || size - p < 4 ||
        read16(packet + p) != 1 || read16(packet + p + 2) != 1)
        return false;
    p += 4;
    unsigned count = read16(packet + 6);
    if (!count || count > 32)
        return false;
    struct record {
        size_t name, data, end;
        uint16_t type, cls;
    } records[32];
    for (unsigned i = 0; i < count; ++i) {
        struct record *r = &records[i];
        r->name = p;
        if (!name_read(packet, size, &p, question) || size - p < 10)
            return false;
        r->type = read16(packet + p);
        r->cls = read16(packet + p + 2);
        size_t length = read16(packet + p + 8);
        p += 10;
        if (length > size - p)
            return false;
        r->data = p;
        r->end = p + length;
        p += length;
    }
    char current[254];
    strcpy(current, d->host);
    d->addresses[0] = 0;
    /* Re-scan to handle records arriving before their CNAME. Only accept A
     * records owned by the query name or its verified alias chain. */
    for (unsigned depth = 0; depth < 8; ++depth) {
        char alias[254] = {0};
        unsigned found = 0;
        for (unsigned i = 0; i < count; ++i) {
            struct record *r = &records[i];
            p = r->name;
            if (!name_read(packet, size, &p, question) || strcmp(question, current) || r->cls != 1)
                continue;
            if (r->type == 5) {
                p = r->data;
                if (!name_read(packet, size, &p, alias) || p != r->end || !alias[0])
                    return false;
            } else if (r->type == 1 && r->end - r->data == 4 && found < 4) {
                char address[INET_ADDRSTRLEN];
                if (!inet_ntop(AF_INET, packet + r->data, address, sizeof(address)))
                    return false;
                size_t n = strlen(d->addresses);
                snprintf(d->addresses + n, sizeof(d->addresses) - n, "%s%s", found ? "," : "",
                         address);
                ++found;
            }
        }
        if (found)
            return true;
        if (!alias[0])
            return false;
        strcpy(current, alias);
    }
    return false;
}
void sl_dns_refresh_cancel(sl_dns_refresh *d) {
    if (d->fd >= 0)
        close(d->fd);
    d->fd = -1;
}
static bool send_query(sl_dns_refresh *d, uint64_t now) {
    sl_dns_refresh_cancel(d);
    while (d->attempt < d->config.count * 2) {
        const struct sockaddr_in *server = &d->config.servers[d->attempt++ % d->config.count];
        d->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (d->fd < 0)
            return false;
        int flags = fcntl(d->fd, F_GETFL, 0);
        if (flags >= 0 && fcntl(d->fd, F_SETFL, flags | O_NONBLOCK) == 0 &&
            connect(d->fd, (const struct sockaddr *)server, sizeof(*server)) == 0 &&
            send(d->fd, d->query, d->query_size, 0) == (ssize_t)d->query_size) {
            d->deadline = now + 1500;
            return true;
        }
        sl_dns_refresh_cancel(d);
    }
    return false;
}
bool sl_dns_refresh_begin(sl_dns_refresh *d, const sl_dns_config *config, const char *host,
                          uint64_t now) {
    sl_dns_refresh_cancel(d);
    memset(d, 0, sizeof(*d));
    d->fd = -1;
    if (!config || !config->count || config->count > 2 || !host || !host[0] || strlen(host) > 253 ||
        host[strlen(host) - 1] == '.')
        return false;
    d->config = *config;
    d->expires_at = now + config->count * 3000;
    d->id = (uint16_t)IHS_CryptoRandomUInt32();
    write16(d->query, d->id);
    write16(d->query + 2, 0x0100); /* Recursion desired. */
    write16(d->query + 4, 1);
    size_t p = 12, offset = 0;
    while (host[offset]) {
        size_t length = strcspn(host + offset, ".");
        if (!length || length > 63 || p + length + 1 > sizeof(d->query) - 5)
            return false;
        d->query[p++] = (uint8_t)length;
        for (size_t i = 0; i < length; ++i) {
            unsigned c = (unsigned char)host[offset + i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '-'))
                return false;
            char lower = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
            d->query[p++] = (uint8_t)lower;
            d->host[offset + i] = lower;
        }
        offset += length;
        if (host[offset])
            d->host[offset++] = '.';
    }
    d->query[p++] = 0;
    write16(d->query + p, 1);
    write16(d->query + p + 2, 1);
    d->query_size = p + 4;
    return send_query(d, now);
}
int sl_dns_refresh_poll(sl_dns_refresh *d, uint64_t now) {
    if (d->fd < 0)
        return -1;
    if (now >= d->expires_at) {
        sl_dns_refresh_cancel(d);
        return -1;
    }
    uint8_t packet[513];
    /* Drain a fixed maximum per tick, so even hostile traffic cannot monopolize
     * the runtime owner. Connected UDP restricts replies to the chosen DNS. */
    for (unsigned i = 0; i < 4; ++i) {
        ssize_t n = recv(d->fd, packet, sizeof(packet), 0);
        if (n > 0 && answer(d, packet, (size_t)n)) {
            sl_dns_refresh_cancel(d);
            return 1;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                break;
            return send_query(d, now) ? 0 : -1;
        }
    }
    if (now >= d->deadline)
        return send_query(d, now) ? 0 : -1;
    return 0;
}
