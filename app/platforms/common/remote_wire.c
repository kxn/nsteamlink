#include "remote_wire.h"
#include <mbedtls/base64.h>
#include <mbedtls/md.h>
#include <string.h>
#include <strings.h>

static bool read_varint(sl_proto_reader *r, uint64_t *out) {
    uint64_t value = 0;
    for (unsigned shift = 0; shift < 70; shift += 7) {
        if (r->offset == r->size)
            break;
        uint8_t byte = r->data[r->offset++];
        if (shift == 63 && byte > 1)
            break;
        value |= (uint64_t)(byte & 127) << shift;
        if (!(byte & 128)) {
            *out = value;
            return true;
        }
    }
    r->invalid = true;
    return false;
}
bool sl_proto_next(sl_proto_reader *r, sl_proto_field *f) {
    if (r->invalid || r->offset == r->size)
        return false;
    uint64_t tag;
    if (!read_varint(r, &tag) || (tag >> 3) == 0 || (tag >> 3) >= (1u << 29)) {
        r->invalid = true;
        return false;
    }
    *f = (sl_proto_field){.number = (uint32_t)(tag >> 3), .wire = tag & 7};
    if (!f->wire)
        return read_varint(r, &f->value);
    uint64_t length;
    if (f->wire == 2) {
        if (!read_varint(r, &length))
            return false;
    } else if (f->wire == 1 || f->wire == 5)
        length = f->wire == 1 ? 8 : 4;
    else {
        r->invalid = true;
        return false;
    }
    if (length > r->size - r->offset) {
        r->invalid = true;
        return false;
    }
    f->bytes = r->data + r->offset;
    f->size = (size_t)length;
    if (f->wire != 2)
        for (size_t i = 0; i < f->size; ++i)
            f->value |= (uint64_t)f->bytes[i] << (i * 8);
    r->offset += f->size;
    return true;
}
bool sl_proto_done(const sl_proto_reader *r) {
    return !r->invalid && r->offset == r->size;
}
static void append(sl_proto_writer *w, const void *p, size_t n) {
    if (w->invalid || n > w->capacity - w->size) {
        w->invalid = true;
        return;
    }
    if (n)
        memcpy(w->data + w->size, p, n);
    w->size += n;
}
static void varint(sl_proto_writer *w, uint64_t n) {
    do {
        uint8_t byte = (n & 127) | (n > 127 ? 128 : 0);
        append(w, &byte, 1);
        n >>= 7;
    } while (n && !w->invalid);
}
static void tag(sl_proto_writer *w, unsigned field, unsigned wire) {
    if (!field || field >= (1u << 29))
        w->invalid = true;
    varint(w, (uint64_t)field << 3 | wire);
}
void sl_proto_uint(sl_proto_writer *w, unsigned field, uint64_t n) {
    tag(w, field, 0);
    varint(w, n);
}
void sl_proto_fixed64(sl_proto_writer *w, unsigned field, uint64_t n) {
    tag(w, field, 1);
    uint8_t data[8];
    for (unsigned i = 0; i < 8; ++i)
        data[i] = (uint8_t)(n >> (8 * i));
    append(w, data, sizeof(data));
}
void sl_proto_bytes(sl_proto_writer *w, unsigned field, const void *data, size_t n) {
    tag(w, field, 2);
    varint(w, n);
    append(w, data, n);
}
int sl_ws_decode(const uint8_t *data, size_t n, sl_ws_frame *frame) {
    if (n < 2)
        return 0;
    unsigned op = data[0] & 15;
    bool final = (data[0] & 128) != 0;
    if ((data[0] & 112) || (data[1] & 128) ||
        (op != 0 && op != 2 && op != 8 && op != 9 && op != 10))
        return -1;
    size_t head = 2;
    uint64_t length = data[1] & 127;
    if (length >= 126) {
        unsigned extra = length == 126 ? 2 : 8;
        if (n < head + extra)
            return 0;
        length = 0;
        for (unsigned i = 0; i < extra; ++i)
            length = length << 8 | data[head++];
        if ((extra == 2 && length < 126) || (extra == 8 && length < 65536))
            return -1;
    }
    if (length > SL_REMOTE_FRAME_MAX || (op >= 8 && (!final || length > 125)) ||
        (op == 8 && length == 1))
        return -1;
    if (length > n - head)
        return 0;
    *frame = (sl_ws_frame){op, final, data + head, (size_t)length, head + (size_t)length};
    return 1;
}
size_t sl_ws_encode(uint8_t *out, size_t capacity, unsigned op, const void *payload, size_t n,
                    const uint8_t mask[4]) {
    if (n > SL_REMOTE_FRAME_MAX || (op != 2 && op != 8 && op != 9 && op != 10) ||
        (op >= 8 && n > 125))
        return 0;
    size_t head = n < 126 ? 2 : n < 65536 ? 4 : 10;
    if (capacity < head + 4 + n)
        return 0;
    out[0] = 128 | op;
    out[1] = 128 | (n < 126 ? (uint8_t)n : n < 65536 ? 126 : 127);
    if (head > 2)
        for (size_t i = 2; i < head; ++i)
            out[i] = (uint8_t)((uint64_t)n >> (8 * (head - i - 1)));
    memcpy(out + head, mask, 4);
    for (size_t i = 0; i < n; ++i)
        out[head + 4 + i] = ((const uint8_t *)payload)[i] ^ mask[i % 4];
    return head + 4 + n;
}
bool sl_ws_accept(const char *key, char out[29]) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    if (strlen(key) != 24)
        return false;
    char source[60];
    memcpy(source, key, 24);
    memcpy(source + 24, guid, 36);
    uint8_t digest[20];
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    size_t size;
    if (!info || mbedtls_md(info, (const uint8_t *)source, sizeof(source), digest) ||
        mbedtls_base64_encode((uint8_t *)out, 29, &size, digest, sizeof(digest)) || size != 28)
        return false;
    out[28] = 0;
    return true;
}
static bool equals(const uint8_t *p, size_t n, const char *text) {
    return n == strlen(text) && !strncasecmp((const char *)p, text, n);
}
static bool token(const uint8_t *p, size_t n, const char *wanted) {
    while (n) {
        while (n && (*p == ' ' || *p == '\t' || *p == ','))
            ++p, --n;
        size_t k = 0;
        while (k < n && p[k] != ',')
            ++k;
        size_t end = k;
        while (end && (p[end - 1] == ' ' || p[end - 1] == '\t'))
            --end;
        if (equals(p, end, wanted))
            return true;
        p += k;
        n -= k;
    }
    return false;
}
bool sl_ws_upgrade_valid(const uint8_t *p, size_t n, const char *expected) {
    if (n < 19 || memcmp(p, "HTTP/1.1 101", 12) || (p[12] != ' ' && p[12] != '\r'))
        return false;
    bool upgrade = false, connection = false;
    unsigned accept = 0;
    size_t offset = 0;
    while (offset + 1 < n) {
        size_t end = offset;
        while (end + 1 < n && (p[end] != '\r' || p[end + 1] != '\n'))
            ++end;
        if (end + 1 == n)
            return false;
        if (end == offset)
            return end + 2 == n && upgrade && connection && accept == 1;
        const uint8_t *colon = memchr(p + offset, ':', end - offset);
        if (colon) {
            const uint8_t *value = colon + 1;
            size_t length = p + end - value;
            while (length && (*value == ' ' || *value == '\t'))
                ++value, --length;
            while (length && (value[length - 1] == ' ' || value[length - 1] == '\t'))
                --length;
            size_t name = colon - (p + offset);
            if (equals(p + offset, name, "Upgrade"))
                upgrade = token(value, length, "websocket");
            else if (equals(p + offset, name, "Connection"))
                connection = token(value, length, "upgrade");
            else if (equals(p + offset, name, "Sec-WebSocket-Accept")) {
                if (length != strlen(expected) || memcmp(value, expected, length))
                    return false;
                ++accept;
            } else if (equals(p + offset, name, "Sec-WebSocket-Extensions") ||
                       equals(p + offset, name, "Sec-WebSocket-Protocol"))
                return false; /* No extension/subprotocol was requested. */
        }
        offset = end + 2;
    }
    return false;
}
