#include "stream_bridge.h"
#include "remote_wire.h"
#include "endianness.h"
#include "protobuf/discovery.pb-c.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct fixture {
    sl_remote *remote;
    sl_signal_channel *channel;
    uint8_t envelope[65536], received[65536];
    size_t size, received_size;
    unsigned sends, receives, failures, updates;
    bool reject_send, reject_signal;
} fixture;
static bool send_frame(const uint8_t *p, size_t n, void *ctx) {
    fixture *f = ctx;
    if (f->reject_send)
        return false;
    assert(n <= sizeof(f->envelope));
    memcpy(f->envelope, p, n);
    f->size = n;
    ++f->sends;
    return true;
}
static bool receive(const uint8_t *p, size_t n, void *ctx) {
    fixture *f = ctx;
    assert(n <= sizeof(f->received));
    memcpy(f->received, p, n);
    f->received_size = n;
    ++f->receives;
    return !f->reject_signal;
}
static void failed(void *ctx) { ++((fixture *)ctx)->failures; }
static void updated(void *ctx) { ++((fixture *)ctx)->updates; }
static void receive_body(uint64_t id, const uint8_t *p, size_t n, void *ctx) {
    fixture *f = ctx;
    sl_signal_channel_receive(f->channel, id, p, n);
}
static sl_proto_field field(const void *p, size_t n, unsigned number) {
    sl_proto_reader r = {p, n, 0, false};
    sl_proto_field f, found = {0};
    while (sl_proto_next(&r, &f))
        if (f.number == number)
            found = f;
    assert(sl_proto_done(&r));
    return found;
}
static void open_session(fixture *f, uint64_t id) {
    assert(sl_remote_open(f->remote));
    uint8_t session[32], response[48];
    sl_proto_writer w = {session, 0, sizeof(session), false};
    sl_proto_fixed64(&w, 1, id);
    sl_proto_uint(&w, 2, 1);
    sl_proto_writer a = {response, 0, sizeof(response), false};
    sl_proto_uint(&a, 1, 1);
    sl_proto_bytes(&a, 2, session, w.size);
    assert(sl_remote_receive(f->remote, response, a.size));
    assert(sl_remote_ready(f->remote));
}
static sl_proto_field outgoing(fixture *f, uint64_t session) {
    sl_proto_field remote = field(f->envelope, f->size, 7);
    assert(remote.wire == 2);
    assert(field(remote.bytes, remote.size, 1).value == session);
    assert(field(remote.bytes, remote.size, 2).value == 88);
    sl_proto_field packet = field(remote.bytes, remote.size, 4);
    uint32_t hs, ms;
    assert(packet.size >= 16);
    IHS_ReadUInt32LE(packet.bytes + 8, &hs);
    assert(hs <= packet.size - 16);
    IHS_ReadUInt32LE(packet.bytes + 12 + hs, &ms);
    assert(ms == packet.size - hs - 16);
    assert(!field(packet.bytes + 12, hs, 1).number);
    assert(!field(packet.bytes + 12, hs, 5).number);
    assert(field(packet.bytes + 12, hs, 2).value == 12);
    return (sl_proto_field){.bytes = packet.bytes + 16 + hs, .size = ms};
}
static void relay_back(fixture *f) {
    sl_proto_field remote = field(f->envelope, f->size, 7);
    sl_proto_field packet = field(remote.bytes, remote.size, 4);
    uint8_t body[65536], envelope[65536];
    sl_proto_writer b = {body, 0, sizeof(body), false};
    /* Steam host replies have a nonzero client ID; original client bridge
     * sends have only msg_type. Do not model both directions as identical. */
    uint32_t hs;
    IHS_ReadUInt32LE(packet.bytes + 8, &hs);
    uint8_t incoming[65536];
    memcpy(incoming, packet.bytes, 8);
    IHS_WriteUInt32LE(incoming+8, 4);
    memcpy(incoming+12, "\x08\x4d\x10\x0c", 4);
    memcpy(incoming+16, packet.bytes+12+hs, packet.size-12-hs);
    sl_proto_bytes(&b, 1, incoming, packet.size+4-hs);
    sl_proto_writer w = {envelope, 0, sizeof(envelope), false};
    sl_proto_uint(&w, 1, 1);
    sl_proto_bytes(&w, 6, body, b.size);
    assert(!b.invalid && !w.invalid);
    assert(sl_remote_receive(f->remote, envelope, w.size));
}
int main(void) {
    fixture *f = calloc(1, sizeof(*f));
    assert(f);
    uint8_t key[16];
    for (unsigned i = 0; i < sizeof(key); ++i)
        key[i] = (uint8_t)i;
    sl_signal_callbacks cb = {.receive = receive, .failed = failed, .updated = updated};
    f->channel = sl_signal_channel_create(77, 88, key, sizeof(key), &cb, f);
    uint8_t secret[32] = {1};
    IHS_ClientConfig config = {.deviceId = 77, .secretKey = secret, .deviceName = "Bridge test"};
    sl_remote_callbacks remote_cb = {.send = send_frame, .transport_signal = receive_body};
    f->remote = sl_remote_create(&config, &remote_cb, f);
    assert(f->remote && f->channel);
    assert(sl_signal_channel_queue(f->channel, (const uint8_t *)"abc", 3));
    sl_signal_channel_flush(f->channel, f->remote);
    assert(f->sends == 0 && sl_signal_channel_pending(f->channel));
    open_session(f, 11);
    f->reject_send = true;
    sl_signal_channel_flush(f->channel, f->remote);
    assert(sl_signal_channel_pending(f->channel));
    sl_remote_close(f->remote);
    f->reject_send = false;
    open_session(f, 22);
    sl_signal_channel_flush(f->channel, f->remote);
    assert(!sl_signal_channel_pending(f->channel));
    sl_proto_field body = outgoing(f, 22);
    sl_proto_field token = field(body.bytes, body.size, 1);
    /* Independent Python hmac/sha256 fixture for key bytes 00..0f and
     * inner protobuf 12 03 61 62 63. Tests actual key length, not a 32-byte pad. */
    const uint8_t expected[32] = {
        0x00,0x03,0xfc,0x2c,0x06,0xc6,0x30,0xd8,0xcf,0x57,0x6e,0x68,0x93,0xb6,0xc0,0x4a,
        0x81,0xe9,0xe1,0xf7,0xed,0x2a,0xde,0xe7,0x64,0x1e,0xec,0x9b,0xf1,0xdf,0xc4,0x67};
    assert(token.size == 32 && !memcmp(token.bytes, expected, 32));
    assert(sl_signal_channel_receive(f->channel, 0, body.bytes, body.size) == 0);
    assert(f->updates == 0);
    relay_back(f);
    assert(f->receives == 1 && f->received_size == 3 && !memcmp(f->received, "abc", 3));
    /* Identical authenticated signals must still reach the inner reliable
     * rendezvous protocol. No outer payload-hash deduplication. */
    relay_back(f);
    assert(f->receives == 2);
    assert(f->updates == 2);
    uint8_t bad[128];
    assert(body.size <= sizeof(bad));
    memcpy(bad, body.bytes, body.size);
    bad[2] ^= 1;
    assert(sl_signal_channel_receive(f->channel, 77, bad, body.size) == 0);
    assert(!sl_signal_channel_failed(f->channel) && f->receives == 2);
    assert(sl_signal_channel_receive(f->channel, 77, (const uint8_t *)"\x12\xff", 2) == 0);
    assert(f->updates == 2); /* Invalid framing/HMAC never updates the backend. */
    /* Reconnect retains FIFO order, including duplicates, but reframes with
     * the new session. A batch is decoded completely before SDK delivery. */
    sl_remote_close(f->remote);
    for (unsigned i = 0; i < 64; ++i) {
        uint8_t value = (uint8_t)(i / 2);
        assert(sl_signal_channel_queue(f->channel, &value, 1));
    }
    assert(!sl_signal_channel_queue(f->channel, (const uint8_t *)"overflow", 8));
    open_session(f, 33);
    sl_signal_channel_flush(f->channel, f->remote);
    body = outgoing(f, 33);
    unsigned before = f->receives;
    relay_back(f);
    assert(f->receives == before + 64 && f->received_size == 1 && f->received[0] == 31);
    assert(f->updates == 3); /* Once for the whole list, not once per element. */
    f->reject_signal = true;
    assert(sl_signal_channel_receive(f->channel, 77, body.bytes, body.size) == -1);
    assert(f->failures == 1 && sl_signal_channel_failed(f->channel));
    assert(f->updates == 4); /* The SDK rejection path still updates once. */
    assert(!sl_signal_channel_queue(f->channel, (const uint8_t *)"late", 4));
    assert(sl_signal_channel_receive(f->channel, 77, body.bytes, body.size) == -1);
    assert(f->failures == 1);
    assert(f->updates == 4);
    sl_remote_destroy(f->remote);
    sl_signal_channel_destroy(f->channel);
    free(f);
    puts("authenticated stream bridge reconnect and FIFO tests passed");
}
