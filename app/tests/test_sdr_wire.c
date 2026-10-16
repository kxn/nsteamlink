#include "sdr_wire.h"
#include "sdr_config.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void wire(void) {
    uint8_t ping[1300];
    assert(sl_sdr_ping(ping, 1300, false, UINT64_C(0x1aabbccdd), 0x10203040,
        0x11223344, 0x01020304, 27015) == 1300);
    const uint8_t expected[] = {1, 2, 's','d','p','i','n','g',
        0xdd,0xcc,0xbb,0xaa, 0x40,0x30,0x20,0x10, 0,0,0,0,
        0x44,0x33,0x22,0x11, 0x44,0x33,0x22,0x11, 0xc7,0x59,13,0};
    assert(!memcmp(ping, expected, sizeof(expected)));
    for (size_t i = 32; i < sizeof(ping); ++i)
        assert(!ping[i]);
    assert(!sl_sdr_ping(ping, 99, true, 0, 1, 2, 3, 4));
    assert(sl_sdr_ping(ping, sizeof(ping), true, 0, 1, 2, 3, 4) == 100 && ping[1] == 0x82);
    uint8_t chunk[] = {0xde, 0xad}, stats[] = {8, 1}, packet[32];
    sl_sdr_data d = {.e2e_sequence = 0x1234, .relay_sequence = 0x5678,
        .connection_id = 0x12345678, .stats = stats, .stats_size = 2,
        .chunk = chunk, .chunk_size = 2, .sender_spacing_us = 250000};
    const uint8_t send_expected[] = {0xa3,0x34,0x12,0x78,0x56,0x78,0x56,0x34,0x12,
        2,8,1,0x09,0x3d,0xde,0xad};
    assert(sl_sdr_write_data(packet, sizeof(packet), &d) == sizeof(send_expected));
    assert(!memcmp(packet, send_expected, sizeof(send_expected)));
    sl_sdr_data received = {0};
    assert(!sl_sdr_parse_data(packet, sizeof(send_expected), &received)); /* Wrong direction. */
    const uint8_t incoming[] = {0x43,0x34,0x12,0x78,0x56,0x78,0x56,0x34,0x12,
        2,8,1,0x09,0x3d, 0x02,0x00,0xde,0xad};
    assert(sl_sdr_parse_data(incoming, sizeof(incoming), &received));
    assert(received.sender_spacing_us == 250000 && received.relay_spacing_us == 32);
    assert(received.e2e_sequence == 0x1234 && received.relay_sequence == 0x5678);
    assert(received.connection_id == 0x12345678 && received.stats_size == 2 &&
        received.chunk_size == 2 && !memcmp(received.chunk, chunk, 2));
    for (size_t n = 0; n < 16; ++n)
        assert(!sl_sdr_parse_data(incoming, n, &received));
    uint8_t invalid[] = {0x41,0,0,0,0,0,0,0,0, 0xff,0xff,0xff,0xff,0x1f};
    assert(!sl_sdr_parse_data(invalid, sizeof(invalid), &received));
    d.sender_spacing_us = 250001;
    assert(sl_sdr_write_data(packet, sizeof(packet), &d) == 14 && packet[0] == 0xa1);
    assert(!sl_sdr_write_data(packet, 13, &d));
}
static void acknowledgments(void) {
    sl_sdr_acks q = {0};
    assert(sl_sdr_ack_deadline(&q) == UINT64_MAX);
    sl_sdr_ack_queue(&q, 10, 1000000, false);
    sl_sdr_ack_queue(&q, 10, 1000001, false);
    assert(q.count == 1 && q.entries[0].received_us == 1000000);
    sl_sdr_ack_queue(&q, 11, 1000002, false);
    sl_sdr_ack_queue(&q, 10, 1000003, false); /* Deduplicate only the tail. */
    assert(q.count == 3 && sl_sdr_ack_deadline(&q) == 1250000);
    sl_sdr_ack_queue(&q, 12, 1000004, false);
    sl_sdr_ack_queue(&q, 13, 1000005, false);
    sl_sdr_ack_queue(&q, 14, 1000006, false);
    assert(q.count == 5 && q.entries[4].sequence == 13 && !q.force);
    assert(sl_sdr_ack_deadline(&q) == 0);
    sl_sdr_ack_queue(&q, 14, 1000007, true);
    assert(q.count == 5 && q.entries[0].sequence == 10 && q.entries[4].sequence == 14 && q.force);
    uint32_t packed[5];
    assert(sl_sdr_ack_pack(&q, 1000064, packed) == 5);
    assert(packed[0] == 0x000a0001 && packed[4] == 0x000e0000);
    assert(q.count == 5); /* Populate does not consume pending ACK. */
    sl_sdr_ack_pack(&q, 999999, packed);
    assert(packed[0] == 0x000affff); /* Negative delay saturates. */
    sl_sdr_ack_pack(&q, 1000000 + UINT64_C(65536) * 64, packed);
    assert(packed[0] == 0x000affff);
    sl_sdr_ack_commit(&q);
    assert(!q.count && !q.force);
}
static void routing(void) {
    sl_sdr_target target = {.revision = UINT32_MAX, .acknowledged = true};
    assert(sl_sdr_target_desire(&target, (const uint8_t *)"a", 1, 1));
    assert(sl_sdr_target_populate(&target));
    assert(target.revision == 0 && !target.acknowledged && target.sent_pop == 1);
    sl_sdr_target_ack(&target, 0);
    assert(target.acknowledged);
    assert(sl_sdr_target_desire(&target, (const uint8_t *)"a", 1, 2));
    assert(sl_sdr_target_populate(&target));
    assert(target.sent_pop == 1 && target.revision == 0 && target.acknowledged);
    assert(sl_sdr_target_desire(&target, NULL, 0, 0));
    assert(!sl_sdr_target_populate(&target));
    assert(target.sent_pop == 1 && target.sent_size == 1 && target.acknowledged);
    sl_sdr_target_ack(&target, 1);
    assert(!target.acknowledged); /* Mismatched ACK retracts confirmation. */
    sl_sdr_revisions r = {.local = 10, .local_acked = 9, .peer = 7, .retry_us = 1000};
    assert(!sl_sdr_routes_received(&r, false, 9) && r.ack_pending);
    assert(!sl_sdr_routes_received(&r, true, 7));
    assert(sl_sdr_routes_received(&r, true, UINT32_MAX));
    assert(!sl_sdr_routes_received(&r, true, 0)); /* No uint32 wrap comparison. */
    sl_sdr_routes_ack(&r, 11);
    assert(r.local_acked == 9);
    sl_sdr_routes_ack(&r, 10);
    assert(r.local_acked == 10 && r.retry_us == 0);
    sl_sdr_routes_ack(&r, 8);
    assert(r.local_acked == 8 && r.retry_us == 0); /* ACK is allowed to regress. */
    r.retry_us = 1000;
    assert(sl_sdr_routes_due(&r, 1000));
    sl_sdr_routing_fields f = sl_sdr_routes_populate_stats(&r, true, false,
        true, true, false, false, 1000);
    assert(f.forward && f.peer_ack && !f.routes && f.e2e_mode == 2);
    assert(r.ack_pending && r.retry_us == 1000);
    f = sl_sdr_routes_populate_stats(&r, true, false, false, false, false, true, 1001);
    assert(f.forward && !f.peer_ack && !f.routes && f.e2e_mode == 0 && f.flags == 24);
    f = sl_sdr_routes_populate_stats(&r, true, false, false, false, true, true, 1000);
    assert(f.peer_ack && f.routes && f.e2e_mode == 2);
    /* A failed control send never invokes Track; inline tracking occurs before
     * the socket call. The caller keeps these commit sites distinct. */
    assert(r.retry_us == 1000);
    sl_sdr_routes_track_stats(&r, f, 1000);
    assert(r.retry_us == 501000 && !r.ack_pending);
    f = sl_sdr_routes_rendezvous(&r, false, 501000);
    assert(f.peer_ack && f.routes && r.retry_us == 1501000);
    f = sl_sdr_routes_rendezvous(&r, true, 1501000);
    assert(f.peer_ack && !f.routes && r.retry_us == 1501000);
}
static void config(void) {
    const char sample[] = "{\"success\":true,\"revision\":1792003701,"
        "\"relay_public_key\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\","
        "\"pops\":{\"sin\":{\"geo\":[1.3,103.8],\"tier\":0,\"relays\":["
        "{\"ipv4\":\"192.0.2.1\",\"port_range\":[27015,27050]}]},"
        "\"abcd\":{\"relays\":[{\"ipv4\":\"198.51.100.2\",\"port_range\":[443,443]}]}}}";
    sl_sdr_config *c = malloc(sizeof(*c));
    assert(c && sl_sdr_config_parse(sample, sizeof(sample) - 1, c));
    assert(c->revision == 1792003701 && c->pop_count == 2 && c->endpoint_count == 2);
    assert(c->have_relay_key && c->relay_public_key[0] == 0 && c->relay_public_key[31] == 31);
    assert(c->pops[0].id == 0x0073696e && c->pops[1].id == 0x64616263);
    assert(c->pops[0].tier == 0 && c->pops[1].tier == 1);
    assert(c->pops[0].first_endpoint == 0 && c->pops[1].first_endpoint == 1);
    assert(c->endpoints[0].ipv4 == 0xc0000201 && c->endpoints[0].port_min == 27015 &&
        c->endpoints[0].port_max == 27050 && c->endpoints[1].ipv4 == 0xc6336402);
    const char invalid[] = "{\"success\":true,\"revision\":1,\"pops\":{\"sin\":{\"relays\":["
        "{\"ipv4\":\"192.0.2.1\",\"port_range\":[65536,65537]}]}}}";
    assert(!sl_sdr_config_parse(invalid, sizeof(invalid) - 1, c));
    assert(c->revision == 1792003701); /* Failed updates leave last config intact. */
    for (size_t i = 0; i < sizeof(sample) - 1; ++i)
        assert(!sl_sdr_config_parse(sample, i, c));
    free(c);
}
int main(int argc, char **argv) {
    wire();
    acknowledgments();
    routing();
    config();
    if (argc == 2) {
        FILE *f = fopen(argv[1], "rb");
        assert(f);
        char *text = malloc(1024 * 1024);
        assert(text);
        size_t n = fread(text, 1, 1024 * 1024, f);
        assert(!ferror(f) && feof(f));
        sl_sdr_config *c = malloc(sizeof(*c));
        assert(c && sl_sdr_config_parse(text, n, c));
        printf("NETWORK_CONFIG_VALID=1 POPS=%zu ENDPOINT_RANGES=%zu\n", c->pop_count, c->endpoint_count);
        free(c);
        free(text);
        fclose(f);
    }
    puts("SDR directional wire, ACK and routing revision evidence fixtures passed");
}
