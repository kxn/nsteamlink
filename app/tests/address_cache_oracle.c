/* No independent policy model: invokes the production address list/sort. */
#include "host_addresses.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
static sl_address_record row(void) {
    char ip[64];
    unsigned port, verified, remote;
    sl_address_record value = {0};
    assert(scanf("%63s %u %u %u %" SCNd64, ip, &port, &verified, &remote,
                  &value.timestamp) == 5);
    assert(port <= 65535 && IHS_IPAddressFromString(&value.address.ip, ip));
    value.address.port = (uint16_t)port;
    value.verified = verified != 0;
    value.remote = remote != 0;
    return value;
}
static void address(const IHS_SocketAddress *a) {
    char ip[64];
    sl_address_text(&a->ip, ip);
    printf("{\"ip\":\"%s\",\"port\":%u}", ip, a->port);
}
int main(int argc, char **argv) {
    if (argc > 1) {
        assert(!strcmp(argv[1], "has-ip"));
        char text[64];
        while (scanf("%63s", text) == 1) {
            IHS_IPAddress ip;
            assert(IHS_IPAddressFromString(&ip, text));
            printf("%d\n", sl_address_has_ip(&ip));
        }
        return 0;
    }
    unsigned programs;
    assert(scanf("%u", &programs) == 1);
    while (programs--) {
        size_t count;
        unsigned actions;
        assert(scanf("%zu %u", &count, &actions) == 2);
        sl_address_list list = {0};
        assert(sl_addresses_reserve(&list, count));
        list.count = count;
        for (size_t i = 0; i < count; ++i) list.entries[i] = row();
        while (actions--) {
            unsigned kind;
            assert(scanf("%u", &kind) == 1);
            bool added = false;
            if (kind == 0) {
                sl_address_record value = row();
                assert(sl_addresses_add(&list, &value.address, value.verified,
                                        value.remote, value.timestamp, &added));
            } else if (kind == 1) sl_addresses_clear_inactive(&list);
            else {
                int depth;
                assert(kind == 2 && scanf("%d", &depth) == 1);
                sl_addresses_sort(&list, depth);
            }
            IHS_SocketAddress selected;
            sl_addresses_get(&list, &selected);
            printf("{\"added\":%s,\"rows\":[", kind ? "null" : added ? "true" : "false");
            for (size_t i = 0; i < list.count; ++i) {
                const sl_address_record *e = &list.entries[i];
                char ip[64];
                sl_address_text(&e->address.ip, ip);
                printf("%s{\"ip\":\"%s\",\"port\":%u,\"verified\":%s,\"remote\":%s,\"time\":%" PRId64 "}",
                       i ? "," : "", ip, e->address.port, e->verified ? "true" : "false",
                       e->remote ? "true" : "false", e->timestamp);
            }
            printf("],\"route\":"); address(&selected); puts("}");
        }
        sl_addresses_destroy(&list);
    }
    return 0;
}
