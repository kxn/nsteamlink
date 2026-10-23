#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <ihslib/net.h>
/* Caller serializes access. Flags are session facts, not persisted reachability. */
typedef struct sl_address_record {
    bool verified, remote;
    int64_t timestamp;
    IHS_SocketAddress address;
} sl_address_record;
typedef struct sl_address_list {
    sl_address_record *entries;
    size_t count, capacity;
} sl_address_list;
void sl_addresses_destroy(sl_address_list *);
bool sl_addresses_reserve(sl_address_list *, size_t count);
/* Success/failure is separate from the original BAddNetworkAddress "new entry"
 * result. Updating an existing entry can succeed with *added=false. */
bool sl_addresses_add(sl_address_list *, const IHS_SocketAddress *, bool verified,
                      bool remote, int64_t now, bool *added);
void sl_addresses_clear_inactive(sl_address_list *);
bool sl_addresses_get(const sl_address_list *, IHS_SocketAddress *);
/* depth<0 chooses the original 2*floor(log2(count)); explicit depth is for the
 * shared production/original oracle, including the heap fallback. */
void sl_addresses_sort(sl_address_list *, int depth);
bool sl_address_parse(IHS_SocketAddress *, const char *text);
bool sl_address_has_ip(const IHS_IPAddress *);
/* Original IPv6 text, including hex IPv4-mapped suffix; no address port. */
void sl_address_text(const IHS_IPAddress *, char out[64]);
#ifdef __cplusplus
}
#endif
