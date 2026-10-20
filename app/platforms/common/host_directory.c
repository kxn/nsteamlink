#include "host_directory.h"
#include <stdlib.h>
#include <string.h>

sl_directory_host *sl_directory_find(sl_directory_host *host, uint64_t id) {
    for (; host; host = host->next)
        if (host->client_id == id) return host;
    return NULL;
}
sl_directory_host *sl_directory_ensure(sl_directory_host **list, uint64_t id) {
    sl_directory_host *host = sl_directory_find(*list, id);
    if (host) return host;
    host = calloc(1, sizeof(*host));
    if (!host) return NULL;
    host->client_id = host->info.clientId = id;
    /* Stable record iteration; sends follow the separately watched-ID list. */
    while (*list) list = &(*list)->next;
    *list = host;
    return host;
}
void sl_directory_destroy(sl_directory_host **list) {
    while (*list) {
        sl_directory_host *host = *list;
        *list = host->next;
        sl_addresses_destroy(&host->addresses);
        sl_accounts_destroy(&host->accounts);
        free(host);
    }
}
bool sl_directory_seed(sl_directory_host **list, uint64_t id, const char *saved_ip) {
    IHS_SocketAddress ip;
    if (!saved_ip || !*saved_ip || !sl_address_parse(&ip, saved_ip) || !sl_address_has_ip(&ip.ip)) return true;
    sl_directory_host *host = sl_directory_ensure(list, id);
    if (!host) return false;
    if (host->seeded || host->status_received) return true;
    bool added;
    if (!sl_addresses_add(&host->addresses, &ip, false, false, 0, &added)) return false;
    host->info.address = ip;
    host->seeded = true;
    return true;
}
bool sl_directory_status(sl_directory_host **list, const IHS_HostInfo *info,
    const IHS_DiscoveryAddressHints *hints, bool cloud,
    const IHS_SocketAddress *source, int64_t now) {
    if (!info->clientId) return false;
    sl_directory_host *host = sl_directory_ensure(list, info->clientId);
    if (!host) return false;
    /* Reserve before mutation so allocation failure does not erase the old
     * complete directory/status. Invalid/duplicate announcements need less. */
    size_t extra = (hints ? hints->addressCount : 0);
    if (extra > SIZE_MAX-2 || host->addresses.count > SIZE_MAX-extra-2 ||
        !sl_addresses_reserve(&host->addresses, host->addresses.count+extra+2)) return false;
    size_t users = hints ? hints->steamIdCount : 0;
    if (users > SIZE_MAX - host->accounts.count ||
        !sl_accounts_reserve(&host->accounts, host->accounts.count + users)) return false;
    bool first_status = !host->status_received;
    if (!host->status_received) {
        sl_addresses_clear_inactive(&host->addresses);
        host->status_received = true;
    }
    /* Original status traverses users from the back, preserving first priority
     * from the wire. An existing-account reorder alone does not trigger save. */
    bool accounts_added = false;
    for (size_t i = users; i; --i) {
        bool added;
        sl_accounts_status(&host->accounts, hints->steamIds[i-1], &added);
        accounts_added |= added;
    }
    bool metadata_added = accounts_added;
    bool added;
    IHS_SocketAddress ip;
    if (hints && hints->publicAddress && sl_address_parse(&ip, hints->publicAddress) && sl_address_has_ip(&ip.ip)) {
        sl_addresses_add(&host->addresses, &ip, false, true, now, &added);
        metadata_added |= added;
    }
    if (hints)
        for (size_t i = 0; i < hints->addressCount; ++i)
            if (sl_address_parse(&ip, hints->addresses[i]) && sl_address_has_ip(&ip.ip)) {
                sl_addresses_add(&host->addresses, &ip, false, false, now, &added);
                metadata_added |= added;
            }
    if (source && sl_address_has_ip(&source->ip)) {
        sl_addresses_add(&host->addresses, source, true, false, now, &added);
        metadata_added |= added;
    }
    if (first_status || metadata_added) host->accounts_dirty = true;
    IHS_SocketAddress display = host->info.address;
    host->info = *info;
    if (sl_addresses_get(&host->addresses, &ip)) host->info.address = ip;
    else if (host->addresses.count) host->info.address = host->addresses.entries[0].address;
    else host->info.address = display;
    host->last_status = now;
    host->visible = true;
    if (cloud) host->cloud = true;
    return true;
}
bool sl_directory_offline(sl_directory_host *list, uint64_t id) {
    sl_directory_host *host = sl_directory_find(list, id);
    if (!host) return false;
    bool removed = host->visible;
    host->visible = host->cloud = false;
    return removed;
}
void sl_directory_disconnect(sl_directory_host *list) {
    for (; list; list = list->next) list->cloud = false;
}
bool sl_directory_expired(const sl_directory_host *host, int64_t now) {
    uint64_t bits = (uint64_t)now - (uint64_t)host->last_status;
    int64_t elapsed;
    memcpy(&elapsed, &bits, sizeof(elapsed));
    return host->visible && !host->cloud && elapsed >= 30;
}
bool sl_directory_direct(const sl_directory_host *host, IHS_HostInfo *out) {
    IHS_SocketAddress address;
    if (!host || !sl_addresses_get(&host->addresses, &address)) return false;
    *out = host->info;
    out->address = address;
    return true;
}
