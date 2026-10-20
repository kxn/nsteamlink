#pragma once
#include "host_addresses.h"
#include "host_accounts.h"
#include <ihslib/client.h>
typedef struct sl_directory_host {
    struct sl_directory_host *next;
    uint64_t client_id;
    IHS_HostInfo info;
    sl_address_list addresses;
    sl_account_list accounts;
    bool accounts_loaded, accounts_absent, accounts_dirty;
    bool status_received, seeded, visible, cloud;
    int64_t last_status;
} sl_directory_host;
/* Caller owns serialization and publishes transitions in the same critical
 * section. Destruction requires all receive/connection producers joined. */
sl_directory_host *sl_directory_find(sl_directory_host *, uint64_t id);
sl_directory_host *sl_directory_ensure(sl_directory_host **, uint64_t id);
void sl_directory_destroy(sl_directory_host **);
bool sl_directory_seed(sl_directory_host **, uint64_t, const char *saved_ip);
bool sl_directory_status(sl_directory_host **, const IHS_HostInfo *,
    const IHS_DiscoveryAddressHints *, bool cloud, const IHS_SocketAddress *source, int64_t now);
bool sl_directory_offline(sl_directory_host *, uint64_t);
void sl_directory_disconnect(sl_directory_host *);
bool sl_directory_expired(const sl_directory_host *, int64_t now);
bool sl_directory_direct(const sl_directory_host *, IHS_HostInfo *);
