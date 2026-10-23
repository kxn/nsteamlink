#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Manager protocol metadata, independent of the UI's selected-account mirror.
 * Caller serializes access. Order is observable by subsequent cloud sends. */
typedef struct sl_account_list {
    uint64_t *ids;
    size_t count, capacity;
} sl_account_list;
void sl_accounts_destroy(sl_account_list *);
bool sl_accounts_reserve(sl_account_list *, size_t);
/* Status BAddSteamID: zero is ignored; existing entries swap with the front.
 * added is the original return value, not an indication of every mutation. */
bool sl_accounts_status(sl_account_list *, uint64_t, bool *added);
/* Success/steamid-present: fast-remove an existing entry, then insert at front.
 * Includes zero, and happens before key validation. */
bool sl_accounts_authorize(sl_account_list *, uint64_t, bool *changed);
/* Global paired accounts append once, independently of per-client ordering. */
bool sl_accounts_pair(sl_account_list *, uint64_t, bool *added);
/* Local durable publication uses tmp/bak recovery. Valid files use the original
 * little-endian uint64 hex, one ID per line. Invalid files are rejected whole;
 * this parser does not claim original malformed-text permissiveness. */
int sl_accounts_load(sl_account_list *, const char *path); /* 0 loaded, 1 absent, -1 invalid/I/O */
bool sl_accounts_save(const sl_account_list *, const char *path);
void sl_account_hex(uint64_t, char out[17]);
