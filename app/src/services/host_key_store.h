#pragma once
#include <stdbool.h>
#include <stdint.h>
/* Long-term key namespace is (remote client ID, selected Steam ID). Steam ID
 * zero is a valid selected input. Profile v5 keeps the selected-host mirror. */
bool sl_host_key_save(const char *directory, uint64_t client, uint64_t steam,
                      const uint8_t key[32]);
/* 0 loaded, 1 missing, -1 invalid/unreadable. Output unchanged on failure. */
int sl_host_key_load(const char *directory, uint64_t client, uint64_t steam, uint8_t key[32]);
