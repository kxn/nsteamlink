#pragma once
#include <stddef.h>
typedef struct sl_sns_config_cache sl_sns_config_cache;
/* Startup prefetch, raw public JSON only. All methods run on the application
 * worker; no SDK, rendering calls or additional threads. One refresh per owner.
 * Snapshot storage belongs to this owner and changes only during update. */
sl_sns_config_cache *sl_sns_config_cache_create(const char *directory);
void sl_sns_config_cache_update(sl_sns_config_cache *);
const char *sl_sns_config_cache_data(const sl_sns_config_cache *, size_t *size);
void sl_sns_config_cache_destroy(sl_sns_config_cache *);
