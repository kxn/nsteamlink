#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
bool sl_system_init(void);
bool sl_system_running(void);
void sl_system_shutdown(void);
bool sl_system_random(void *data, size_t size);
const char *sl_system_data_dir(void);
/* Font memory remains valid until shutdown; desktop returns a filename. */
const void *sl_system_font(int index, size_t *size, const char **path);
uint64_t sl_system_now(void);

/* Bounded, best-effort diagnostic output; never called on the input path. */
void sl_system_log(const char *message);

/* Obtain on the resolving worker; cancellation may be requested by its owner. */
uint32_t sl_system_dns_begin(void);
void sl_system_dns_cancel(uint32_t handle);

const char *sl_system_locale(void);
