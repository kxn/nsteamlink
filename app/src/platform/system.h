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
