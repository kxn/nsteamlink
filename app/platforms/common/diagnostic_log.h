#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool sl_log_start(void);
void sl_log(const char *message);
void sl_log_finish(void);
bool sl_log_copy_tail(char *out, size_t capacity, bool previous);
unsigned sl_log_drop_count(void);
uint16_t sl_log_http_port(void);
