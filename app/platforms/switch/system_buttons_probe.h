#pragma once
#include <stdbool.h>
#include <stdint.h>
/* Diagnostic-only, main-owner API. The caller pumps the ordinary applet loop
 * between ticks and forces the application offline before the first tick. */
bool sl_system_buttons_probe_tick(uint64_t now_ms);
void sl_system_buttons_probe_cleanup(void);
