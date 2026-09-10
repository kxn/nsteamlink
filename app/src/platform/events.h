#pragma once
#include <stdbool.h>
/* Application lifecycle facts; input payload adaptation stays platform-private. */
void sl_events_init(void);
bool sl_events_foreground(void);
bool sl_events_exit_requested(void);
