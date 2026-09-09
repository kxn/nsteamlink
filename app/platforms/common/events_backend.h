#pragma once
#include "platform/events.h"
#include <SDL.h>
/* One main-thread pump, capped per iteration to keep collect/local exit moving. */
bool sl_events_next(SDL_Event *);
