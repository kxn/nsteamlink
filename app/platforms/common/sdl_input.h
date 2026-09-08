#pragma once
#include "input/input_router.h"
/* SDL owner callback; context is sl_input_router*. */
void sl_sdl_input(const void *event, void *context);
