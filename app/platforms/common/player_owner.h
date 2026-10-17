#pragma once
#include <stdbool.h>
#include <stdint.h>
/* Official SDL_main teardown gates. Hard/background are the original Android
 * process modes, kept separate from input focus and Remote Play pause. The
 * Switch runtime uses normal mode; final app shutdown always releases its ABI. */
typedef struct sl_player_teardown {
    bool request_quit, destroy_player, background;
} sl_player_teardown;
bool sl_player_input_focus(uint64_t window_flags);
sl_player_teardown sl_player_owner_decide(bool input_focus, bool hard, bool background);
