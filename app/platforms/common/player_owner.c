#include "player_owner.h"
bool sl_player_input_focus(uint64_t window_flags) {
    return (window_flags & UINT64_C(0x200)) != 0;
}
sl_player_teardown sl_player_owner_decide(bool input_focus, bool hard, bool background) {
    if (!input_focus)
        background = true;
    return (sl_player_teardown){.request_quit = !hard && !background,
                                .destroy_player = !background,
                                .background = background};
}
