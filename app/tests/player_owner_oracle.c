#include "player_owner.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    unsigned flags, hard, background, count;
    while (scanf("%u %u %u %u", &flags, &hard, &background, &count) == 4) {
        bool focus = sl_player_input_focus(flags);
        printf("{\"focus\":[%s", focus ? "true" : "false");
        for (unsigned i = 0; i < count; ++i) {
            unsigned event;
            assert(scanf("%u", &event) == 1 && event <= 1);
            focus = event != 0;
            printf(",%s", focus ? "true" : "false");
        }
        sl_player_teardown d = sl_player_owner_decide(focus, hard != 0, background != 0);
        printf("],\"quit\":%s,\"destroy\":%s,\"background\":%s}\n",
               d.request_quit ? "true" : "false", d.destroy_player ? "true" : "false",
               d.background ? "true" : "false");
    }
    return 0;
}
