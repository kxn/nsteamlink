#include "platform/shortcut.h"
void sl_shortcut_source(int argc, char **argv) {
    (void)argc;
    (void)argv;
}
sl_text_id sl_shortcut_install(char *detail, size_t capacity) {
    if (capacity)
        detail[0] = 0;
    return SL_T_SHORTCUT_SWITCH_ONLY;
}
