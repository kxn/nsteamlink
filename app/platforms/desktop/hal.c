#include <stdlib.h>

#include "platform/hal.h"

struct sl_hal {
    int unused;
};

sl_hal *sl_hal_create(void) {
    return calloc(1, sizeof(sl_hal));
}

void sl_hal_destroy(sl_hal *hal) {
    free(hal);
}

const char *sl_hal_platform_name(const sl_hal *hal) {
    (void)hal;
    return "desktop";
}
