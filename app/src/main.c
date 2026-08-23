#include <stdio.h>

#include "platform/hal.h"

int main(void) {
    sl_hal *hal = sl_hal_create();
    if (hal == NULL) {
        fprintf(stderr, "nsteamlink: platform backend init failed\n");
        return 1;
    }
    printf("nsteamlink skeleton on %s\n", sl_hal_platform_name(hal));
    sl_hal_destroy(hal);
    return 0;
}
