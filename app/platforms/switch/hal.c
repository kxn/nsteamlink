// M0 构建验证用的最小后端（决策 D-006）：仅证明交叉编译管线可用，
// 不含任何协议 / 媒体逻辑。真正的 Switch 能力自 M2 起按里程碑补齐。
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
    return "switch";
}
