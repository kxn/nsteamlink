// 平台抽象层（HAL）接口。
// 规则：本目录下的头文件不得包含任何平台专属头文件；业务代码只允许通过
// 这些接口使用平台能力，禁止出现 #ifdef __SWITCH__ 之类的平台条件编译。
#pragma once

typedef struct sl_hal sl_hal;

/// 创建平台后端实例，失败返回 NULL。
sl_hal *sl_hal_create(void);

/// 销毁平台后端实例，允许传入 NULL。
void sl_hal_destroy(sl_hal *hal);

/// 返回平台标识（"desktop" / "switch"），生命周期与 hal 实例相同。
const char *sl_hal_platform_name(const sl_hal *hal);
