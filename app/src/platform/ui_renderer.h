#pragma once
#include "platform/runtime.h"
#include "ui/ui_model.h"
typedef struct sl_ui_renderer sl_ui_renderer;
sl_ui_renderer *sl_ui_renderer_create(void *native_renderer);
void sl_ui_renderer_draw(sl_ui_renderer *, const sl_ui_model *, const sl_debug_snapshot *);
void sl_ui_renderer_destroy(sl_ui_renderer *);
