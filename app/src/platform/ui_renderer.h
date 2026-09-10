#pragma once
#include "platform/gfx.h"
#include "platform/runtime.h"
#include "ui/ui_model.h"
typedef struct sl_ui_renderer sl_ui_renderer;
sl_ui_renderer *sl_ui_renderer_create(sl_gfx *native_renderer);
void sl_ui_renderer_draw(sl_ui_renderer *, const sl_ui_model *, const sl_debug_snapshot *);
void sl_ui_renderer_destroy(sl_ui_renderer *);

struct sl_artwork;
void sl_ui_renderer_set_artwork(sl_ui_renderer *, struct sl_artwork *);
