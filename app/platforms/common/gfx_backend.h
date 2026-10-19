#pragma once
#include "platform/gfx.h"
#include "video_pipeline.h"
/* CPU rasterizer bridge, private to platform code. */
struct SDL_Surface;
sl_gfx_texture *sl_gfx_from_surface(sl_gfx *, struct SDL_Surface *);
bool sl_gfx_video(sl_gfx *, sl_video_frame *);

void sl_gfx_forget_video(sl_gfx *);

sl_gfx_texture *sl_gfx_glyph_surface(sl_gfx *, struct SDL_Surface *);

/* Canonical 1280x720 screenshots stay independent of physical output size. */
bool sl_gfx_readback_copy(const void *source, unsigned width, unsigned height,
                          const sl_gfx_rect *logical_box, void *pixels, size_t bytes, int pitch);
