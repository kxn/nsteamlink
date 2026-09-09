#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct sl_gfx sl_gfx;
typedef struct sl_gfx_texture sl_gfx_texture;
typedef struct sl_gfx_rect {
    int x, y, w, h;
} sl_gfx_rect;
typedef struct sl_gfx_frect {
    float x, y, w, h;
} sl_gfx_frect;
typedef struct sl_gfx_color {
    uint8_t r, g, b, a;
} sl_gfx_color;
typedef enum {
    SL_GFX_READY,
    SL_GFX_BUSY,
    SL_GFX_SUSPENDED,
    SL_GFX_CAPACITY,
    SL_GFX_ERROR
} sl_gfx_result;
typedef struct sl_gfx_config {
    unsigned width, height;
    const char *title;
} sl_gfx_config;
typedef struct sl_gfx_present_result {
    sl_gfx_result result;
    bool submitted, output_returned;
    uint64_t submission_serial;
} sl_gfx_present_result;
typedef enum { SL_GFX_RGBA8, SL_GFX_R8, SL_GFX_RG8 } sl_gfx_format;
typedef enum { SL_GFX_STATIC, SL_GFX_TARGET } sl_gfx_access;
typedef enum { SL_GFX_BLEND_NONE, SL_GFX_BLEND_ALPHA } sl_gfx_blend;
sl_gfx *sl_gfx_create(const sl_gfx_config *);
sl_gfx_result sl_gfx_begin(sl_gfx *);
sl_gfx_present_result sl_gfx_present(sl_gfx *);
void sl_gfx_collect(sl_gfx *);
sl_gfx_result sl_gfx_poll_drain(sl_gfx *);
void sl_gfx_destroy(sl_gfx *);
bool sl_gfx_healthy(const sl_gfx *);
sl_gfx_texture *sl_gfx_create_texture(sl_gfx *, sl_gfx_format, sl_gfx_access, int, int);
void sl_gfx_destroy_texture(sl_gfx_texture *);
int sl_gfx_upload(sl_gfx_texture *, const sl_gfx_rect *, const void *, int pitch);
int sl_gfx_texture_blend(sl_gfx_texture *, sl_gfx_blend);
int sl_gfx_texture_color(sl_gfx_texture *, uint8_t, uint8_t, uint8_t);
int sl_gfx_texture_alpha(sl_gfx_texture *, uint8_t);
int sl_gfx_texture_linear(sl_gfx_texture *, int linear);
int sl_gfx_draw_color(sl_gfx *, uint8_t, uint8_t, uint8_t, uint8_t);
int sl_gfx_draw_blend(sl_gfx *, sl_gfx_blend);
int sl_gfx_clear(sl_gfx *);
int sl_gfx_fill(sl_gfx *, const sl_gfx_rect *);
int sl_gfx_line(sl_gfx *, int, int, int, int);
int sl_gfx_point(sl_gfx *, int, int);
int sl_gfx_copy(sl_gfx *, sl_gfx_texture *, const sl_gfx_rect *, const sl_gfx_rect *);
int sl_gfx_copy_f(sl_gfx *, sl_gfx_texture *, const sl_gfx_rect *, const sl_gfx_frect *);
int sl_gfx_target(sl_gfx *, sl_gfx_texture *);
sl_gfx_texture *sl_gfx_get_target(sl_gfx *);
int sl_gfx_viewport(sl_gfx *, const sl_gfx_rect *);
void sl_gfx_get_viewport(sl_gfx *, sl_gfx_rect *);
int sl_gfx_clip(sl_gfx *, const sl_gfx_rect *);
bool sl_gfx_intersect(const sl_gfx_rect *, const sl_gfx_rect *, sl_gfx_rect *);
/* Readback must be requested before recording and completed with its batch. */
bool sl_gfx_request_readback(sl_gfx *);
bool sl_gfx_readback(sl_gfx *, const sl_gfx_rect *, void *rgba, size_t bytes, int pitch);

/* Exit-only SDK idle boundary. Does not treat a timeout as safe release. */
void sl_gfx_finish(sl_gfx *);

/* Renderer-thread diagnostic snapshot; counters do not touch the protocol. */
typedef struct sl_gfx_counters {
    uint64_t imports, uploads, uploaded_bytes, video_draws, retired_groups;
    size_t image_bytes, imported_bytes;
    unsigned pool_groups, maps, busy_batches;
} sl_gfx_counters;
void sl_gfx_get_counters(const sl_gfx *, sl_gfx_counters *);
