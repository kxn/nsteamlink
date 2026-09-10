#include "gfx_backend.h"
#include <SDL.h>
#include <stdlib.h>
bool sl_gfx_intersect(const sl_gfx_rect *a, const sl_gfx_rect *b, sl_gfx_rect *out) {
    int left = a->x > b->x ? a->x : b->x, top = a->y > b->y ? a->y : b->y;
    int right = a->x + a->w < b->x + b->w ? a->x + a->w : b->x + b->w;
    int bottom = a->y + a->h < b->y + b->h ? a->y + a->h : b->y + b->h;
    *out =
        (sl_gfx_rect){left, top, right > left ? right - left : 0, bottom > top ? bottom - top : 0};
    return out->w && out->h;
}
sl_gfx_texture *sl_gfx_from_surface(sl_gfx *gfx, SDL_Surface *source) {
    SDL_Surface *rgba = SDL_ConvertSurfaceFormat(source, SDL_PIXELFORMAT_RGBA32, 0);
    if (!rgba)
        return NULL;
    sl_gfx_texture *texture =
        sl_gfx_create_texture(gfx, SL_GFX_RGBA8, SL_GFX_STATIC, rgba->w, rgba->h);
    if (texture && sl_gfx_upload(texture, NULL, rgba->pixels, rgba->pitch)) {
        sl_gfx_destroy_texture(texture);
        texture = NULL;
    }
    if (texture)
        sl_gfx_texture_blend(texture, SL_GFX_BLEND_ALPHA);
    SDL_FreeSurface(rgba);
    return texture;
}

sl_gfx_texture *sl_gfx_glyph_surface(sl_gfx *gfx, SDL_Surface *source) {
#if NSL_GFX_DEKO
    SDL_Surface *rgba = SDL_ConvertSurfaceFormat(source, SDL_PIXELFORMAT_RGBA32, 0);
    if (!rgba)
        return NULL;
    unsigned char *alpha = malloc((size_t)rgba->w * rgba->h);
    sl_gfx_texture *texture = NULL;
    if (alpha) {
        for (int y = 0; y < rgba->h; ++y)
            for (int x = 0; x < rgba->w; ++x)
                alpha[(size_t)y * rgba->w + x] =
                    ((unsigned char *)rgba->pixels)[(size_t)y * rgba->pitch + x * 4 + 3];
        texture = sl_gfx_create_texture(gfx, SL_GFX_R8, SL_GFX_STATIC, rgba->w, rgba->h);
        if (texture && sl_gfx_upload(texture, NULL, alpha, rgba->w)) {
            sl_gfx_destroy_texture(texture);
            texture = NULL;
        }
        if (texture)
            sl_gfx_texture_blend(texture, SL_GFX_BLEND_ALPHA);
        free(alpha);
    }
    SDL_FreeSurface(rgba);
    return texture;
#else
    return sl_gfx_from_surface(gfx, source);
#endif
}
