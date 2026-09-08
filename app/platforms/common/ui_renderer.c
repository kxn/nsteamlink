#include "platform/ui_renderer.h"
#include "platform/system.h"
#include <SDL.h>
#include <SDL_ttf.h>
#include <stdlib.h>
#include <string.h>
static const int sizes[] = {24, 26, 28, 30, 32, 36, 40, 44, 72};
typedef struct glyph {
    uint32_t code;
    int size, w, h, advance;
    SDL_Texture *texture;
    uint64_t used;
} glyph;
struct sl_ui_renderer {
    SDL_Renderer *renderer;
    TTF_Font *fonts[3][9];
    glyph cache[512];
    uint64_t tick;
};
static SDL_Color bg = {16, 34, 53, 255}, panel = {28, 52, 75, 255}, accent = {142, 213, 255, 255},
                 fg = {232, 242, 250, 255}, muted = {169, 194, 212, 255};
static void rect(SDL_Renderer *r, SDL_Rect box, SDL_Color c) {
    SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
    SDL_RenderFillRect(r, &box);
}
static uint32_t utf8(const char **s) {
    const unsigned char *p = (const unsigned char *)*s;
    uint32_t c = *p++;
    int n = 0;
    if (c >= 0xf0) {
        c &= 7;
        n = 3;
    } else if (c >= 0xe0) {
        c &= 15;
        n = 2;
    } else if (c >= 0xc0) {
        c &= 31;
        n = 1;
    }
    for (int i = 0; i < n; ++i) {
        if ((*p & 0xc0) != 0x80) {
            *s = (const char *)p;
            return 0xfffd;
        }
        c = (c << 6) | (*p++ & 63);
    }
    *s = (const char *)p;
    return c;
}
static glyph *get_glyph(sl_ui_renderer *r, uint32_t code, int size) {
    int slot = 0;
    uint64_t oldest = UINT64_MAX;
    for (int i = 0; i < 512; ++i) {
        glyph *g = &r->cache[i];
        if (g->texture && g->code == code && g->size == size) {
            g->used = ++r->tick;
            return g;
        }
        if (g->used < oldest) {
            oldest = g->used;
            slot = i;
        }
    }
    int sz = 0;
    while (sz < 8 && sizes[sz] < size)
        sz++;
    TTF_Font *font = NULL;
    for (int f = 0; f < 3; ++f) {
        if (r->fonts[f][sz] && TTF_GlyphIsProvided32(r->fonts[f][sz], code)) {
            font = r->fonts[f][sz];
            break;
        }
    }
    if (!font)
        font = r->fonts[0][sz];
    if (!font)
        return NULL;
    SDL_Surface *surface = TTF_RenderGlyph32_Blended(font, code, (SDL_Color){255, 255, 255, 255});
    if (!surface)
        return NULL;
    glyph *g = &r->cache[slot];
    SDL_DestroyTexture(g->texture);
    *g = (glyph){.code = code, .size = size, .w = surface->w, .h = surface->h, .used = ++r->tick};
    TTF_GlyphMetrics32(font, code, NULL, NULL, NULL, NULL, &g->advance);
    g->texture = SDL_CreateTextureFromSurface(r->renderer, surface);
    SDL_FreeSurface(surface);
    return g;
}
static void draw_text(sl_ui_renderer *r, const char *s, int x, int y, int width, int height,
                      int size, SDL_Color color) {
    int px = x, py = y, line = size + 10;
    while (*s) {
        uint32_t cp = utf8(&s);
        if (cp == '\n') {
            px = x;
            py += line;
            continue;
        }
        glyph *g = get_glyph(r, cp, size);
        if (!g)
            continue;
        if (px + g->advance > x + width) {
            px = x;
            py += line;
        }
        if (py + size > y + height) {
            glyph *dot = get_glyph(r, 0x2026, size);
            if (dot) {
                SDL_SetTextureColorMod(dot->texture, color.r, color.g, color.b);
                SDL_Rect dst = {x + width - dot->w, y + height - line, dot->w, dot->h};
                SDL_RenderCopy(r->renderer, dot->texture, NULL, &dst);
            }
            break;
        }
        SDL_SetTextureColorMod(g->texture, color.r, color.g, color.b);
        SDL_Rect dst = {px, py, g->w, g->h};
        SDL_RenderCopy(r->renderer, g->texture, NULL, &dst);
        px += g->advance;
    }
}
static int text_width(sl_ui_renderer *r, const char *s, int size) {
    int width = 0;
    while (*s) {
        glyph *g = get_glyph(r, utf8(&s), size);
        if (g)
            width += g->advance;
    }
    return width;
}
sl_ui_renderer *sl_ui_renderer_create(void *native) {
    if (TTF_Init())
        return NULL;
    sl_ui_renderer *r = calloc(1, sizeof(*r));
    if (!r) {
        TTF_Quit();
        return NULL;
    }
    r->renderer = native;
    for (int f = 0; f < 3; ++f) {
        size_t bytes;
        const char *path;
        const void *data = sl_system_font(f, &bytes, &path);
        for (int s = 0; s < 9; ++s) {
            if (data && bytes)
                r->fonts[f][s] = TTF_OpenFontRW(SDL_RWFromConstMem(data, (int)bytes), 1, sizes[s]);
            else if (path)
                r->fonts[f][s] = TTF_OpenFont(path, sizes[s]);
        }
    }
    if (!r->fonts[0][0] || !r->fonts[1][0]) {
        sl_ui_renderer_destroy(r);
        return NULL;
    }
    SDL_SetRenderDrawBlendMode(r->renderer, SDL_BLENDMODE_BLEND);
    return r;
}
void sl_ui_renderer_draw(sl_ui_renderer *r, const sl_ui_model *m, const sl_debug_snapshot *d) {
    const sl_layout *l = &m->layout;
    if (!l->fullscreen)
        rect(r->renderer, (SDL_Rect){0, 0, 1280, 720}, bg);
    if (l->dialog) {
        rect(r->renderer, (SDL_Rect){0, 0, 1280, 720}, (SDL_Color){0, 0, 0, 140});
        rect(r->renderer, (SDL_Rect){272, 96, 736, 588}, panel);
    }
    if (l->title[0])
        draw_text(r, l->title, l->dialog ? 320 : 64, l->dialog ? 128 : 20, l->dialog ? 640 : 1100,
                  68, l->dialog ? 40 : 26, fg);
    for (int i = 0; i < l->label_count; ++i) {
        const sl_label *t = &l->labels[i];
        int x = t->x, width = l->dialog ? 960 - x : 1216 - x;
        if (t->center) {
            int measured = text_width(r, t->text, t->size);
            if (measured < 1152) {
                x = (1280 - measured) / 2;
                width = measured + 2;
            }
        }
        draw_text(r, t->text, x, t->y, width, t->size * 2 + 22, t->size, fg);
    }
    for (int i = 0; i < l->count; ++i) {
        const sl_control *c = &l->controls[i];
        SDL_Rect box = {c->x, c->y, c->w, c->h};
        bool tab = c->action == SL_SELECT_HOST,
             plain = m->page == SL_HOME &&
                     (tab || c->y >= 632 || c->action == SL_PREV_HOST ||
                      c->action == SL_NEXT_HOST || (c->action == SL_START && !c->primary));
        SDL_Color ink = c->primary && !tab ? (SDL_Color){16, 43, 62, 255} : fg;
        rect(r->renderer, box, plain ? bg : c->primary ? accent : panel);
        if (tab && c->primary) {
            rect(r->renderer, (SDL_Rect){c->x, c->y + c->h - 3, c->w, 3}, accent);
            ink = accent;
        }
        if (c->id == m->focus) {
            SDL_SetRenderDrawColor(r->renderer, accent.r, accent.g, accent.b, 255);
            for (int k = 0; k < 3; ++k) {
                SDL_Rect edge = {box.x - k - 2, box.y - k - 2, box.w + k * 2 + 4,
                                 box.h + k * 2 + 4};
                SDL_RenderDrawRect(r->renderer, &edge);
            }
        }
        int size = c->action == SL_RECENT ? 40 : c->y >= 632 ? 26 : 30;
        int x = c->x + 20, width = c->w - 40,
            y = c->y + (c->action == SL_RECENT ? c->h - 76
                        : c->h > 100           ? 24
                                               : 14);
        bool centered = tab || c->action == SL_START || c->action == SL_DIGIT ||
                        c->action == SL_SUBMIT || c->action == SL_OPEN_MENU || c->y >= 632;
        int measured = text_width(r, c->label, size);
        if (centered && measured < width) {
            x = c->x + (c->w - measured) / 2;
            width = measured + 2;
        }
        draw_text(r, c->label, x, y, width, c->action == SL_RECENT ? 66 : c->h - 18, size, ink);
    }
    if (m->debug && m->streaming && m->page == SL_STREAM) {
        rect(r->renderer, (SDL_Rect){24, 24, 500, 320}, panel);
        draw_text(r, d->title[0] ? d->title : "诊断", 44, 42, 460, 38, 24, muted);
        const char *names[] = {"呈现",     "本机视频",        "解码 / 上传",
                               "音频缓冲", "HID 待发 / 在途", "最大 ACK 等待"};
        for (int i = 0; i < 6; ++i) {
            draw_text(r, names[i], 44, 90 + i * 36, 250, 34, 24, fg);
            draw_text(r, d->values[i][0] ? d->values[i] : "—", 296, 90 + i * 36, 208, 34, 24, fg);
        }
        if (m->now > d->sampled_at + 3000)
            draw_text(r, "数据已过期", 44, 304, 400, 32, 24, muted);
    }
}
void sl_ui_renderer_destroy(sl_ui_renderer *r) {
    if (!r)
        return;
    for (int i = 0; i < 512; ++i)
        SDL_DestroyTexture(r->cache[i].texture);
    for (int f = 0; f < 3; ++f)
        for (int s = 0; s < 9; ++s)
            if (r->fonts[f][s])
                TTF_CloseFont(r->fonts[f][s]);
    free(r);
    TTF_Quit();
}
