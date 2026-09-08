#include "platform/ui_renderer.h"
#include "platform/system.h"
#include <SDL.h>
#include <SDL_ttf.h>
#include <stdlib.h>
#include <string.h>
static const int sizes[] = {24, 26, 28, 30, 32, 36, 40, 44, 72};
typedef struct glyph {
    uint32_t code;
    int size, w, h, advance, left, top;
    SDL_Texture *texture;
    uint64_t used;
} glyph;
struct sl_ui_renderer {
    SDL_Renderer *renderer;
    TTF_Font *fonts[3][9];
    glyph cache[512];
    uint64_t tick;
};
static SDL_Color bg = {17, 24, 35, 255}, panel = {29, 39, 53, 255}, accent = {117, 207, 247, 255},
                 fg = {232, 242, 250, 255}, muted = {169, 194, 212, 255};
static void rect(SDL_Renderer *r, SDL_Rect box, SDL_Color c) {
    SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
    SDL_RenderFillRect(r, &box);
}
static void rounded(SDL_Renderer *r, SDL_Rect b, int radius, SDL_Color c) {
    rect(r, (SDL_Rect){b.x, b.y + radius, b.w, b.h - 2 * radius}, c);
    SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
    for (int y = 0; y < radius; ++y) {
        int x = 0, dy = radius - y - 1;
        while ((x + 1) * (x + 1) + dy * dy <= radius * radius)
            ++x;
        SDL_RenderDrawLine(r, b.x + radius - x, b.y + y, b.x + b.w - radius + x - 1, b.y + y);
        SDL_RenderDrawLine(r, b.x + radius - x, b.y + b.h - y - 1, b.x + b.w - radius + x - 1,
                           b.y + b.h - y - 1);
    }
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
    /* Crop transparent font padding, retaining a common baseline across fallback
     * fonts. Point size is not the visible glyph height (notably Switch CJK). */
    SDL_Surface *rgba = SDL_ConvertSurfaceFormat(surface, SDL_PIXELFORMAT_RGBA32, 0);
    if (!rgba) {
        SDL_FreeSurface(surface);
        return NULL;
    }
    int left = rgba->w, right = -1, top = rgba->h, bottom = -1;
    for (int y = 0; y < rgba->h; ++y)
        for (int x = 0; x < rgba->w; ++x) {
            Uint8 *pixel = (Uint8 *)rgba->pixels + y * rgba->pitch + x * 4;
            if (pixel[3]) {
                if (x < left)
                    left = x;
                if (x > right)
                    right = x;
                if (y < top)
                    top = y;
                if (y > bottom)
                    bottom = y;
            }
        }
    SDL_Rect crop = right >= left ? (SDL_Rect){left, top, right - left + 1, bottom - top + 1}
                                  : (SDL_Rect){0, 0, 1, 1};
    g->left = crop.x;
    g->top = crop.y - TTF_FontAscent(font);
    g->w = crop.w;
    g->h = crop.h;
    SDL_Surface *trimmed =
        SDL_CreateRGBSurfaceWithFormat(0, crop.w, crop.h, 32, SDL_PIXELFORMAT_RGBA32);
    if (!trimmed) {
        SDL_FreeSurface(rgba);
        SDL_FreeSurface(surface);
        return NULL;
    }
    SDL_SetSurfaceBlendMode(rgba, SDL_BLENDMODE_NONE);
    SDL_BlitSurface(rgba, &crop, trimmed, NULL);
    g->texture = SDL_CreateTextureFromSurface(r->renderer, trimmed);
    SDL_FreeSurface(trimmed);
    SDL_FreeSurface(rgba);
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
                SDL_SetTextureAlphaMod(dot->texture, color.a);
                SDL_Rect dst = {x + width - dot->w, y + height - line + size + dot->top, dot->w,
                                dot->h};
                SDL_RenderCopy(r->renderer, dot->texture, NULL, &dst);
            }
            break;
        }
        SDL_SetTextureColorMod(g->texture, color.r, color.g, color.b);
        SDL_SetTextureAlphaMod(g->texture, color.a);
        SDL_Rect dst = {px + g->left, py + size + g->top, g->w, g->h};
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
static int centered_y(sl_ui_renderer *r, const char *s, int size, int y, int height, int width) {
    int top = 0, bottom = 0, advance = 0, line = 0;
    bool any = false;
    while (*s) {
        uint32_t cp = utf8(&s);
        if (cp == '\n') {
            line += size + 10;
            advance = 0;
            continue;
        }
        glyph *g = get_glyph(r, cp, size);
        if (!g)
            continue;
        if (advance + g->advance > width) {
            if (line + size + 10 >= height)
                break;
            line += size + 10;
            advance = 0;
        }
        if (cp != ' ') {
            if (!any || g->top + line < top)
                top = g->top + line;
            if (!any || g->top + line + g->h > bottom)
                bottom = g->top + line + g->h;
            any = true;
        }
        advance += g->advance;
    }
    return y + (height - (bottom - top)) / 2 - size - top;
}
static void badge(sl_ui_renderer *r, const char *key, int x, int y, SDL_Color ink) {
    SDL_Rect b = {x, y, 34, 34};
    rounded(r->renderer, b, 17, ink);
    SDL_Color dark = bg;
    dark.a = ink.a;
    draw_text(r, key, x + (34 - text_width(r, key, 24)) / 2, centered_y(r, key, 24, y, 34, 34), 34,
              44, 24, bg);
}
static void chevron(SDL_Renderer *r, int x, int y, SDL_Color c) {
    SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
    for (int k = 0; k < 2; ++k) {
        SDL_RenderDrawLine(r, x + k, y - 6, x + 6 + k, y);
        SDL_RenderDrawLine(r, x + 6 + k, y, x + k, y + 6);
    }
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
        rounded(r->renderer, (SDL_Rect){268, 100, 744, 592}, 24, (SDL_Color){0, 0, 0, 80});
        rounded(r->renderer, (SDL_Rect){272, 96, 736, 588}, 22, panel);
        rect(r->renderer, (SDL_Rect){320, 183, 640, 1}, (SDL_Color){67, 82, 101, 255});
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
        if (!strcmp(t->text, "A  确认")) {
            badge(r, "A", x, 647, muted);
            draw_text(r, "确认", x + 48, centered_y(r, "确认", 26, 632, 64, width - 48), width - 48,
                      70, 26, fg);
        } else
            draw_text(r, t->text, x, t->y, width, t->size * 2 + 22, t->size, fg);
    }
    for (int i = 0; i < l->count; ++i) {
        const sl_control *c = &l->controls[i];
        SDL_Rect box = {c->x, c->y, c->w, c->h};
        bool tab = c->action == SL_SELECT_HOST;
        bool footer = c->label[0] && c->label[1] == ' ' && c->label[2] == ' ';
        bool shoulder = c->action == SL_PREV_HOST || c->action == SL_NEXT_HOST;
        bool focused = c->id == m->focus;
        bool plain = tab || footer || shoulder || (c->action == SL_START && !c->primary);
        SDL_Color ink = c->primary && !tab ? bg : fg;
        if (!plain || focused) {
            if (focused)
                rounded(r->renderer, (SDL_Rect){box.x - 3, box.y - 3, box.w + 6, box.h + 6}, 15,
                        accent);
            SDL_Color fill = c->primary && !tab ? accent
                             : focused          ? (SDL_Color){45, 67, 86, 255}
                                                : (SDL_Color){38, 51, 68, 255};
            rounded(r->renderer, box, 12, fill);
        }
        if (tab && c->primary) {
            rounded(r->renderer, (SDL_Rect){c->x + 28, c->y + c->h - 4, c->w - 56, 4}, 2, accent);
            ink = accent;
        }
        int size = c->action == SL_RECENT ? 36 : footer ? 26 : 30;
        const char *label = footer ? c->label + 3 : c->label;
        int x = c->x + 24, width = c->w - 48;
        bool centered = tab || c->action == SL_START || c->action == SL_DIGIT ||
                        c->action == SL_SUBMIT || shoulder || footer;
        int measured = text_width(r, label, size);
        if (footer) {
            int group = measured + 48;
            x = c->x + (c->w - group) / 2;
            char key[2] = {c->label[0], 0};
            badge(r, key, x, c->y + (c->h - 34) / 2, focused ? accent : muted);
            x += 48;
            width = measured + 2;
        } else if (shoulder) {
            rounded(r->renderer, (SDL_Rect){box.x + 8, box.y + 20, box.w - 16, 32}, 9, muted);
            ink = bg;
            x = c->x + (c->w - measured) / 2;
        } else if (centered && measured < width) {
            x = c->x + (c->w - measured) / 2;
            width = measured + 2;
        }
        int y = centered_y(r, label, size, c->y, c->h, width);
        if (c->action == SL_RECENT) {
            rounded(r->renderer, (SDL_Rect){box.x + 24, box.y + 24, 52, 52}, 14,
                    (SDL_Color){62, 92, 115, 255});
            chevron(r->renderer, box.x + 46, box.y + 50, accent);
            y = centered_y(r, label, size, box.y + box.h - 88, 64, width);
        } else if (!centered && !footer) {
            width -= 28;
            chevron(r->renderer, box.x + box.w - 35, box.y + box.h / 2, muted);
        }
        SDL_RenderSetClipRect(r->renderer, &box);
        draw_text(r, label, x, y, width, c->y + c->h - 8 - y, size, ink);
        SDL_RenderSetClipRect(r->renderer, NULL);
    }
    if (m->page == SL_STREAM && m->now >= m->stream_started_at) {
        uint64_t elapsed = m->now - m->stream_started_at;
        if (elapsed < 4200) {
            Uint8 alpha = elapsed < 2800 ? 255 : (Uint8)((4200 - elapsed) * 255 / 1400);
            rounded(r->renderer, (SDL_Rect){436, 592, 408, 64}, 18,
                    (SDL_Color){17, 24, 35, (Uint8)(alpha * 220 / 255)});
            SDL_Color ink = fg;
            ink.a = alpha;
            draw_text(r, "同时长按", 468, centered_y(r, "同时长按", 26, 592, 64, 120), 120, 70, 26,
                      ink);
            badge(r, "−", 602, 607, ink);
            badge(r, "+", 648, 607, ink);
            draw_text(r, "打开菜单", 708, centered_y(r, "打开菜单", 26, 592, 64, 280), 280, 70, 26,
                      ink);
        }
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
