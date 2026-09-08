#include "platform/ui_renderer.h"
#include "platform/system.h"
#include <SDL.h>
#include <SDL_ttf.h>
#include <math.h>
#include <stdio.h>
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
    SDL_Texture *backdrop, *outline;
    float text_alpha;
    bool painted, focus_valid;
    sl_page page;
    int focus_id;
    uint64_t focus_at, page_at;
    SDL_FRect focus_from, focus_to, focus_box;
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
static float ease(uint64_t elapsed, float duration) {
    float t = elapsed / duration;
    if (t >= 1.f)
        return 1.f;
    float remaining = 1.f - t;
    return 1.f - remaining * remaining * remaining;
}
static SDL_Color mix(SDL_Color a, SDL_Color b, float t) {
    return (SDL_Color){a.r + (b.r - a.r) * t, a.g + (b.g - a.g) * t, a.b + (b.b - a.b) * t,
                       a.a + (b.a - a.a) * t};
}
static void line(SDL_Renderer *r, int x1, int y1, int x2, int y2, SDL_Color c) {
    SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
    SDL_RenderDrawLine(r, x1, y1, x2, y2);
    SDL_RenderDrawLine(r, x1, y1 + 1, x2, y2 + 1);
}
static void play_icon(SDL_Renderer *r, int x, int y, int size, SDL_Color color) {
    SDL_SetRenderDrawColor(r, color.r, color.g, color.b, color.a);
    for (int i = 0; i < size; ++i) {
        int half = (size - i) / 2;
        SDL_RenderDrawLine(r, x + i, y - half, x + i, y + half);
    }
}
static void monitor(SDL_Renderer *r, int x, int y, int size, SDL_Color color) {
    rounded(r, (SDL_Rect){x, y, size, size * 2 / 3}, 6, color);
    rounded(r, (SDL_Rect){x + 2, y + 2, size - 4, size * 2 / 3 - 4}, 4,
            (SDL_Color){26, 40, 55, 255});
    line(r, x + size / 2, y + size * 2 / 3, x + size / 2, y + size * 2 / 3 + 7, color);
    line(r, x + size / 2 - 9, y + size * 2 / 3 + 8, x + size / 2 + 9, y + size * 2 / 3 + 8, color);
}
static SDL_Texture *make_backdrop(SDL_Renderer *r) {
    SDL_Surface *s = SDL_CreateRGBSurfaceWithFormat(0, 1280, 720, 32, SDL_PIXELFORMAT_RGBA32);
    if (!s)
        return NULL;
    for (int y = 0; y < 720; ++y)
        for (int x = 0; x < 1280; ++x) {
            float dx = (x - 960) / 1050.f, dy = (y + 80) / 800.f;
            float glow = 1.f - dx * dx - dy * dy;
            if (glow < 0)
                glow = 0;
            Uint8 *p = (Uint8 *)s->pixels + y * s->pitch + x * 4;
            p[0] = 15 + 9 * glow;
            p[1] = 21 + 17 * glow;
            p[2] = 30 + 23 * glow;
            p[3] = 255;
        }
    SDL_Texture *texture = SDL_CreateTextureFromSurface(r, s);
    SDL_FreeSurface(s);
    return texture;
}
static SDL_Texture *make_outline(SDL_Renderer *r) {
    SDL_Surface *s = SDL_CreateRGBSurfaceWithFormat(0, 64, 64, 32, SDL_PIXELFORMAT_RGBA32);
    if (!s)
        return NULL;
    for (int y = 0; y < 64; ++y)
        for (int x = 0; x < 64; ++x) {
            float qx = fabsf(x - 31.5f) - 18.f, qy = fabsf(y - 31.5f) - 18.f;
            float ax = fmaxf(qx, 0), ay = fmaxf(qy, 0);
            float distance = sqrtf(ax * ax + ay * ay) + fminf(fmaxf(qx, qy), 0) - 13.5f;
            float outer = fminf(1, fmaxf(0, .5f - distance));
            float inner = fminf(1, fmaxf(0, .5f - distance - 2));
            Uint8 *p = (Uint8 *)s->pixels + y * s->pitch + x * 4;
            p[0] = p[1] = p[2] = 255;
            p[3] = (Uint8)((outer - inner) * 255);
        }
    SDL_Texture *texture = SDL_CreateTextureFromSurface(r, s);
    SDL_FreeSurface(s);
    if (texture)
        SDL_SetTextureBlendMode(texture, SDL_BLENDMODE_BLEND);
    return texture;
}
static void outline(sl_ui_renderer *r, SDL_Rect b) {
    if (!r->outline)
        return;
    SDL_SetTextureColorMod(r->outline, accent.r, accent.g, accent.b);
    const int source[] = {0, 16, 48, 64};
    int xs[] = {b.x, b.x + 16, b.x + b.w - 16, b.x + b.w};
    int ys[] = {b.y, b.y + 16, b.y + b.h - 16, b.y + b.h};
    for (int y = 0; y < 3; ++y)
        for (int x = 0; x < 3; ++x) {
            if (x == 1 && y == 1)
                continue;
            SDL_Rect src = {source[x], source[y], source[x + 1] - source[x],
                            source[y + 1] - source[y]};
            SDL_Rect dst = {xs[x], ys[y], xs[x + 1] - xs[x], ys[y + 1] - ys[y]};
            SDL_RenderCopy(r->renderer, r->outline, &src, &dst);
        }
}
static void animate_focus(sl_ui_renderer *r, const sl_ui_model *m) {
    bool page_changed = !r->painted || r->page != m->page;
    if (page_changed) {
        r->page = m->page;
        r->page_at = m->now;
        r->focus_valid = false;
    }
    r->painted = true;
    const sl_control *target = NULL;
    for (int i = 0; i < m->layout.count; ++i)
        if (m->layout.controls[i].id == m->focus)
            target = &m->layout.controls[i];
    if (!target) {
        r->focus_valid = false;
        return;
    }
    SDL_FRect dest = {(float)target->x, (float)target->y, (float)target->w, (float)target->h};
    if (!r->focus_valid) {
        r->focus_from = r->focus_to = r->focus_box = dest;
        r->focus_id = m->focus;
        r->focus_at = m->now;
        r->focus_valid = true;
    } else if (r->focus_id != m->focus || memcmp(&dest, &r->focus_to, sizeof(dest))) {
        r->focus_from = r->focus_box;
        r->focus_to = dest;
        r->focus_id = m->focus;
        r->focus_at = m->now;
    }
    float t = ease(m->now >= r->focus_at ? m->now - r->focus_at : 0, 140);
    r->focus_box = (SDL_FRect){r->focus_from.x + (dest.x - r->focus_from.x) * t,
                               r->focus_from.y + (dest.y - r->focus_from.y) * t,
                               r->focus_from.w + (dest.w - r->focus_from.w) * t,
                               r->focus_from.h + (dest.h - r->focus_from.h) * t};
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
    color.a = (Uint8)(color.a * r->text_alpha);
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
              44, 24, dark);
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
    r->backdrop = make_backdrop(r->renderer);
    r->outline = make_outline(r->renderer);
    r->text_alpha = 1.f;
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
    animate_focus(r, m);
    float arrival = ease(m->now >= r->page_at ? m->now - r->page_at : 0, 180);
    r->text_alpha = l->dialog ? .65f + .35f * arrival : 1.f;
    if (!l->fullscreen) {
        if (r->backdrop)
            SDL_RenderCopy(r->renderer, r->backdrop, NULL, NULL);
        else
            rect(r->renderer, (SDL_Rect){0, 0, 1280, 720}, bg);
    }
    if (l->dialog) {
        rect(r->renderer, (SDL_Rect){0, 0, 1280, 720}, (SDL_Color){0, 0, 0, 105 + 35 * arrival});
        rounded(r->renderer, (SDL_Rect){268, 100, 744, 592}, 24, (SDL_Color){0, 0, 0, 80});
        rounded(r->renderer, (SDL_Rect){271, 95, 738, 590}, 23, (SDL_Color){61, 77, 94, 255});
        rounded(r->renderer, (SDL_Rect){272, 96, 736, 588}, 22,
                mix(bg, panel, .8f + .2f * arrival));
        rect(r->renderer, (SDL_Rect){320, 183, 640, 1}, (SDL_Color){67, 82, 101, 255});
    }
    if (l->title[0]) {
        if (!l->dialog) {
            draw_text(r, "NSteamLink", 52, centered_y(r, "NSteamLink", 28, 18, 44, 220), 220, 64,
                      28, fg);
            draw_text(r, "http://github.com/kxn/nsteamlink", 276,
                      centered_y(r, "http://github.com/kxn/nsteamlink", 24, 18, 44, 780), 780, 64,
                      24, muted);
            char version[40];
            snprintf(version, sizeof(version), "v%s", NSL_APP_VERSION);
            int w = text_width(r, version, 24) + 32;
            rounded(r->renderer, (SDL_Rect){1228 - w, 23, w, 34}, 10, (SDL_Color){38, 53, 68, 255});
            draw_text(r, version, 1244 - w, centered_y(r, version, 24, 23, 34, w), w, 48, 24,
                      muted);
            rect(r->renderer, (SDL_Rect){52, 76, 1176, 1}, (SDL_Color){78, 103, 124, 60});
        } else
            draw_text(r, l->title, 320, 128, 640, 68, 40, fg);
    }
    if (m->page == SL_HOME && !m->layout.dialog) {
        const sl_host_registry *hosts = &m->store.registry;
        const sl_host *host = hosts->selected >= 0 && hosts->selected < hosts->count
                                  ? &hosts->hosts[hosts->selected]
                                  : NULL;
        if (!host || !host->paired || !host->games[0].id) {
            rounded(r->renderer, (SDL_Rect){596, 194, 88, 72}, 20, (SDL_Color){49, 81, 104, 75});
            monitor(r->renderer, 615, 210, 50, muted);
        }
        rect(r->renderer, (SDL_Rect){52, 612, 1176, 1}, (SDL_Color){78, 103, 124, 45});
    }
    if (m->page == SL_CONNECTING || m->page == SL_SAVING ||
        (m->page == SL_PAIRING && !sl_ui_pair_prompt_visible(m))) {
        rounded(r->renderer, (SDL_Rect){532, 426, 216, 3}, 1, (SDL_Color){45, 64, 81, 255});
        float phase = (m->now % 1500) / 1500.f;
        float travel = phase < .5f ? phase * 2 : 2 - phase * 2;
        rounded(r->renderer, (SDL_Rect){532 + (int)(156 * travel), 426, 60, 3}, 1, accent);
    }
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
            if (!plain) {
                rounded(r->renderer, (SDL_Rect){box.x, box.y + 3, box.w, box.h}, 13,
                        (SDL_Color){0, 0, 0, 50});
                rounded(r->renderer, (SDL_Rect){box.x - 1, box.y - 1, box.w + 2, box.h + 2}, 13,
                        (SDL_Color){64, 83, 101, 120});
            }
            SDL_Color fill = c->primary && !tab ? accent
                             : focused          ? (SDL_Color){42, 63, 80, 255}
                                                : (SDL_Color){32, 45, 60, 255};
            rounded(r->renderer, box, 12, fill);
            if (c->primary && !tab)
                rounded(r->renderer, (SDL_Rect){box.x + 12, box.y + 1, box.w - 24, 1}, 0,
                        (SDL_Color){213, 244, 255, 150});
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
            play_icon(r->renderer, box.x + 43, box.y + 50, 18, accent);
            y = centered_y(r, label, size, box.y + box.h - 88, 64, width);
        } else if (!centered && !footer) {
            width -= 28;
            chevron(r->renderer, box.x + box.w - 35, box.y + box.h / 2, muted);
        }
        SDL_RenderSetClipRect(r->renderer, &box);
        draw_text(r, label, x, y, width, c->y + c->h - 8 - y, size, ink);
        SDL_RenderSetClipRect(r->renderer, NULL);
    }
    if (r->focus_valid && m->page != SL_STREAM) {
        SDL_FRect f = r->focus_box;
        SDL_SetRenderDrawColor(r->renderer, accent.r, accent.g, accent.b, 210);
        /* Only the focus indicator moves; control layout and hit testing stay fixed. */
        SDL_Rect b = {(int)f.x - 3, (int)f.y - 3, (int)f.w + 6, (int)f.h + 6};
        outline(r, b);
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
    SDL_DestroyTexture(r->backdrop);
    SDL_DestroyTexture(r->outline);
    for (int i = 0; i < 512; ++i)
        SDL_DestroyTexture(r->cache[i].texture);
    for (int f = 0; f < 3; ++f)
        for (int s = 0; s < 9; ++s)
            if (r->fonts[f][s])
                TTF_CloseFont(r->fonts[f][s]);
    free(r);
    TTF_Quit();
}
