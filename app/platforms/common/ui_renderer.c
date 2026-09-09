#include "platform/ui_renderer.h"
#include "artwork.h"
#include "platform/system.h"
#include "services/i18n.h"
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
    SDL_Texture *backdrop, *outline, *overlay;
    sl_ui_model *base_ui;
    sl_artwork *artwork;
    struct {
        uint64_t id, used, ready_at;
        SDL_Texture *texture, *blurred;
        int w, h;
    } covers[8];
    float text_alpha;
    bool painted, focus_valid;
    sl_page page;
    int focus_id;
    uint64_t focus_at, title_at, title_host;
    int title_focus;
    char title_text[512];
    struct {
        uint64_t id, used;
        int language;
        char name[512];
    } titles[16];
    SDL_FRect focus_from, focus_to, focus_box;
};
static SDL_Color bg = {18, 20, 25, 255}, panel = {32, 35, 42, 255}, accent = {114, 199, 242, 255},
                 fg = {239, 242, 246, 255}, muted = {162, 170, 184, 255},
                 green = {154, 218, 104, 255}, amber = {241, 190, 104, 255},
                 violet = {179, 158, 238, 255}, coral = {239, 130, 130, 255};
static void rect(SDL_Renderer *r, SDL_Rect box, SDL_Color c) {
    SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
    SDL_RenderFillRect(r, &box);
}
static void rounded(SDL_Renderer *r, SDL_Rect b, int radius, SDL_Color c) {
    rect(r, (SDL_Rect){b.x, b.y + radius, b.w, b.h - 2 * radius}, c);
    for (int y = 0; y < radius; ++y) {
        float dy = radius - y - .5f;
        float edge = radius - sqrtf(radius * radius - dy * dy);
        int inset = (int)edge;
        SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
        SDL_RenderDrawLine(r, b.x + inset + 1, b.y + y, b.x + b.w - inset - 2, b.y + y);
        SDL_RenderDrawLine(r, b.x + inset + 1, b.y + b.h - y - 1, b.x + b.w - inset - 2,
                           b.y + b.h - y - 1);
        SDL_SetRenderDrawColor(r, c.r, c.g, c.b, (Uint8)(c.a * (1.f - edge + inset)));
        SDL_RenderDrawPoint(r, b.x + inset, b.y + y);
        SDL_RenderDrawPoint(r, b.x + b.w - inset - 1, b.y + y);
        SDL_RenderDrawPoint(r, b.x + inset, b.y + b.h - y - 1);
        SDL_RenderDrawPoint(r, b.x + b.w - inset - 1, b.y + b.h - y - 1);
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
extern const unsigned char nsl_background[];
extern const size_t nsl_background_size;
static SDL_Texture *make_backdrop(SDL_Renderer *r) {
    SDL_Surface *s =
        SDL_LoadBMP_RW(SDL_RWFromConstMem(nsl_background, (int)nsl_background_size), 1);
    if (!s)
        return NULL;
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
    SDL_SetTextureColorMod(r->outline, fg.r, fg.g, fg.b);
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
    if (page_changed)
        r->title_focus = 0;
    if (page_changed) {
        r->page = m->page;
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
    if (m->page == SL_HOME || !r->focus_valid) {
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
static const char *localized_title(sl_ui_renderer *r, uint64_t id, const char *fallback) {
    int language = sl_i18n_resolved(), slot = -1;
    for (int i = 0; i < 16; ++i)
        if (r->titles[i].id == id && r->titles[i].language == language) {
            slot = i;
            break;
        }
    if (slot < 0) {
        slot = 0;
        for (int i = 1; i < 16; ++i)
            if (r->titles[i].used < r->titles[slot].used)
                slot = i;
        r->titles[slot].id = id;
        r->titles[slot].language = language;
        r->titles[slot].name[0] = 0;
    }
    r->titles[slot].used = ++r->tick;
    char name[512];
    if (sl_artwork_title(r->artwork, id, language, name, sizeof(name)))
        strcpy(r->titles[slot].name, name);
    return r->titles[slot].name[0] ? r->titles[slot].name : fallback;
}
/* A card title is always one line. Measure visible glyph bounds independently
 * of clipping so neither truncation nor scrolling changes its baseline. */
static void card_title(sl_ui_renderer *r, const char *label, SDL_Rect box, SDL_Rect viewport,
                       bool focused, const sl_ui_model *m) {
    char text[512];
    snprintf(text, sizeof(text), "%s", label);
    for (char *p = text; *p; ++p)
        if (*p == '\n' || *p == '\r')
            *p = ' ';
    const int size = 30;
    int measured = text_width(r, text, size), top = 0, bottom = 0;
    bool any = false;
    for (const char *p = text; *p;) {
        uint32_t cp = utf8(&p);
        glyph *g = get_glyph(r, cp, size);
        if (g && cp != ' ') {
            if (!any || g->top < top)
                top = g->top;
            if (!any || g->top + g->h > bottom)
                bottom = g->top + g->h;
            any = true;
        }
    }
    float offset = 0.f;
    if (focused) {
        if (r->title_focus != m->focus || r->title_host != m->games_host ||
            strcmp(r->title_text, text) || m->games_dragging ||
            fabsf(m->games_target - m->games_scroll) > .5f) {
            r->title_focus = m->focus;
            r->title_host = m->games_host;
            snprintf(r->title_text, sizeof(r->title_text), "%s", text);
            r->title_at = m->now;
        }
        if (measured > box.w && m->now >= r->title_at) {
            float travel = (measured - box.w) / 30.f; /* 30 pixels / second. */
            float t = fmodf((m->now - r->title_at) / 1000.f, 2.f * travel + 2.4f);
            if (t > 1.2f && t <= 1.2f + travel)
                offset = (t - 1.2f) * 30.f;
            else if (t > 1.2f + travel && t <= 2.4f + travel)
                offset = measured - box.w;
            else if (t > 2.4f + travel)
                offset = (2.4f + 2.f * travel - t) * 30.f;
        }
    }
    SDL_Rect clip;
    if (!SDL_IntersectRect(&box, &viewport, &clip))
        return;
    SDL_RenderSetClipRect(r->renderer, &clip);
    int baseline = box.y + (box.h - (bottom - top)) / 2 - top;
    bool truncated = !focused && measured > box.w;
    int dots = truncated ? text_width(r, "...", size) : 0;
    int pen = box.x - (int)offset;
    const char *p = text;
    while (*p) {
        glyph *g = get_glyph(r, utf8(&p), size);
        if (!g)
            continue;
        if (truncated && pen + g->advance > box.x + box.w - dots)
            break;
        SDL_SetTextureColorMod(g->texture, fg.r, fg.g, fg.b);
        SDL_SetTextureAlphaMod(g->texture, (Uint8)(255 * r->text_alpha));
        SDL_Rect dst = {pen + g->left, baseline + g->top, g->w, g->h};
        SDL_RenderCopy(r->renderer, g->texture, NULL, &dst);
        pen += g->advance;
    }
    if (truncated) {
        glyph *dot = get_glyph(r, '.', size);
        if (dot) {
            SDL_SetTextureColorMod(dot->texture, fg.r, fg.g, fg.b);
            SDL_SetTextureAlphaMod(dot->texture, (Uint8)(255 * r->text_alpha));
            for (int i = 0; i < 3; ++i) {
                SDL_Rect dst = {pen + dot->left, baseline + dot->top, dot->w, dot->h};
                SDL_RenderCopy(r->renderer, dot->texture, NULL, &dst);
                pen += dot->advance;
            }
        }
    }
    SDL_RenderSetClipRect(r->renderer, NULL);
}
static void badge(sl_ui_renderer *r, const char *key, int x, int y, SDL_Color ink) {
    SDL_Rect b = {x, y, 34, 34};
    rounded(r->renderer, b, 17, ink);
    SDL_Color dark = ink.r < 80 ? fg : bg;
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
static SDL_Color action_color(sl_action a) {
    switch (a) {
    case SL_START:
    case SL_RECENT:
    case SL_BACK:
        return green;
    case SL_OPEN_SETTINGS:
    case SL_OPEN_QUALITY:
    case SL_SET_QUALITY:
        return violet;
    case SL_OPEN_MANUAL:
        return amber;
    case SL_OPEN_FORGET:
    case SL_CONFIRM_FORGET:
    case SL_CONFIRM_STOP:
        return coral;
    default:
        return accent;
    }
}
/* Native two-pixel pictograms, sharing the same 28px optical box. */
static void action_icon(SDL_Renderer *r, sl_action a, int x, int y, SDL_Color c) {
    if (a == SL_BACK || a == SL_START || a == SL_RECENT) {
        play_icon(r, x + 7, y + 14, 19, c);
    } else if (a == SL_OPEN_SETTINGS || a == SL_SET_QUALITY) {
        for (int i = 0; i < 3; ++i) {
            int yy = y + 6 + i * 8, xx = x + (i == 1 ? 17 : 9);
            line(r, x + 3, yy, x + 27, yy, c);
            rounded(r, (SDL_Rect){xx - 2, yy - 3, 5, 8}, 2, c);
        }
    } else if (a == SL_OPEN_FORGET || a == SL_CONFIRM_FORGET) {
        line(r, x + 4, y + 6, x + 26, y + 6, c);
        line(r, x + 11, y + 2, x + 19, y + 2, c);
        line(r, x + 7, y + 10, x + 9, y + 26, c);
        line(r, x + 23, y + 10, x + 21, y + 26, c);
        line(r, x + 9, y + 26, x + 21, y + 26, c);
    } else if (a == SL_OPEN_DISCONNECT || a == SL_CONFIRM_STOP || a == SL_CONFIRM_EXIT) {
        line(r, x + 14, y + 2, x + 14, y + 15, c);
        for (int i = 0; i < 25; ++i) {
            float u = (50 + i * 260.f / 25) * 3.14159265f / 180;
            float v = (50 + (i + 1) * 260.f / 25) * 3.14159265f / 180;
            line(r, x + 14 + 11 * sinf(u), y + 15 - 11 * cosf(u), x + 14 + 11 * sinf(v),
                 y + 15 - 11 * cosf(v), c);
        }
    } else if (a == SL_SOUND) {
        line(r, x + 3, y + 10, x + 9, y + 10, c);
        line(r, x + 3, y + 18, x + 9, y + 18, c);
        line(r, x + 3, y + 10, x + 3, y + 18, c);
        line(r, x + 9, y + 10, x + 16, y + 4, c);
        line(r, x + 9, y + 18, x + 16, y + 24, c);
        line(r, x + 16, y + 4, x + 16, y + 24, c);
        line(r, x + 23, y + 8, x + 27, y + 14, c);
        line(r, x + 27, y + 14, x + 23, y + 20, c);
    } else if (a == SL_OPEN_LANGUAGE) {
        for (int i = 0; i < 32; ++i) {
            float u = i * 6.2831853f / 32, v = (i + 1) * 6.2831853f / 32;
            line(r, x + 14 + 12 * cosf(u), y + 14 + 12 * sinf(u), x + 14 + 12 * cosf(v),
                 y + 14 + 12 * sinf(v), c);
            line(r, x + 14 + 6 * cosf(u), y + 14 + 12 * sinf(u), x + 14 + 6 * cosf(v),
                 y + 14 + 12 * sinf(v), c);
        }
        line(r, x + 2, y + 14, x + 26, y + 14, c);
    } else if (a == SL_OPEN_QUALITY || a == SL_OPEN_MANUAL) {
        monitor(r, x + 1, y + 3, 28, c);
    } else {
        rounded(r, (SDL_Rect){x + 2, y + 2, 26, 26}, 13, c);
        line(r, x + 14, y + 7, x + 14, y + 9, bg);
        line(r, x + 14, y + 13, x + 14, y + 22, bg);
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
    r->base_ui = calloc(1, sizeof(*r->base_ui));
    r->overlay = SDL_CreateTexture(r->renderer, SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_TARGET,
                                   1280, 720);
    if (r->overlay)
        SDL_SetTextureBlendMode(r->overlay, SDL_BLENDMODE_BLEND);
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
    if (!r->base_ui || !r->fonts[0][0] || !r->fonts[1][0]) {
        sl_ui_renderer_destroy(r);
        return NULL;
    }
    SDL_SetRenderDrawBlendMode(r->renderer, SDL_BLENDMODE_BLEND);
    return r;
}
/* Precompute a small separable blur once per downloaded image. No readback,
 * allocation or filtering is needed during the launch animation. */
static SDL_Texture *blurred_cover(sl_ui_renderer *r, const sl_artwork_image *image) {
    int w = 192, h = (int)(192.f * image->height / image->width);
    if (h < 1)
        h = 1;
    if (h > 192)
        h = 192;
    unsigned char *pixels = malloc((size_t)w * h * 8);
    if (!pixels)
        return NULL;
    unsigned char *temp = pixels + w * h * 4;
    for (int y = 0; y < h; ++y)
        for (int x = 0; x < w; ++x)
            memcpy(pixels + (y * w + x) * 4,
                   image->pixels +
                       ((y * image->height / h) * image->width + x * image->width / w) * 4,
                   4);
    for (int pass = 0; pass < 2; ++pass) {
        for (int y = 0; y < h; ++y)
            for (int x = 0; x < w; ++x)
                for (int c = 0; c < 4; ++c) {
                    unsigned sum = 0;
                    for (int k = -1; k <= 1; ++k) {
                        int sx = x, sy = y;
                        if (pass % 2)
                            sy = y + k;
                        else
                            sx = x + k;
                        if (sx < 0)
                            sx = 0;
                        if (sx >= w)
                            sx = w - 1;
                        if (sy < 0)
                            sy = 0;
                        if (sy >= h)
                            sy = h - 1;
                        sum += pixels[(sy * w + sx) * 4 + c];
                    }
                    temp[(y * w + x) * 4 + c] = sum / 3;
                }
        memcpy(pixels, temp, (size_t)w * h * 4);
    }
    SDL_Texture *texture =
        SDL_CreateTexture(r->renderer, SDL_PIXELFORMAT_RGBA32, SDL_TEXTUREACCESS_STATIC, w, h);
    if (texture) {
        SDL_UpdateTexture(texture, NULL, pixels, w * 4);
        SDL_SetTextureBlendMode(texture, SDL_BLENDMODE_BLEND);
        SDL_SetTextureScaleMode(texture, SDL_ScaleModeLinear);
    }
    free(pixels);
    return texture;
}
static bool launch_background(sl_ui_renderer *r, const sl_ui_model *m) {
    bool handoff = m->page == SL_STREAM && m->now >= m->stream_started_at &&
                   m->now - m->stream_started_at < 180;
    if ((!handoff && m->page != SL_CONNECTING) || !m->intent.game_id)
        return false;
    int index = -1;
    for (int i = 0; i < 8; ++i)
        if (r->covers[i].id == m->intent.game_id && r->covers[i].texture)
            index = i;
    if (index < 0)
        return false;
    r->covers[index].used = ++r->tick;
    float t = fminf(1.f, (m->now >= m->launch_at ? m->now - m->launch_at : 0) / 420.f);
    /* Strong initial acceleration and a short settle, without spring overshoot. */
    float p = handoff ? 1.f : 1.f - powf(1.f - t, 4.f);
    float alpha = handoff ? 1.f - (m->now - m->stream_started_at) / 180.f : 1.f;
    int iw = r->covers[index].w, ih = r->covers[index].h;
    const sl_control *c = &m->launch_card;
    float start_scale = c->w ? fminf((c->w - 16.f) / iw, 198.f / ih) : 0.f;
    float end_scale = fmaxf(1280.f / iw, 720.f / ih);
    float scale = start_scale + (end_scale - start_scale) * p;
    float cx = c->w ? c->x + c->w / 2.f : 640.f;
    float cy = c->w ? c->y + 8.f + 99.f : 360.f;
    cx += (640.f - cx) * p;
    cy += (360.f - cy) * p;
    SDL_FRect dest = {cx - iw * scale / 2, cy - ih * scale / 2, iw * scale, ih * scale};
    {
        SDL_SetTextureAlphaMod(r->covers[index].texture, (Uint8)(255 * alpha));
        SDL_RenderCopyF(r->renderer, r->covers[index].texture, NULL, &dest);
    }
    if (r->covers[index].blurred) {
        SDL_SetTextureAlphaMod(r->covers[index].blurred, (Uint8)(90 * p * alpha));
        SDL_RenderCopyF(r->renderer, r->covers[index].blurred, NULL, &dest);
    }
    rect(r->renderer, (SDL_Rect){0, 0, 1280, 720},
         (SDL_Color){9, 12, 20, (Uint8)(120 * p * alpha)});
    return true;
}
static void draw_cover(sl_ui_renderer *r, uint64_t id, SDL_Rect box, uint64_t now) {
    if (!r->artwork || !sl_artwork_appid(id))
        return;
    int index = -1;
    for (int i = 0; i < 8; ++i)
        if (r->covers[i].id == id) {
            index = i;
            break;
        }
    if (index < 0) {
        sl_artwork_request(r->artwork, id);
        sl_artwork_image image;
        if (!sl_artwork_take(r->artwork, id, &image))
            return;
        index = 0;
        for (int i = 1; i < 8; ++i)
            if (r->covers[i].used < r->covers[index].used)
                index = i;
        SDL_DestroyTexture(r->covers[index].texture);
        SDL_DestroyTexture(r->covers[index].blurred);
        r->covers[index].blurred = blurred_cover(r, &image);
        r->covers[index].texture =
            SDL_CreateTexture(r->renderer, SDL_PIXELFORMAT_RGBA32, SDL_TEXTUREACCESS_STATIC,
                              image.width, image.height);
        if (r->covers[index].texture) {
            SDL_UpdateTexture(r->covers[index].texture, NULL, image.pixels, image.width * 4);
            SDL_SetTextureBlendMode(r->covers[index].texture, SDL_BLENDMODE_BLEND);
        }
        r->covers[index].w = image.width;
        r->covers[index].h = image.height;
        free(image.pixels);
        r->covers[index].id = id;
        r->covers[index].ready_at = now;
    }
    r->covers[index].used = ++r->tick;
    if (!r->covers[index].texture)
        return;
    /* Contain the complete header artwork; never crop the game's logo. */
    float scale = fminf((float)box.w / r->covers[index].w, (float)box.h / r->covers[index].h);
    int w = (int)(r->covers[index].w * scale), h = (int)(r->covers[index].h * scale);
    SDL_Rect target = {box.x + (box.w - w) / 2, box.y + (box.h - h) / 2, w, h};
    Uint8 alpha = (Uint8)(255.f * fminf(1.f, (float)(now - r->covers[index].ready_at) / 180.f));
    SDL_SetTextureAlphaMod(r->covers[index].texture, alpha);
    SDL_RenderCopy(r->renderer, r->covers[index].texture, NULL, &target);
}
static void draw_scene(sl_ui_renderer *r, const sl_ui_model *m, const sl_debug_snapshot *d,
                       bool focused_scene) {
    const sl_layout *l = &m->layout;
    r->text_alpha = 1.f;
    SDL_Texture *previous_target = SDL_GetRenderTarget(r->renderer);
    SDL_Rect previous_viewport;
    SDL_RenderGetViewport(r->renderer, &previous_viewport);
    bool layer = false;
    if (!l->fullscreen && !l->dialog) {
        if (r->backdrop)
            SDL_RenderCopy(r->renderer, r->backdrop, NULL, NULL);
        else
            rect(r->renderer, (SDL_Rect){0, 0, 1280, 720}, bg);
        launch_background(r, m);
    } else if (m->page == SL_STREAM) {
        launch_background(r, m);
    }
    if (l->dialog) {
        rect(r->renderer, (SDL_Rect){0, 0, 1280, 720},
             (SDL_Color){0, 0, 0, (Uint8)(130 * l->opacity)});
        layer = r->overlay && SDL_SetRenderTarget(r->renderer, r->overlay) == 0;
        if (layer) {
            SDL_SetRenderDrawColor(r->renderer, 0, 0, 0, 0);
            SDL_RenderClear(r->renderer);
        } else {
            SDL_Rect viewport = {l->offset_x, l->offset_y, 1280, 720};
            SDL_RenderSetViewport(r->renderer, &viewport);
            r->text_alpha = l->opacity;
        }
        SDL_Rect box = {l->panel_x, l->panel_y, l->panel_w, l->panel_h};
        if (l->drawer) {
            rect(r->renderer, box, panel);
            rect(r->renderer, (SDL_Rect){box.x, 0, 1, 720}, (SDL_Color){77, 82, 94, 150});
            rect(r->renderer, (SDL_Rect){784, 139, 456, 1}, (SDL_Color){59, 63, 73, 255});
            draw_text(r, sl_tr(SL_T_BRAND), 784, 29, 440, 42, 24, muted);
        } else {
            for (int i = 20; i > 0; i -= 2)
                rounded(r->renderer,
                        (SDL_Rect){box.x - i, box.y - i + 8, box.w + i * 2, box.h + i * 2}, 16 + i,
                        (SDL_Color){0, 0, 0, 6});
            rounded(r->renderer, (SDL_Rect){box.x - 1, box.y - 1, box.w + 2, box.h + 2}, 17,
                    (SDL_Color){73, 77, 86, 255});
            rounded(r->renderer, box, 16, panel);
        }
    }
    if (l->title[0]) {
        if (!l->dialog) {
            draw_text(r, sl_tr(SL_T_BRAND), 52, centered_y(r, sl_tr(SL_T_BRAND), 28, 18, 44, 220),
                      220, 64, 28, fg);
            draw_text(r, sl_tr(SL_T_PROJECT_URL), 276,
                      centered_y(r, sl_tr(SL_T_PROJECT_URL), 24, 18, 44, 780), 780, 64, 24, muted);
            char version[64];
            snprintf(version, sizeof(version), sl_tr(SL_T_VERSION), NSL_APP_VERSION);
            int w = text_width(r, version, 24) + 32;
            rounded(r->renderer, (SDL_Rect){1228 - w, 23, w, 34}, 10, (SDL_Color){38, 53, 68, 255});
            draw_text(r, version, 1244 - w, centered_y(r, version, 24, 23, 34, w), w, 48, 24,
                      muted);
            rect(r->renderer, (SDL_Rect){52, 76, 1176, 1}, (SDL_Color){78, 103, 124, 60});
        } else {
            int x = l->panel_x + 40, y = l->panel_y + (l->drawer ? 78 : 36);
            draw_text(r, l->title, x, y, l->panel_w - 80, 68, l->drawer ? 36 : 40, fg);
        }
    }
    if (m->page == SL_HOME && !m->layout.dialog) {
        const sl_host_registry *hosts = &m->store.registry;
        const sl_host *host = hosts->selected >= 0 && hosts->selected < hosts->count
                                  ? &hosts->hosts[hosts->selected]
                                  : NULL;
        if (!host || !host->paired || !host->games[0].id) {
            SDL_Color state = !host ? accent : host->paired ? green : amber;
            rounded(r->renderer, (SDL_Rect){588, 190, 104, 78}, 22, mix(bg, state, .13f));
            monitor(r->renderer, 615, 208, 50, state);
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
        int x = t->x, width = l->dialog ? l->panel_x + l->panel_w - 40 - x : 1216 - x;
        if (t->center) {
            int measured = text_width(r, t->text, t->size);
            if (measured < 1152) {
                x = (1280 - measured) / 2;
                width = measured + 2;
            }
        }
        if (m->page == SL_PAIRING && t->size == 72 && m->pairing_code[0]) {
            for (int digit = 0; digit < 4; ++digit) {
                int dx = 430 + digit * 108;
                rounded(r->renderer, (SDL_Rect){dx, 322, 96, 104}, 12, mix(panel, amber, .13f));
                char value[] = {m->pairing_code[digit], 0};
                draw_text(r, value, dx + (96 - text_width(r, value, 72)) / 2,
                          centered_y(r, value, 72, 322, 104, 96), 96, 114, 72, amber);
            }
        } else if (!strcmp(t->text, sl_tr(SL_T_CONFIRM_KEY))) {
            badge(r, "A", x, 647, muted);
            draw_text(r, sl_tr(SL_T_CONFIRM), x + 48,
                      centered_y(r, sl_tr(SL_T_CONFIRM), 26, 632, 64, width - 48), width - 48, 70,
                      26, fg);
        } else
            draw_text(r, t->text, x, t->y, width, t->size * 2 + 22, t->size, fg);
    }
    for (int i = 0; i < l->count; ++i) {
        const sl_control *c = &l->controls[i];
        SDL_Rect box = {c->x, c->y, c->w, c->h};
        bool card = c->action == SL_RECENT;
        SDL_Rect viewport = {40, SL_CARD_Y - 8, 1200, SL_CARD_HEIGHT + 16}, clip;
        if (card) {
            if (!SDL_IntersectRect(&box, &viewport, &clip))
                continue;
            SDL_RenderSetClipRect(r->renderer, &clip);
        }
        bool tab = c->action == SL_SELECT_HOST;
        bool footer = c->label[0] && c->label[1] == ' ' && c->label[2] == ' ';
        bool shoulder = c->action == SL_PREV_HOST || c->action == SL_NEXT_HOST;
        bool focused = focused_scene && c->id == m->focus;
        bool menu_row = l->drawer && !footer;
        SDL_Color role = action_color(c->action);
        if (c->action == SL_START &&
            !m->store.registry
                 .hosts[m->store.registry.selected >= 0 ? m->store.registry.selected : 0]
                 .paired)
            role = amber;
        bool plain =
            tab || (footer && !c->primary) || shoulder || (c->action == SL_START && !c->primary);
        SDL_Color ink = focused || (c->primary && !tab) ? bg : fg;
        if (l->compact) {
            /* White always means the explicitly labelled A action. */
            ink = c->primary ? bg : fg;
            rounded(r->renderer, box, 9, c->primary ? fg : (SDL_Color){43, 47, 57, 255});
        } else if (card) {
            ink = fg;
            rounded(r->renderer, box, 14, focused ? (SDL_Color){52, 62, 78, 255} : panel);
        } else if (menu_row) {
            if (focused)
                rounded(r->renderer, box, 8, fg);
            if (c->action == SL_SET_QUALITY || c->action == SL_SET_LANGUAGE) {
                int x = box.x + 23, y = box.y + (box.h - 26) / 2;
                SDL_Color surface = focused ? fg : panel;
                SDL_Color ring = focused ? bg : muted;
                rounded(r->renderer, (SDL_Rect){x, y, 26, 26}, 13, ring);
                rounded(r->renderer, (SDL_Rect){x + 2, y + 2, 22, 22}, 11, surface);
                if (c->arg == (c->action == SL_SET_LANGUAGE ? (int)sl_i18n_language()
                                                            : (int)m->store.quality))
                    rounded(r->renderer, (SDL_Rect){x + 6, y + 6, 14, 14}, 7, focused ? bg : green);
            } else {
                SDL_Color tile = mix(panel, role, .16f);
                rounded(r->renderer, (SDL_Rect){box.x + 14, box.y + 14, 44, 44}, 10, tile);
                action_icon(r->renderer, c->action, box.x + 21, box.y + 21, role);
            }
        } else if (!plain || focused) {
            SDL_Color fill = focused              ? fg
                             : c->primary && !tab ? role
                                                  : (SDL_Color){43, 47, 57, 255};
            if (c->primary && !tab)
                fill = focused ? mix(role, fg, .18f) : role;
            rounded(r->renderer, box, c->action == SL_RECENT ? 14 : 9, fill);
        }
        if (tab && c->primary) {
            rounded(r->renderer, (SDL_Rect){c->x + 28, c->y + c->h - 4, c->w - 56, 4}, 2, accent);
            ink = focused ? bg : accent;
        }
        int size = c->action == SL_RECENT ? 30 : footer ? 26 : 30;
        const char *label = c->action == SL_SOUND ? sl_tr(SL_T_SOUND)
                            : footer              ? c->label + 3
                                                  : c->label;
        int x = c->x + (menu_row ? 78 : 24), width = c->w - (menu_row ? 110 : 48);
        bool centered = l->compact || tab || c->action == SL_START || c->action == SL_DIGIT ||
                        c->action == SL_SUBMIT || c->action == SL_ERASE || shoulder || footer;
        if (tab) {
            const sl_host *host = &m->store.registry.hosts[c->arg];
            SDL_Color status = !sl_host_online(host, m->now) ? muted : host->paired ? green : amber;
            rounded(r->renderer, (SDL_Rect){box.x + 18, box.y + (box.h - 12) / 2, 12, 12}, 6,
                    status);
            x = box.x + 44;
            width = box.w - 60;
        }
        int measured = text_width(r, label, size);
        if (footer) {
            int group = measured + 48;
            x = c->x + (c->w - group) / 2;
            char key[2] = {c->label[0], 0};
            badge(r, key, x, c->y + (c->h - 34) / 2, c->primary || focused ? bg : muted);
            x += 48;
            width = measured + 2;
        } else if (shoulder) {
            width = c->w - 8;
            rounded(r->renderer, (SDL_Rect){box.x + 8, box.y + 20, box.w - 16, 32}, 9, muted);
            ink = bg;
            x = c->x + (c->w - measured) / 2;
        } else if (centered && !tab && measured < width) {
            x = c->x + (c->w - measured) / 2;
            width = measured + 2;
        }
        int y = centered_y(r, label, size, c->y, c->h, width);
        if (c->action == SL_RECENT) {
            SDL_Color game_color = c->arg % 2 ? amber : violet;
            SDL_Rect art = {box.x + 8, box.y + 8, box.w - 16, 198};
            rounded(r->renderer, art, 10, mix(panel, game_color, .16f));
            play_icon(r->renderer, box.x + box.w / 2 - 10, box.y + 96, 28, game_color);
            int selected = m->store.registry.selected;
            if (selected >= 0 && selected < m->store.registry.count && c->arg < SL_RECENT_LIMIT)
                draw_cover(r, m->store.registry.hosts[selected].games[c->arg].id, art, m->now);
            if (selected >= 0 && selected < m->store.registry.count && c->arg < SL_RECENT_LIMIT)
                label =
                    localized_title(r, m->store.registry.hosts[selected].games[c->arg].id, label);
            card_title(r, label, (SDL_Rect){box.x + 24, box.y + box.h - 62, box.w - 48, 54},
                       viewport, focused, m);
            continue;
        } else if (!centered && !footer) {
            width -= 28;
            if (c->action == SL_SOUND) {
                SDL_Color track = m->store.sound ? green : muted;
                int tx = box.x + box.w - 74, ty = box.y + (box.h - 28) / 2;
                rounded(r->renderer, (SDL_Rect){tx, ty, 50, 28}, 14, track);
                rounded(r->renderer, (SDL_Rect){tx + (m->store.sound ? 25 : 3), ty + 3, 22, 22}, 11,
                        bg);
            } else if (c->action != SL_BACK && c->action != SL_SET_QUALITY &&
                       c->action != SL_SET_LANGUAGE)
                chevron(r->renderer, box.x + box.w - 35, box.y + box.h / 2, focused ? bg : muted);
        }
        SDL_RenderSetClipRect(r->renderer, card ? &clip : &box);
        draw_text(r, label, x, y, width, c->y + c->h - 8 - y, size, ink);
        SDL_RenderSetClipRect(r->renderer, NULL);
    }
    if (focused_scene && r->focus_valid && m->page != SL_STREAM && !l->dialog) {
        SDL_FRect f = r->focus_box;
        SDL_SetRenderDrawColor(r->renderer, accent.r, accent.g, accent.b, 210);
        /* Only the focus indicator moves; control layout and hit testing stay fixed. */
        SDL_Rect b = {(int)f.x - 3, (int)f.y - 3, (int)f.w + 6, (int)f.h + 6};
        SDL_Rect viewport = {40, SL_CARD_Y - 8, 1200, SL_CARD_HEIGHT + 16};
        if (m->page == SL_HOME)
            SDL_RenderSetClipRect(r->renderer, &viewport);
        outline(r, b);
        SDL_RenderSetClipRect(r->renderer, NULL);
    }

    if (l->dialog) {
        if (layer) {
            SDL_SetRenderTarget(r->renderer, previous_target);
            SDL_RenderSetViewport(r->renderer, &previous_viewport);
            SDL_SetTextureAlphaMod(r->overlay, l->drawer ? 255 : (Uint8)(255 * l->opacity));
            SDL_Rect destination = {l->offset_x, l->offset_y, 1280, 720};
            SDL_RenderCopy(r->renderer, r->overlay, NULL, &destination);
        } else
            SDL_RenderSetViewport(r->renderer, &previous_viewport);
        r->text_alpha = 1.f;
    }

    if (m->page == SL_STREAM && m->now >= m->stream_started_at) {
        uint64_t elapsed = m->now - m->stream_started_at;
        if (elapsed < 4200) {
            Uint8 alpha = elapsed < 2800 ? 255 : (Uint8)((4200 - elapsed) * 255 / 1400);
            const char *before = sl_tr(SL_T_HOLD_TOGETHER), *after = sl_tr(SL_T_OPEN_MENU);
            int before_w = text_width(r, before, 26), after_w = text_width(r, after, 26);
            int total = before_w + after_w + 96 + 32 + 48;
            int left = (1280 - total) / 2;
            rounded(r->renderer, (SDL_Rect){left, 592, total, 64}, 18,
                    (SDL_Color){17, 24, 35, (Uint8)(alpha * 220 / 255)});
            SDL_Color ink = fg;
            ink.a = alpha;
            int x = left + 24;
            draw_text(r, before, x, centered_y(r, before, 26, 592, 64, before_w + 2), before_w + 2,
                      70, 26, ink);
            x += before_w + 16;
            badge(r, "−", x, 607, ink);
            badge(r, "+", x + 46, 607, ink);
            x += 96 + 16;
            draw_text(r, after, x, centered_y(r, after, 26, 592, 64, after_w + 2), after_w + 2, 70,
                      26, ink);
        }
    }

#if NSL_DIAGNOSTICS
    if (m->debug && m->streaming && m->page == SL_STREAM) {
        rect(r->renderer, (SDL_Rect){24, 24, 640, 320}, panel);
        draw_text(r, d->title[0] ? d->title : sl_tr(SL_T_DIAGNOSTICS), 44, 42, 600, 38, 24, muted);
        const char *names[] = {sl_tr(SL_T_PRESENTATION),  sl_tr(SL_T_LOCAL_VIDEO),
                               sl_tr(SL_T_DECODE_UPLOAD), sl_tr(SL_T_AUDIO_BUFFER),
                               sl_tr(SL_T_HID_QUEUE),     sl_tr(SL_T_MAX_ACK)};
        for (int i = 0; i < 6; ++i) {
            draw_text(r, names[i], 44, 90 + i * 36, 310, 34, 24, fg);
            draw_text(r, d->values[i][0] ? d->values[i] : "—", 370, 90 + i * 36, 274, 34, 24, fg);
        }
        if (m->now > d->sampled_at + 3000)
            draw_text(r, sl_tr(SL_T_STALE), 44, 304, 400, 32, 24, muted);
    }
#else
    (void)d;
#endif
}
void sl_ui_renderer_set_artwork(sl_ui_renderer *r, sl_artwork *artwork) {
    r->artwork = artwork;
}
void sl_ui_renderer_draw(sl_ui_renderer *r, const sl_ui_model *m, const sl_debug_snapshot *d) {
    animate_focus(r, m);
    if (m->layout.dialog) {
        *r->base_ui = *m;
        r->base_ui->leaving = false;
        r->base_ui->entered_at = 0;
        if (!m->streaming) {
            r->base_ui->page = SL_HOME;
            sl_ui_layout(r->base_ui);
            draw_scene(r, r->base_ui, d, false);
        }
        /* A confirmation keeps the menu it belongs to underneath it. */
        if (m->depth) {
            r->base_ui->page = m->stack[m->depth - 1];
            sl_ui_layout(r->base_ui);
            if (r->base_ui->layout.drawer) {
                r->base_ui->layout.opacity = 1.f;
                r->base_ui->layout.offset_x = 0;
                draw_scene(r, r->base_ui, d, false);
            }
        }
    }
    draw_scene(r, m, d, true);
}
void sl_ui_renderer_destroy(sl_ui_renderer *r) {
    if (!r)
        return;
    for (int i = 0; i < 8; ++i) {
        SDL_DestroyTexture(r->covers[i].texture);
        SDL_DestroyTexture(r->covers[i].blurred);
    }
    SDL_DestroyTexture(r->overlay);
    free(r->base_ui);
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
