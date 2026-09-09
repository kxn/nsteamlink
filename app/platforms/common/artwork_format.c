#include "artwork.h"
#include <math.h>
#include <setjmp.h>
#include <stdio.h>

#include <jpeglib.h>
#include <stdlib.h>
#include <string.h>
#define JSMN_STATIC
#define JSMN_STRICT
#include "jsmn.h"

bool sl_artwork_appid(uint64_t id) {
    /* Steam CGameID: 24-bit appid, 8-bit type, 32-bit mod/shortcut id. */
    return id > 0 && id <= 0xffffff;
}
static bool equal(const char *s, jsmntok_t *t, const char *value) {
    return (size_t)(t->end - t->start) == strlen(value) &&
           !memcmp(s + t->start, value, strlen(value));
}
static int member(const char *s, jsmntok_t *t, int count, int object, const char *key) {
    if (object < 0 || t[object].type != JSMN_OBJECT)
        return -1;
    for (int i = object + 1; i + 1 < count && t[i].start < t[object].end;) {
        int value = i + 1;
        if (t[i].type != JSMN_STRING)
            return -1;
        if (equal(s, &t[i], key))
            return value;
        int end = t[value].end;
        i = value + 1;
        while (i < count && t[i].start < end)
            ++i;
    }
    return -1;
}
static bool ascii_string(const char *s, jsmntok_t *t, char *out, size_t cap) {
    if (t->type != JSMN_STRING)
        return false;
    size_t n = 0;
    for (int i = t->start; i < t->end; ++i) {
        unsigned char c = s[i];
        if (c == '\\') {
            if (++i >= t->end || s[i] != '/')
                return false;
            c = '/';
        }
        if (c < 33 || c > 126 || n + 1 >= cap)
            return false;
        out[n++] = c;
    }
    out[n] = 0;
    return n > 0;
}
bool sl_artwork_url(const unsigned char *data, size_t size, uint32_t appid, char *url, size_t cap) {
    if (!data || !size || size > 65536 || !sl_artwork_appid(appid))
        return false;
    const char *s = (const char *)data;
    jsmntok_t tokens[512];
    jsmn_parser p;
    jsmn_init(&p);
    int n = jsmn_parse(&p, s, size, tokens, 512);
    if (n <= 0)
        return false;
    int response = member(s, tokens, n, 0, "response");
    int items = member(s, tokens, n, response, "store_items");
    if (items < 0 || tokens[items].type != JSMN_ARRAY || tokens[items].size != 1)
        return false;
    int item = items + 1;
    int success = member(s, tokens, n, item, "success");
    int id = member(s, tokens, n, item, "appid");
    char number[16];
    snprintf(number, sizeof(number), "%u", appid);
    if (success < 0 || id < 0 || tokens[id].type != JSMN_PRIMITIVE ||
        !equal(s, &tokens[success], "1") || !equal(s, &tokens[id], number))
        return false;
    int assets = member(s, tokens, n, item, "assets_without_overrides");
    int format = member(s, tokens, n, assets, "asset_url_format");
    int header = member(s, tokens, n, assets, "header");
    char pattern[1024], filename[512], prefix[64];
    if (format < 0 || header < 0 || !ascii_string(s, &tokens[format], pattern, sizeof(pattern)) ||
        !ascii_string(s, &tokens[header], filename, sizeof(filename)))
        return false;
    snprintf(prefix, sizeof(prefix), "steam/apps/%u/", appid);
    if (strncmp(pattern, prefix, strlen(prefix)) || strstr(pattern, ".."))
        return false;
    /* Steam headers may live under a content-hash directory. Accept a relative
     * asset path while keeping the fixed CDN and app-specific root. */
    if (strspn(filename, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_/.-") !=
            strlen(filename) ||
        strstr(filename, "..") || filename[0] == '/' || filename[0] == '.' ||
        filename[strlen(filename) - 1] == '/' || strstr(filename, "//") || strstr(filename, "/./"))
        return false;
    char *slot = strstr(pattern, "${FILENAME}");
    if (!slot || strstr(slot + 11, "${FILENAME}"))
        return false;
    *slot = 0;
    int written = snprintf(url, cap, "https://shared.steamstatic.com/store_item_assets/%s%s%s",
                           pattern, filename, slot + 11);
    return written > 0 && (size_t)written < cap &&
           strspn(url, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/_.-?=&%") ==
               strlen(url);
}

typedef struct jpeg_work {
    struct jpeg_decompress_struct c;
    struct jpeg_error_mgr error;
    jmp_buf jump;
    unsigned char *rgb;
    bool created;
} jpeg_work;
static void jpeg_fail(j_common_ptr c) {
    jpeg_work *w = c->client_data;
    longjmp(w->jump, 1);
}
static void jpeg_quiet(j_common_ptr c) {
    (void)c;
}
bool sl_artwork_decode(const unsigned char *data, size_t size, sl_artwork_image *out) {
    memset(out, 0, sizeof(*out));
    if (!data || size < 4 || size > 1024 * 1024 || data[0] != 0xff || data[1] != 0xd8)
        return false;
    jpeg_work *w = calloc(1, sizeof(*w));
    if (!w)
        return false;
    w->c.err = jpeg_std_error(&w->error);
    w->error.error_exit = jpeg_fail;
    w->error.output_message = jpeg_quiet;
    w->c.client_data = w;
    if (setjmp(w->jump)) {
        if (w->created)
            jpeg_destroy_decompress(&w->c);
        free(w->rgb);
        free(w);
        return false;
    }
    jpeg_create_decompress(&w->c);
    w->created = true;
    jpeg_mem_src(&w->c, data, size);
    if (jpeg_read_header(&w->c, TRUE) != JPEG_HEADER_OK || !w->c.image_width ||
        !w->c.image_height || w->c.image_width > 2048 || w->c.image_height > 2048 ||
        w->c.image_width * w->c.image_height > 2097152)
        jpeg_fail((j_common_ptr)&w->c);
    w->c.out_color_space = JCS_RGB;
    w->c.scale_num = 1;
    w->c.scale_denom = 1;
    while (w->c.image_width / w->c.scale_denom > 1024 && w->c.scale_denom < 8)
        w->c.scale_denom *= 2;
    jpeg_start_decompress(&w->c);
    size_t row = w->c.output_width * 3;
    w->rgb = malloc(row * w->c.output_height);
    if (!w->rgb)
        jpeg_fail((j_common_ptr)&w->c);
    while (w->c.output_scanline < w->c.output_height) {
        JSAMPROW line = w->rgb + row * w->c.output_scanline;
        jpeg_read_scanlines(&w->c, &line, 1);
    }
    int width = w->c.output_width, height = w->c.output_height;
    jpeg_finish_decompress(&w->c);
    if (w->error.num_warnings)
        jpeg_fail((j_common_ptr)&w->c);
    jpeg_destroy_decompress(&w->c);
    w->created = false;
    float scale = fminf(1.f, fminf(548.f / width, 256.f / height));
    out->width = (int)(width * scale);
    out->height = (int)(height * scale);
    if (!out->width || !out->height) {
        free(w->rgb);
        free(w);
        return false;
    }
    out->pixels = malloc((size_t)out->width * out->height * 4);
    if (out->pixels) {
        for (int y = 0; y < out->height; ++y)
            for (int x = 0; x < out->width; ++x) {
                size_t src =
                    ((size_t)(y * height / out->height) * width + x * width / out->width) * 3;
                size_t dst = ((size_t)y * out->width + x) * 4;
                memcpy(out->pixels + dst, w->rgb + src, 3);
                out->pixels[dst + 3] = 255;
            }
    }
    free(w->rgb);
    free(w);
    return out->pixels != NULL;
}

static int hex4(const char *s) {
    int v = 0;
    for (int i = 0; i < 4; ++i) {
        int c = s[i], d = c >= '0' && c <= '9'   ? c - '0'
                          : c >= 'a' && c <= 'f' ? c - 'a' + 10
                          : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                                 : -1;
        if (d < 0)
            return -1;
        v = v * 16 + d;
    }
    return v;
}
/* Decode JSON escapes and validate raw UTF-8. Never split a codepoint. */
static bool title_string(const char *s, const jsmntok_t *t, char *out, size_t cap) {
    if (t->type != JSMN_STRING || !cap)
        return false;
    size_t written = 0;
    for (int i = t->start; i < t->end;) {
        uint32_t cp = (unsigned char)s[i++];
        if (cp == '\\') {
            if (i >= t->end)
                return false;
            char esc = s[i++];
            if (esc == 'u') {
                if (i + 4 > t->end)
                    return false;
                int v = hex4(s + i);
                i += 4;
                if (v < 0)
                    return false;
                cp = v;
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    if (i + 6 > t->end || s[i] != '\\' || s[i + 1] != 'u')
                        return false;
                    v = hex4(s + i + 2);
                    i += 6;
                    if (v < 0xdc00 || v > 0xdfff)
                        return false;
                    cp = 0x10000 + ((cp - 0xd800) << 10) + v - 0xdc00;
                } else if (cp >= 0xdc00 && cp <= 0xdfff)
                    return false;
            } else if (esc == '"' || esc == '\\' || esc == '/')
                cp = esc;
            else if (esc == 'n' || esc == 'r' || esc == 't' || esc == 'b' || esc == 'f')
                cp = ' ';
            else
                return false;
        } else if (cp >= 0x80) {
            int count = cp >= 0xc2 && cp <= 0xdf   ? 1
                        : cp >= 0xe0 && cp <= 0xef ? 2
                        : cp >= 0xf0 && cp <= 0xf4 ? 3
                                                   : -1;
            if (count < 0 || i + count > t->end)
                return false;
            cp &= (1u << (6 - count)) - 1;
            for (int n = 0; n < count; ++n) {
                unsigned char c = s[i++];
                if ((c & 0xc0) != 0x80)
                    return false;
                cp = (cp << 6) | (c & 63);
            }
            if (cp < (count == 1   ? 0x80u
                      : count == 2 ? 0x800u
                                   : 0x10000u) ||
                cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
                return false;
        }
        if (cp < 32 || cp == 127)
            return false;
        unsigned char bytes[4];
        int n;
        if (cp < 0x80) {
            bytes[0] = cp;
            n = 1;
        } else if (cp < 0x800) {
            bytes[0] = 0xc0 | (cp >> 6);
            bytes[1] = 0x80 | (cp & 63);
            n = 2;
        } else if (cp < 0x10000) {
            bytes[0] = 0xe0 | (cp >> 12);
            bytes[1] = 0x80 | ((cp >> 6) & 63);
            bytes[2] = 0x80 | (cp & 63);
            n = 3;
        } else {
            bytes[0] = 0xf0 | (cp >> 18);
            bytes[1] = 0x80 | ((cp >> 12) & 63);
            bytes[2] = 0x80 | ((cp >> 6) & 63);
            bytes[3] = 0x80 | (cp & 63);
            n = 4;
        }
        if (written + n >= cap)
            return false;
        memcpy(out + written, bytes, n);
        written += n;
    }
    out[written] = 0;
    return written && strspn(out, " ") != written;
}
bool sl_artwork_name(const unsigned char *data, size_t size, uint32_t appid, char *out,
                     size_t cap) {
    if (!out || !cap)
        return false;
    out[0] = 0;
    if (!data || !size || size > 65536 || !sl_artwork_appid(appid))
        return false;
    const char *s = (const char *)data;
    jsmntok_t t[512];
    jsmn_parser parser;
    jsmn_init(&parser);
    int n = jsmn_parse(&parser, s, size, t, 512);
    if (n <= 0)
        return false;
    int response = member(s, t, n, 0, "response"), items = member(s, t, n, response, "store_items");
    if (items < 0 || t[items].type != JSMN_ARRAY || t[items].size != 1)
        return false;
    int item = items + 1, success = member(s, t, n, item, "success"),
        id = member(s, t, n, item, "appid"), name = member(s, t, n, item, "name");
    char number[16];
    snprintf(number, sizeof(number), "%u", appid);
    bool ok = success >= 0 && id >= 0 && name >= 0 && t[success].type == JSMN_PRIMITIVE &&
              t[id].type == JSMN_PRIMITIVE && equal(s, &t[success], "1") &&
              equal(s, &t[id], number) && title_string(s, &t[name], out, cap);
    if (!ok)
        out[0] = 0;
    return ok;
}
