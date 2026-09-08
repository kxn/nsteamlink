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
    char pattern[1024], filename[128], prefix[64];
    if (format < 0 || header < 0 || !ascii_string(s, &tokens[format], pattern, sizeof(pattern)) ||
        !ascii_string(s, &tokens[header], filename, sizeof(filename)))
        return false;
    snprintf(prefix, sizeof(prefix), "steam/apps/%u/", appid);
    if (strncmp(pattern, prefix, strlen(prefix)) || strstr(pattern, ".."))
        return false;
    if (strspn(filename, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") !=
            strlen(filename) ||
        strstr(filename, ".."))
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
