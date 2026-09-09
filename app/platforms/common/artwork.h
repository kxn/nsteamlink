#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct sl_artwork sl_artwork;
typedef struct sl_artwork_image {
    unsigned char *pixels;
    int width, height;
} sl_artwork_image;
/* Test seam: production passes NULL and uses verified HTTPS. Returned data is malloc-owned. */
typedef bool (*sl_artwork_fetch_fn)(const char *url, size_t limit, unsigned char **data,
                                    size_t *size, void *context);
sl_artwork *sl_artwork_create(const char *data_dir, sl_artwork_fetch_fn fetch, void *context);
void sl_artwork_pause(sl_artwork *, bool paused);
void sl_artwork_request(sl_artwork *, uint64_t gameid);
bool sl_artwork_take(sl_artwork *, uint64_t gameid, sl_artwork_image *out);
void sl_artwork_destroy(sl_artwork *);
bool sl_artwork_appid(uint64_t gameid);
bool sl_artwork_url(const unsigned char *json, size_t size, uint32_t appid, char *url,
                    size_t capacity);
bool sl_artwork_decode(const unsigned char *jpeg, size_t size, sl_artwork_image *out);

/* Non-blocking lookup/queue, keyed by app and resolved UI language. */
bool sl_artwork_title(sl_artwork *, uint64_t gameid, int language, char *out, size_t capacity);
bool sl_artwork_name(const unsigned char *json, size_t size, uint32_t appid, char *out,
                     size_t capacity);
