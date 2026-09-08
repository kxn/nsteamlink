#include "artwork.h"
#include "platform/system.h"
#include <assert.h>
#include <dirent.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>

#include <jpeglib.h>
static const char response[] =
    "{\"response\":{\"store_items\":[{\"success\":1,\"appid\":413150,\"assets_without_overrides\":{"
    "\"asset_url_format\":\"steam/apps/413150/${FILENAME}?t=123\",\"header\":\"header.jpg\"}}]}}";
typedef struct fixture {
    unsigned char *jpeg;
    unsigned long size;
    atomic_int calls, failures;
    atomic_bool fail, hold, entered;
} fixture;
static void make_jpeg(fixture *f) {
    struct jpeg_compress_struct c = {0};
    struct jpeg_error_mgr error;
    c.err = jpeg_std_error(&error);
    jpeg_create_compress(&c);
    jpeg_mem_dest(&c, &f->jpeg, &f->size);
    c.image_width = 920;
    c.image_height = 430;
    c.input_components = 3;
    c.in_color_space = JCS_RGB;
    jpeg_set_defaults(&c);
    jpeg_start_compress(&c, TRUE);
    unsigned char row[920 * 3];
    for (int x = 0; x < 920; ++x) {
        row[3 * x] = x % 255;
        row[3 * x + 1] = 90;
        row[3 * x + 2] = 150;
    }
    while (c.next_scanline < c.image_height) {
        JSAMPROW p = row;
        jpeg_write_scanlines(&c, &p, 1);
    }
    jpeg_finish_compress(&c);
    jpeg_destroy_compress(&c);
}
static bool fetch(const char *url, size_t limit, unsigned char **out, size_t *size, void *ctx) {
    fixture *f = ctx;
    atomic_fetch_add(&f->calls, 1);
    atomic_store(&f->entered, true);
    while (atomic_load(&f->hold))
        usleep(1000);
    if (atomic_load(&f->fail))
        return false;
    if (atomic_load(&f->failures) > 0) {
        atomic_fetch_sub(&f->failures, 1);
        return false;
    }
    bool metadata = strstr(url, "api.steampowered.com/") != NULL;
    const void *data = metadata ? (const void *)response : f->jpeg;
    *size = metadata ? strlen(response) : f->size;
    assert(*size <= limit);
    *out = malloc(*size);
    assert(*out);
    memcpy(*out, data, *size);
    return true;
}
static sl_artwork_image wait_image(sl_artwork *a) {
    sl_artwork_image image = {0};
    for (int i = 0; i < 3000; ++i) {
        if (sl_artwork_take(a, 413150, &image))
            return image;
        usleep(1000);
    }
    assert(!"artwork timed out");
    return image;
}
static void *destroy(void *a) {
    sl_artwork_destroy(a);
    return NULL;
}
static void cache_limit(fixture *f) {
    char root[] = "/tmp/nsl-artwork-limit-XXXXXX", dir[256], path[600];
    assert(mkdtemp(root));
    snprintf(dir, sizeof(dir), "%s/artwork", root);
    assert(!mkdir(dir, 0700));
    for (int i = 0; i <= 40; ++i) {
        snprintf(path, sizeof(path), "%s/%d.jpg", dir, i ? 9000 + i : 413150);
        FILE *file = fopen(path, "wb");
        assert(file);
        assert(fwrite(f->jpeg, 1, f->size, file) == f->size);
        assert(!fclose(file));
        if (i) {
            struct utimbuf stamp = {.actime = i, .modtime = i};
            assert(!utime(path, &stamp));
        }
    }
    atomic_store(&f->fail, true);
    atomic_store(&f->calls, 0);
    sl_artwork *a = sl_artwork_create(root, fetch, f);
    assert(a);
    sl_artwork_request(a, 413150);
    sl_artwork_image image = wait_image(a);
    free(image.pixels);
    sl_artwork_destroy(a);
    assert(atomic_load(&f->calls) == 0);
    DIR *directory = opendir(dir);
    assert(directory);
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(directory))) {
        if (!strstr(entry->d_name, ".jpg"))
            continue;
        ++count;
        snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        assert(!unlink(path));
    }
    closedir(directory);
    assert(count == 32);
    assert(!rmdir(dir));
    assert(!rmdir(root));
}
static void asset_paths(void) {
    const char *paths[] = {"08a8d3df458f6b3ec9cf32d7faf2c87101598623/header.jpg",
                           "6912f19c43a95ff5fe514eedd35e68bf12335459/header.jpg",
                           "hash/header.jpg",
                           "hash\\/header.jpg",
                           "../header.jpg",
                           "hash/../header.jpg",
                           "/header.jpg",
                           "//elsewhere/header.jpg",
                           "https://elsewhere/header.jpg",
                           "hash//header.jpg",
                           "hash/./header.jpg",
                           "hash/",
                           "hash/%2e%2e/header.jpg",
                           "hash/header.jpg?x=1",
                           "hash/header.jpg#fragment",
                           "./header.jpg",
                           ""};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        unsigned id = i == 0 ? 3337210 : 1623730;
        char json[2048], url[1536], expected[1536];
        snprintf(json, sizeof(json),
                 "{\"response\":{\"store_items\":[{\"success\":1,\"appid\":%u,"
                 "\"assets_without_overrides\":{\"asset_url_format\":"
                 "\"steam/apps/%u/${FILENAME}?t=123\",\"header\":\"%s\"}}]}}",
                 id, id, paths[i]);
        bool accepted =
            sl_artwork_url((const unsigned char *)json, strlen(json), id, url, sizeof(url));
        assert(accepted == (i < 4));
        if (accepted) {
            snprintf(expected, sizeof(expected),
                     "https://shared.steamstatic.com/store_item_assets/steam/apps/%u/%s?t=123", id,
                     i == 3 ? "hash/header.jpg" : paths[i]);
            assert(!strcmp(url, expected));
            assert(!sl_artwork_url((const unsigned char *)json, strlen(json), id, url, 20));
        }
    }
}
int main(int argc, char **argv) {
    asset_paths();
    char url[1536];
    assert(sl_artwork_appid(413150));
    assert(!sl_artwork_appid(0));
    assert(!sl_artwork_appid(0x8000000002000000ULL));
    assert(!sl_artwork_appid(0x1000000));
    assert(sl_artwork_url((const unsigned char *)response, strlen(response), 413150, url,
                          sizeof(url)));
    assert(!strcmp(
        url,
        "https://shared.steamstatic.com/store_item_assets/steam/apps/413150/header.jpg?t=123"));
    assert(
        !sl_artwork_url((const unsigned char *)response, strlen(response), 570, url, sizeof(url)));
    for (size_t i = 0; i < strlen(response); ++i)
        assert(!sl_artwork_url((const unsigned char *)response, i, 413150, url, sizeof(url)));
    char bad[sizeof(response)];
    memcpy(bad, response, sizeof(response));
    memcpy(strstr(bad, "steam/apps"), "https://xx", 10);
    assert(!sl_artwork_url((const unsigned char *)bad, strlen(bad), 413150, url, sizeof(url)));
    fixture f = {0};
    make_jpeg(&f);
    sl_artwork_image image;
    assert(sl_artwork_decode(f.jpeg, f.size, &image));
    assert(image.width <= 548 && image.height <= 256);
    free(image.pixels);
    assert(!sl_artwork_decode(f.jpeg, f.size / 2, &image));
    char dir[] = "/tmp/nsl-artwork-XXXXXX";
    assert(mkdtemp(dir));
    sl_artwork *a = sl_artwork_create(dir, fetch, &f);
    assert(a);
    sl_artwork_pause(a, true);
    sl_artwork_request(a, 413150);
    usleep(20000);
    assert(atomic_load(&f.calls) == 0);
    sl_artwork_pause(a, false);
    for (int i = 0; i < 100; ++i)
        sl_artwork_request(a, 413150);
    image = wait_image(a);
    free(image.pixels);
    assert(atomic_load(&f.calls) == 2);
    sl_artwork_request(a, 0x8000000002000000ULL);
    usleep(20000);
    assert(atomic_load(&f.calls) == 2);
    sl_artwork_destroy(a);
    /* A separate run must read and decode the cache even with the network unavailable. */
    atomic_store(&f.fail, true);
    atomic_store(&f.calls, 0);
    a = sl_artwork_create(dir, fetch, &f);
    assert(a);
    sl_artwork_request(a, 413150);
    image = wait_image(a);
    free(image.pixels);
    assert(atomic_load(&f.calls) == 0);
    sl_artwork_destroy(a);
    char path[512];
    snprintf(path, sizeof(path), "%s/artwork/413150.jpg", dir);
    FILE *file = fopen(path, "wb");
    assert(file);
    fputs("broken", file);
    fclose(file);
    atomic_store(&f.fail, false);
    atomic_store(&f.calls, 0);
    a = sl_artwork_create(dir, fetch, &f);
    assert(a);
    sl_artwork_request(a, 413150);
    image = wait_image(a);
    free(image.pixels);
    assert(atomic_load(&f.calls) == 2);
    sl_artwork_destroy(a);
    unlink(path);
    /* A request cancelled by briefly opening a menu retries immediately on return. */
    atomic_store(&f.calls, 0);
    atomic_store(&f.failures, 1);
    atomic_store(&f.hold, true);
    atomic_store(&f.entered, false);
    a = sl_artwork_create(dir, fetch, &f);
    assert(a);
    sl_artwork_request(a, 413150);
    for (int i = 0; i < 1000 && !atomic_load(&f.entered); ++i)
        usleep(1000);
    assert(atomic_load(&f.entered));
    sl_artwork_pause(a, true);
    sl_artwork_pause(a, false);
    atomic_store(&f.hold, false);
    image = wait_image(a);
    free(image.pixels);
    assert(atomic_load(&f.calls) == 3);
    sl_artwork_destroy(a);
    unlink(path);
    /* Backoff prevents a draw loop from continuously retrying failed requests. */
    atomic_store(&f.fail, true);
    atomic_store(&f.calls, 0);
    a = sl_artwork_create(dir, fetch, &f);
    assert(a);
    for (int i = 0; i < 100; ++i) {
        sl_artwork_request(a, 413150);
        usleep(1000);
    }
    assert(atomic_load(&f.calls) == 1);
    sl_artwork_destroy(a);
    /* Destruction joins an in-flight worker before freeing its context. */
    atomic_store(&f.fail, false);
    atomic_store(&f.hold, true);
    atomic_store(&f.entered, false);
    a = sl_artwork_create(dir, fetch, &f);
    assert(a);
    sl_artwork_request(a, 413150);
    for (int i = 0; i < 1000 && !atomic_load(&f.entered); ++i)
        usleep(1000);
    assert(atomic_load(&f.entered));
    pthread_t t;
    assert(pthread_create(&t, NULL, destroy, a) == 0);
    usleep(10000);
    atomic_store(&f.hold, false);
    pthread_join(t, NULL);
    if (argc == 2 && !strcmp(argv[1], "--live")) {
        a = sl_artwork_create(dir, NULL, NULL);
        assert(a);
        const uint64_t ids[] = {413150, 3337210, 1623730};
        for (size_t game = 0; game < sizeof(ids) / sizeof(ids[0]); ++game) {
            sl_artwork_request(a, ids[game]);
            bool received = false;
            for (int i = 0; i < 20000; ++i) {
                if (sl_artwork_take(a, ids[game], &image)) {
                    free(image.pixels);
                    received = true;
                    break;
                }
                usleep(1000);
            }
            assert(received);
            printf("live artwork decoded: %llu\n", (unsigned long long)ids[game]);
            snprintf(path, sizeof(path), "%s/artwork/%llu.jpg", dir, (unsigned long long)ids[game]);
            unlink(path);
        }
        sl_artwork_destroy(a);
        puts("live Steam artwork fetched and decoded");
    }
    unlink(path);
    snprintf(path, sizeof(path), "%s/artwork", dir);
    rmdir(path);
    rmdir(dir);
    cache_limit(&f);
    free(f.jpeg);
    puts("artwork tests passed");
    return 0;
}
