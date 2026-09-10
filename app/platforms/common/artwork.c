#include "artwork.h"
#include "build_identity.h"
#include "platform/system.h"
#include "services/i18n.h"
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#define SLOT_COUNT  8
#define IMAGE_LIMIT (1024 * 1024)
#define RETRY_MS    60000

enum state { EMPTY, QUEUED, LOADING, READY, DELIVERED, FAILED };
typedef struct entry {
    uint64_t id, touched, retry;
    enum state state;
    sl_artwork_image image;
} entry;
typedef struct title_entry {
    uint64_t id, touched, retry;
    int language;
    enum state state;
    char name[512];
} title_entry;
struct sl_artwork {
    pthread_t worker;
    pthread_mutex_t lock;
    pthread_cond_t wake;
    atomic_bool stop, paused, finished;
    atomic_uint dns_handle, cancel_generation;
    bool curl_ready;
    char directory[768];
    entry entries[SLOT_COUNT];
    title_entry titles[16];
    sl_artwork_fetch_fn fetch;
    void *context;
};
typedef struct download {
    sl_artwork *owner;
    unsigned char *data;
    size_t size, limit;
} download;
static bool cancelled(sl_artwork *a) {
    return atomic_load(&a->stop) || atomic_load(&a->paused);
}
static size_t receive(char *data, size_t size, size_t count, void *ctx) {
    download *d = ctx;
    if (cancelled(d->owner) || (size && count > (d->limit - d->size) / size))
        return 0;
    size_t bytes = size * count;
    if (!bytes)
        return 0;
    unsigned char *next = realloc(d->data, d->size + bytes);
    if (!next)
        return 0;
    d->data = next;
    memcpy(d->data + d->size, data, bytes);
    d->size += bytes;
    return bytes;
}
static int progress(void *ctx, curl_off_t total, curl_off_t now, curl_off_t ut, curl_off_t un) {
    (void)total;
    (void)now;
    (void)ut;
    (void)un;
    return cancelled(ctx);
}
static bool fetch_https(const char *url, size_t limit, unsigned char **data, size_t *size,
                        void *ctx) {
    sl_artwork *a = ctx;
    *data = NULL;
    *size = 0;
    if (cancelled(a))
        return false;
    CURL *c = curl_easy_init();
    if (!c)
        return false;
    download d = {.owner = a, .limit = limit};
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, 3000L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, 8000L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    /* No redirects or cookies: both URLs have fixed HTTPS authorities. */
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "NSteamLink/" NSL_SEMANTIC_VERSION);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, receive);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &d);
    curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, progress);
    curl_easy_setopt(c, CURLOPT_XFERINFODATA, a);
    atomic_store(&a->dns_handle, sl_system_dns_begin());
    CURLcode result = cancelled(a) ? CURLE_ABORTED_BY_CALLBACK : curl_easy_perform(c);
    atomic_store(&a->dns_handle, 0);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);
    if (result != CURLE_OK || code != 200 || !d.size || cancelled(a)) {
        free(d.data);
        return false;
    }
    *data = d.data;
    *size = d.size;
    return true;
}
static void cache_path(sl_artwork *a, uint64_t id, char *path, size_t size) {
    snprintf(path, size, "%s/%u.jpg", a->directory, (unsigned)id);
}
static bool read_cache(const char *path, sl_artwork_image *image) {
    struct stat st;
    if (stat(path, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > IMAGE_LIMIT)
        return false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    unsigned char *data = malloc((size_t)st.st_size);
    bool ok = data && fread(data, 1, (size_t)st.st_size, f) == (size_t)st.st_size &&
              sl_artwork_decode(data, (size_t)st.st_size, image);
    fclose(f);
    free(data);
    if (ok)
        utime(path, NULL);
    else
        unlink(path);
    return ok;
}
/* Only this worker touches disk. Limit cache to 32 verified JPEG files (<=32 MiB). */
static void prune(sl_artwork *a) {
    for (;;) {
        DIR *dir = opendir(a->directory);
        if (!dir)
            return;
        unsigned count = 0;
        char oldest[900] = {0};
        time_t stamp = 0;
        struct dirent *ent;
        while ((ent = readdir(dir))) {
            unsigned id;
            int consumed = 0;
            if (sscanf(ent->d_name, "%u.jpg%n", &id, &consumed) != 1 || !consumed ||
                ent->d_name[consumed])
                continue;
            char path[900];
            struct stat st;
            cache_path(a, id, path, sizeof(path));
            if (stat(path, &st) || !S_ISREG(st.st_mode))
                continue;
            ++count;
            if (!oldest[0] || st.st_mtime < stamp) {
                snprintf(oldest, sizeof(oldest), "%s", path);
                stamp = st.st_mtime;
            }
        }
        closedir(dir);
        if (count <= 32 || !oldest[0] || unlink(oldest))
            return;
    }
}
static void save_cache(sl_artwork *a, const char *path, const unsigned char *data, size_t size) {
    char temporary[920];
    snprintf(temporary, sizeof(temporary), "%s.tmp", path);
    FILE *f = fopen(temporary, "wb");
    if (!f)
        return;
    bool ok = fwrite(data, 1, size, f) == size;
    if (fclose(f))
        ok = false;
    if (!ok || rename(temporary, path))
        unlink(temporary);
    else
        prune(a);
}
static void prune_titles(sl_artwork *a);
static bool load(sl_artwork *a, uint64_t id, sl_artwork_image *image) {
    char path[900];
    cache_path(a, id, path, sizeof(path));
    if (read_cache(path, image))
        return true;
    if (cancelled(a))
        return false;
    char request[768];
    snprintf(request, sizeof(request),
             "https://api.steampowered.com/IStoreBrowseService/GetItems/v1/?input_json="
             "%%7B%%22ids%%22:%%5B%%7B%%22appid%%22:%u%%7D%%5D,%%22context%%22:%%7B%%22language%%"
             "22:%%22english%%22,"
             "%%22country_code%%22:%%22US%%22%%7D,%%22data_request%%22:%%7B%%22include_assets_"
             "without_overrides%%22:true%%7D%%7D",
             (unsigned)id);
    unsigned char *data = NULL;
    size_t size = 0;
    char url[1536];
    bool ok = a->fetch(request, 65536, &data, &size, a->context) &&
              sl_artwork_url(data, size, (uint32_t)id, url, sizeof(url));
    /* Reuse the English metadata already fetched for a new cover. */
    char title[512], title_path[900];
    if (!cancelled(a) && sl_artwork_name(data, size, (uint32_t)id, title, sizeof(title))) {
        snprintf(title_path, sizeof(title_path), "%s/%u.%d.name.json", a->directory, (unsigned)id,
                 SL_LANG_EN);
        save_cache(a, title_path, data, size);
        prune_titles(a);
    }
    free(data);
    data = NULL;
    if (!ok || cancelled(a))
        return false;
    ok = a->fetch(url, IMAGE_LIMIT, &data, &size, a->context) && !cancelled(a) &&
         sl_artwork_decode(data, size, image);
    if (ok)
        save_cache(a, path, data, size);
    free(data);
    return ok;
}
/* Separate bounded metadata cache: existing JPEGs must not skip title lookup. */
static void prune_titles(sl_artwork *a) {
    for (;;) {
        DIR *dir = opendir(a->directory);
        if (!dir)
            return;
        unsigned count = 0;
        char oldest[900] = {0};
        time_t stamp = 0;
        struct dirent *e;
        while ((e = readdir(dir))) {
            unsigned id, language;
            int used = 0;
            if (sscanf(e->d_name, "%u.%u.name.json%n", &id, &language, &used) != 2 || !used ||
                e->d_name[used] || language < SL_LANG_ZH_CN || language > SL_LANG_EN)
                continue;
            char path[900];
            struct stat st;
            snprintf(path, sizeof(path), "%s/%u.%u.name.json", a->directory, id, language);
            if (stat(path, &st) || !S_ISREG(st.st_mode))
                continue;
            ++count;
            if (!oldest[0] || st.st_mtime < stamp) {
                strcpy(oldest, path);
                stamp = st.st_mtime;
            }
        }
        closedir(dir);
        if (count <= 64 || !oldest[0] || unlink(oldest))
            return;
    }
}
static bool load_title(sl_artwork *a, uint64_t id, int language, char *name, size_t cap) {
    char path[900];
    snprintf(path, sizeof(path), "%s/%u.%d.name.json", a->directory, (unsigned)id, language);
    struct stat st;
    unsigned char *data = NULL;
    size_t size = 0;
    if (!stat(path, &st) && S_ISREG(st.st_mode) && st.st_size > 0 && st.st_size <= 65536) {
        FILE *f = fopen(path, "rb");
        data = malloc(st.st_size);
        bool ok = f && data && fread(data, 1, st.st_size, f) == (size_t)st.st_size &&
                  sl_artwork_name(data, st.st_size, (uint32_t)id, name, cap);
        if (f)
            fclose(f);
        free(data);
        data = NULL;
        if (ok) {
            utime(path, NULL);
            return true;
        }
        unlink(path);
    }
    if (cancelled(a))
        return false;
    char request[768];
    snprintf(request, sizeof(request),
             "https://api.steampowered.com/IStoreBrowseService/GetItems/v1/?input_json="
             "%%7B%%22ids%%22:%%5B%%7B%%22appid%%22:%u%%7D%%5D,%%22context%%22:%%7B%%22language%%"
             "22:%%22%s%%22,%%22country_code%%22:%%22US%%22%%7D%%7D",
             (unsigned)id, language == SL_LANG_ZH_CN ? "schinese" : "english");
    bool ok = a->fetch(request, 65536, &data, &size, a->context) && !cancelled(a) &&
              sl_artwork_name(data, size, (uint32_t)id, name, cap);
    if (ok) {
        save_cache(a, path, data, size);
        prune_titles(a);
    }
    free(data);
    return ok;
}
static void *worker(void *ctx) {
    sl_artwork *a = ctx;
    mkdir(a->directory, 0700);
    prune(a);
    prune_titles(a);
    pthread_mutex_lock(&a->lock);
    while (!atomic_load(&a->stop)) {
        int index = -1;
        if (!atomic_load(&a->paused))
            for (int i = 0; i < SLOT_COUNT; ++i)
                if (a->entries[i].state == QUEUED) {
                    index = i;
                    break;
                }
        if (index < 0 && !atomic_load(&a->paused)) {
            for (int i = 0; i < 16; ++i) {
                title_entry *t = &a->titles[i];
                if (t->state != QUEUED)
                    continue;
                uint64_t id = t->id;
                int language = t->language;
                unsigned generation = atomic_load(&a->cancel_generation);
                t->state = LOADING;
                pthread_mutex_unlock(&a->lock);
                char name[512] = {0};
                bool ok = load_title(a, id, language, name, sizeof(name));
                pthread_mutex_lock(&a->lock);
                if (ok) {
                    strcpy(t->name, name);
                    t->state = READY;
                } else {
                    t->state = cancelled(a) || generation != atomic_load(&a->cancel_generation)
                                   ? QUEUED
                                   : FAILED;
                    t->retry = sl_system_now() + RETRY_MS;
                }
                index = -2;
                break;
            }
        }
        if (index == -2)
            continue;
        if (index < 0) {
            pthread_cond_wait(&a->wake, &a->lock);
            continue;
        }
        entry *e = &a->entries[index];
        uint64_t id = e->id;
        unsigned generation = atomic_load(&a->cancel_generation);
        e->state = LOADING;
        pthread_mutex_unlock(&a->lock);
        sl_artwork_image image = {0};
        bool ok = load(a, id, &image);
        pthread_mutex_lock(&a->lock);
        if (ok) {
            e->image = image;
            e->state = READY;
        } else {
            e->state =
                cancelled(a) || generation != atomic_load(&a->cancel_generation) ? QUEUED : FAILED;
            e->retry = sl_system_now() + RETRY_MS;
        }
    }
    pthread_mutex_unlock(&a->lock);
    atomic_store_explicit(&a->finished, true, memory_order_release);
    return NULL;
}
sl_artwork *sl_artwork_create(const char *dir, sl_artwork_fetch_fn fetch, void *ctx) {
    sl_artwork *a = calloc(1, sizeof(*a));
    if (!a)
        return NULL;
    atomic_init(&a->finished, false);
    if (snprintf(a->directory, sizeof(a->directory), "%s/artwork", dir) >=
        (int)sizeof(a->directory)) {
        free(a);
        return NULL;
    }
    if (pthread_mutex_init(&a->lock, NULL)) {
        free(a);
        return NULL;
    }
    if (pthread_cond_init(&a->wake, NULL)) {
        pthread_mutex_destroy(&a->lock);
        free(a);
        return NULL;
    }
    if (!fetch) {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
            pthread_cond_destroy(&a->wake);
            pthread_mutex_destroy(&a->lock);
            free(a);
            return NULL;
        }
        a->curl_ready = true;
    }
    a->fetch = fetch ? fetch : fetch_https;
    a->context = fetch ? ctx : a;
    if (pthread_create(&a->worker, NULL, worker, a)) {
        if (a->curl_ready)
            curl_global_cleanup();
        pthread_cond_destroy(&a->wake);
        pthread_mutex_destroy(&a->lock);
        free(a);
        return NULL;
    }
    return a;
}
void sl_artwork_pause(sl_artwork *a, bool paused) {
    if (!a || atomic_exchange(&a->paused, paused) == paused)
        return;
    if (paused) {
        atomic_fetch_add(&a->cancel_generation, 1);
        sl_system_dns_cancel(atomic_load(&a->dns_handle));
    }
    pthread_mutex_lock(&a->lock);
    pthread_cond_signal(&a->wake);
    pthread_mutex_unlock(&a->lock);
}
void sl_artwork_request(sl_artwork *a, uint64_t id) {
    if (!a || !sl_artwork_appid(id) || pthread_mutex_trylock(&a->lock))
        return;
    entry *slot = NULL;
    for (int i = 0; i < SLOT_COUNT; ++i)
        if (a->entries[i].id == id) {
            slot = &a->entries[i];
            break;
        }
    uint64_t now = sl_system_now();
    if (!slot)
        for (int i = 0; i < SLOT_COUNT; ++i) {
            entry *e = &a->entries[i];
            if (e->state != LOADING && (!slot || e->touched < slot->touched))
                slot = e;
        }
    if (slot) {
        if (slot->id != id) {
            free(slot->image.pixels);
            memset(slot, 0, sizeof(*slot));
            slot->id = id;
        }
        slot->touched = now;
        if (slot->state == EMPTY || slot->state == DELIVERED ||
            (slot->state == FAILED && now >= slot->retry)) {
            slot->state = QUEUED;
            pthread_cond_signal(&a->wake);
        }
    }
    pthread_mutex_unlock(&a->lock);
}
bool sl_artwork_take(sl_artwork *a, uint64_t id, sl_artwork_image *out) {
    if (!a || pthread_mutex_trylock(&a->lock))
        return false;
    bool found = false;
    for (int i = 0; i < SLOT_COUNT; ++i) {
        entry *e = &a->entries[i];
        if (e->id == id && e->state == READY) {
            *out = e->image;
            memset(&e->image, 0, sizeof(e->image));
            e->state = DELIVERED;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&a->lock);
    return found;
}
bool sl_artwork_title(sl_artwork *a, uint64_t id, int language, char *out, size_t capacity) {
    if (!out || !capacity)
        return false;
    out[0] = 0;
    if (!a || !sl_artwork_appid(id) || (language != SL_LANG_ZH_CN && language != SL_LANG_EN) ||
        pthread_mutex_trylock(&a->lock))
        return false;
    title_entry *slot = NULL;
    for (int i = 0; i < 16; ++i)
        if (a->titles[i].id == id && a->titles[i].language == language) {
            slot = &a->titles[i];
            break;
        }
    if (!slot)
        for (int i = 0; i < 16; ++i) {
            title_entry *t = &a->titles[i];
            if (t->state != LOADING && (!slot || t->touched < slot->touched))
                slot = t;
        }
    bool found = false;
    if (slot) {
        if (slot->id != id || slot->language != language)
            *slot = (title_entry){.id = id, .language = language};
        uint64_t now = sl_system_now();
        slot->touched = now;
        if (slot->state == READY && strlen(slot->name) < capacity) {
            strcpy(out, slot->name);
            found = true;
        }
        if (slot->state == EMPTY || (slot->state == FAILED && now >= slot->retry)) {
            slot->state = QUEUED;
            pthread_cond_signal(&a->wake);
        }
    }
    pthread_mutex_unlock(&a->lock);
    return found;
}
void sl_artwork_request_stop(sl_artwork *a) {
    if (!a)
        return;
    atomic_store(&a->stop, true);
    sl_system_dns_cancel(atomic_load(&a->dns_handle));
    pthread_mutex_lock(&a->lock);
    pthread_cond_signal(&a->wake);
    pthread_mutex_unlock(&a->lock);
}
bool sl_artwork_finished(sl_artwork *a) {
    return !a || atomic_load_explicit(&a->finished, memory_order_acquire);
}
void sl_artwork_destroy(sl_artwork *a) {
    if (!a)
        return;
    atomic_store(&a->stop, true);
    sl_system_dns_cancel(atomic_load(&a->dns_handle));
    pthread_mutex_lock(&a->lock);
    pthread_cond_signal(&a->wake);
    pthread_mutex_unlock(&a->lock);
    sl_system_log("artwork: stop requested; joining worker");
    pthread_join(a->worker, NULL);
    for (int i = 0; i < SLOT_COUNT; ++i)
        free(a->entries[i].image.pixels);
    if (a->curl_ready)
        curl_global_cleanup();
    pthread_cond_destroy(&a->wake);
    pthread_mutex_destroy(&a->lock);
    free(a);
    sl_system_log("artwork: worker joined; curl released");
}
