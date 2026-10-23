#include "updater.h"
#include "platform/system.h"
#include "http_route.h"
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define JSON_LIMIT 262144
#define SUMS_LIMIT 16384
#define NRO_LIMIT  (96ull * 1024 * 1024)

struct sl_updater {
    pthread_t worker;
    pthread_mutex_t lock;
    pthread_cond_t wake;
    atomic_bool stop, finished;
    atomic_uint dns_handle;
    bool curl_ready, install_requested, changed;
    sl_update_status status;
    sl_update_release release;
    char current[16];
    char targets[SL_UPDATE_MAX_TARGETS][512];
    int target_count;
    sl_update_fetch_fn fetch;
    sl_update_download_fn download;
    void *context;
};

static bool stopping(sl_updater *u) {
    return atomic_load(&u->stop);
}
static void set_status(sl_updater *u, sl_update_state state, sl_update_error error) {
    pthread_mutex_lock(&u->lock);
    u->status.state = state;
    u->status.error = error;
    u->changed = true;
    pthread_mutex_unlock(&u->lock);
}

/* ---- HTTPS ---------------------------------------------------------------- */

typedef struct transfer {
    sl_updater *owner;
    unsigned char *data;
    size_t size, limit;
    int fd;
    uint64_t written, file_limit;
} transfer;
static size_t to_memory(char *data, size_t size, size_t count, void *ctx) {
    transfer *t = ctx;
    if (stopping(t->owner) || !size || count > (t->limit - t->size) / size)
        return 0;
    size_t bytes = size * count;
    unsigned char *next = realloc(t->data, t->size + bytes);
    if (!next)
        return 0;
    t->data = next;
    memcpy(t->data + t->size, data, bytes);
    t->size += bytes;
    return bytes;
}
static size_t to_file(char *data, size_t size, size_t count, void *ctx) {
    transfer *t = ctx;
    size_t bytes = size * count;
    if (stopping(t->owner) || (size && count > SIZE_MAX / size) ||
        bytes > t->file_limit - t->written)
        return 0;
    for (size_t done = 0; done < bytes;) {
        ssize_t n = write(t->fd, data + done, bytes - done);
        if (n <= 0)
            return 0;
        done += (size_t)n;
    }
    t->written += bytes;
    return bytes;
}
static int progress(void *ctx, curl_off_t total, curl_off_t now, curl_off_t ut, curl_off_t un) {
    (void)total;
    (void)now;
    (void)ut;
    (void)un;
    return stopping(ctx);
}
static bool perform(sl_updater *u, const char *url, transfer *t, bool large) {
    CURL *c = curl_easy_init();
    if (!c)
        return false;
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    /* Release assets redirect from github.com to GitHub's download CDN;
     * follow HTTPS only. */
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L);
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, "https");
#else
    curl_easy_setopt(c, CURLOPT_PROTOCOLS, (long)CURLPROTO_HTTPS);
    curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS, (long)CURLPROTO_HTTPS);
#endif
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    if (large) {
        /* No total timeout for the NRO; give up on a stalled transfer. */
        curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, 1024L);
        curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, 30L);
    } else {
        curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, 15000L);
    }
    curl_easy_setopt(c, CURLOPT_USERAGENT, "NSteamLink/updater");
    struct curl_slist *headers = curl_slist_append(NULL, "Accept: application/vnd.github+json");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, t->fd >= 0 ? to_file : to_memory);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, t);
    curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, progress);
    curl_easy_setopt(c, CURLOPT_XFERINFODATA, u);
    atomic_store(&u->dns_handle, sl_system_dns_begin());
    CURLcode result = stopping(u) ? CURLE_ABORTED_BY_CALLBACK : sl_http_route_perform(c, url, large ? 0 : 15000);
    sl_system_dns_end(atomic_exchange(&u->dns_handle, 0));
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);
    curl_slist_free_all(headers);
    return result == CURLE_OK && code == 200 && !stopping(u);
}
static bool fetch_https(const char *url, size_t limit, unsigned char **data, size_t *size,
                        void *ctx) {
    transfer t = {.owner = ctx, .limit = limit, .fd = -1};
    *data = NULL;
    *size = 0;
    if (!perform(ctx, url, &t, false) || !t.size) {
        free(t.data);
        return false;
    }
    *data = t.data;
    *size = t.size;
    return true;
}
static bool download_https(const char *url, uint64_t limit, int fd, void *ctx) {
    transfer t = {.owner = ctx, .fd = fd, .file_limit = limit};
    return perform(ctx, url, &t, true);
}

/* ---- Files ------------------------------------------------------------------ */

static bool file_digest(const char *path, uint64_t *size, uint8_t digest[32]) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    unsigned char *buffer = malloc(65536);
    bool ok = buffer != NULL;
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    ok = ok && mbedtls_sha256_starts(&ctx, 0) == 0;
#else
    ok = ok && mbedtls_sha256_starts_ret(&ctx, 0) == 0;
#endif
    *size = 0;
    size_t n;
    while (ok && (n = fread(buffer, 1, 65536, f)) > 0) {
        *size += n;
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
        ok = mbedtls_sha256_update(&ctx, buffer, n) == 0;
#else
        ok = mbedtls_sha256_update_ret(&ctx, buffer, n) == 0;
#endif
    }
    ok = ok && !ferror(f);
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    ok = ok && mbedtls_sha256_finish(&ctx, digest) == 0;
#else
    ok = ok && mbedtls_sha256_finish_ret(&ctx, digest) == 0;
#endif
    mbedtls_sha256_free(&ctx);
    free(buffer);
    fclose(f);
    return ok;
}
/* Horizon's rename() never replaces an existing file: move the old one aside
 * and restore it if publishing the new one fails. */
static bool replace_file(const char *temporary, const char *path) {
    if (rename(temporary, path) == 0)
        return true;
    if (errno != EEXIST && errno != ENOTEMPTY)
        return false;
    char old[560];
    snprintf(old, sizeof(old), "%s.old", path);
    if (remove(old) && errno != ENOENT)
        return false;
    if (rename(path, old))
        return false;
    if (rename(temporary, path) == 0) {
        remove(old);
        return true;
    }
    int error = errno;
    rename(old, path);
    errno = error;
    return false;
}
static bool copy_file(const char *from, const char *to) {
    FILE *in = fopen(from, "rb"), *out = in ? fopen(to, "wb") : NULL;
    unsigned char *buffer = malloc(65536);
    bool ok = in && out && buffer;
    size_t n;
    while (ok && (n = fread(buffer, 1, 65536, in)) > 0)
        ok = fwrite(buffer, 1, n, out) == n;
    ok = ok && !ferror(in) && !fflush(out);
    if (out && fclose(out))
        ok = false;
    if (in)
        fclose(in);
    free(buffer);
    return ok;
}

/* ---- Worker ----------------------------------------------------------------- */

static void check(sl_updater *u) {
    unsigned char *data = NULL;
    size_t size = 0;
    sl_update_release release;
    bool found = u->fetch(SL_UPDATE_API, JSON_LIMIT, &data, &size, u->context) &&
                 sl_update_parse_release(data, size, &release) &&
                 sl_update_newer(release.version, u->current) && release.nro_size <= NRO_LIMIT;
    free(data);
    pthread_mutex_lock(&u->lock);
    if (found) {
        u->release = release;
        snprintf(u->status.version, sizeof(u->status.version), "%s", release.version);
    }
    u->status.state = found ? SL_UPDATE_AVAILABLE : SL_UPDATE_CURRENT;
    u->changed = true;
    pthread_mutex_unlock(&u->lock);
    char line[96];
    snprintf(line, sizeof(line), "update: %s%s", found ? "available " : "none newer than ",
             found ? release.version : u->current);
    sl_system_log(line);
}
static sl_update_error install(sl_updater *u) {
    unsigned char *sums = NULL;
    size_t sums_size = 0;
    uint8_t expected[32], actual[32];
    bool listed = u->fetch(u->release.sums_url, SUMS_LIMIT, &sums, &sums_size, u->context) &&
                  sl_update_find_digest(sums, sums_size, u->release.nro_name, expected);
    free(sums);
    if (!listed)
        return stopping(u) ? SL_UPDATE_ERROR_DOWNLOAD : SL_UPDATE_ERROR_VERIFY;
    /* Same directory as the installed NRO, so publishing it is a rename. */
    char temporary[560];
    snprintf(temporary, sizeof(temporary), "%s.download", u->targets[0]);
    int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return SL_UPDATE_ERROR_WRITE;
    bool downloaded = u->download(u->release.nro_url, u->release.nro_size, fd, u->context);
    if (close(fd))
        downloaded = false;
    uint64_t size = 0;
    if (!downloaded) {
        remove(temporary);
        return SL_UPDATE_ERROR_DOWNLOAD;
    }
    if (!file_digest(temporary, &size, actual) || size != u->release.nro_size ||
        memcmp(actual, expected, 32)) {
        remove(temporary);
        return SL_UPDATE_ERROR_VERIFY;
    }
    /* Extra targets (the HOME shortcut's copy) get a verified copy first,
     * then the launched NRO is replaced last. */
    for (int i = 1; i < u->target_count; ++i) {
        char copy[560];
        snprintf(copy, sizeof(copy), "%s.download", u->targets[i]);
        if (!copy_file(temporary, copy) || !replace_file(copy, u->targets[i])) {
            remove(copy);
            remove(temporary);
            return SL_UPDATE_ERROR_WRITE;
        }
    }
    if (!replace_file(temporary, u->targets[0])) {
        remove(temporary);
        return SL_UPDATE_ERROR_WRITE;
    }
    return SL_UPDATE_OK;
}
static void *worker(void *ctx) {
    sl_updater *u = ctx;
    check(u);
    pthread_mutex_lock(&u->lock);
    while (!stopping(u)) {
        if (!u->install_requested) {
            pthread_cond_wait(&u->wake, &u->lock);
            continue;
        }
        u->install_requested = false;
        pthread_mutex_unlock(&u->lock);
        set_status(u, SL_UPDATE_INSTALLING, SL_UPDATE_OK);
        sl_update_error error = install(u);
        char line[96];
        snprintf(line, sizeof(line), "update: install %s result=%d", u->release.version, error);
        sl_system_log(line);
        set_status(u, error == SL_UPDATE_OK ? SL_UPDATE_INSTALLED : SL_UPDATE_FAILED, error);
        pthread_mutex_lock(&u->lock);
    }
    pthread_mutex_unlock(&u->lock);
    atomic_store_explicit(&u->finished, true, memory_order_release);
    return NULL;
}

sl_updater *sl_updater_create(const char *current, const char *const *targets, int target_count,
                              sl_update_fetch_fn fetch, sl_update_download_fn download,
                              void *context) {
    if (target_count < 1 || !targets)
        return NULL;
    sl_updater *u = calloc(1, sizeof(*u));
    if (!u)
        return NULL;
    atomic_init(&u->stop, false);
    atomic_init(&u->finished, false);
    snprintf(u->current, sizeof(u->current), "%s", current);
    for (int i = 0; i < target_count && u->target_count < SL_UPDATE_MAX_TARGETS; ++i) {
        bool duplicate = false;
        for (int j = 0; j < u->target_count; ++j)
            duplicate |= !strcmp(u->targets[j], targets[i]);
        if (!duplicate && targets[i] && strlen(targets[i]) < sizeof(u->targets[0]))
            strcpy(u->targets[u->target_count++], targets[i]);
    }
    u->status.state = SL_UPDATE_CHECKING;
    if (pthread_mutex_init(&u->lock, NULL)) {
        free(u);
        return NULL;
    }
    if (pthread_cond_init(&u->wake, NULL)) {
        pthread_mutex_destroy(&u->lock);
        free(u);
        return NULL;
    }
    if (!fetch || !download) {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
            pthread_cond_destroy(&u->wake);
            pthread_mutex_destroy(&u->lock);
            free(u);
            return NULL;
        }
        u->curl_ready = true;
    }
    u->fetch = fetch ? fetch : fetch_https;
    u->download = download ? download : download_https;
    u->context = fetch || download ? context : u;
    if (pthread_create(&u->worker, NULL, worker, u)) {
        if (u->curl_ready)
            curl_global_cleanup();
        pthread_cond_destroy(&u->wake);
        pthread_mutex_destroy(&u->lock);
        free(u);
        return NULL;
    }
    return u;
}
bool sl_updater_poll(sl_updater *u, sl_update_status *out) {
    if (!u || pthread_mutex_trylock(&u->lock))
        return false;
    bool changed = u->changed;
    if (changed) {
        *out = u->status;
        u->changed = false;
    }
    pthread_mutex_unlock(&u->lock);
    return changed;
}
bool sl_updater_install(sl_updater *u) {
    if (!u)
        return false;
    pthread_mutex_lock(&u->lock);
    bool ok = (u->status.state == SL_UPDATE_AVAILABLE || u->status.state == SL_UPDATE_FAILED) &&
              u->release.nro_url[0];
    if (ok) {
        u->install_requested = true;
        pthread_cond_signal(&u->wake);
    }
    pthread_mutex_unlock(&u->lock);
    return ok;
}
void sl_updater_request_stop(sl_updater *u) {
    if (!u)
        return;
    atomic_store(&u->stop, true);
    sl_system_dns_cancel(atomic_load(&u->dns_handle));
    pthread_mutex_lock(&u->lock);
    pthread_cond_signal(&u->wake);
    pthread_mutex_unlock(&u->lock);
}
bool sl_updater_finished(sl_updater *u) {
    return !u || atomic_load_explicit(&u->finished, memory_order_acquire);
}
void sl_updater_destroy(sl_updater *u) {
    if (!u)
        return;
    sl_updater_request_stop(u);
    sl_system_log("update: stop requested; joining worker");
    pthread_join(u->worker, NULL);
    if (u->curl_ready)
        curl_global_cleanup();
    pthread_cond_destroy(&u->wake);
    pthread_mutex_destroy(&u->lock);
    free(u);
    sl_system_log("update: worker joined");
}
