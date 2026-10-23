#include "sns_config_cache.h"
#include "dns_policy.h"
#include "file_replace.h"
#include "http_route.h"
#include "sns_config_http.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { CONFIG_LIMIT = 1024 * 1024 };
struct sl_sns_config_cache {
    CURLM *http;
    CURL *request;
    bool request_added;
    sl_http_route route;
    char *data, *download;
    size_t size, downloaded;
    bool global;
    char path[1024];
};
static void event(const char *name) {
#if NSL_DIAGNOSTICS
    char line[96];
    snprintf(line, sizeof(line), "sns_config_cache event=%s", name);
    sl_dns_policy_report(line);
#else
    (void)name;
#endif
}
/* Shell's CUtlString::SetValue consumes a C string. Disk bytes are raw; only
 * the in-memory view stops at an embedded NUL. No JSON/import or TTL here. */
static void publish(sl_sns_config_cache *c, char *data, size_t size) {
    free(c->data);
    c->data = data;
    const char *end = size ? memchr(data, 0, size) : NULL;
    c->size = end ? (size_t)(end - data) : size;
}
static void load(sl_sns_config_cache *c) {
    if (c->path[0] && !sl_file_replace_recover(c->path))
        event("cache_recovery_failed");
    FILE *f = c->path[0] ? fopen(c->path, "rb") : NULL;
    if (!f) return;
    char *data = NULL;
    long size = -1;
    bool ok = !fseek(f, 0, SEEK_END) && (size = ftell(f)) > 0 && size <= CONFIG_LIMIT &&
              !fseek(f, 0, SEEK_SET) && (data = malloc((size_t)size + 1)) &&
              fread(data, 1, (size_t)size, f) == (size_t)size;
    if (fclose(f)) ok = false;
    if (!ok) { free(data); event("cache_ignored"); return; }
    data[size] = 0;
    publish(c, data, (size_t)size);
    event("cache_loaded");
}
static void save(sl_sns_config_cache *c) {
    /* Local publication discipline: retain the previous disk file on a failed
     * write/close. Retail writes directly; its callback ignores save failure. */
    char temporary[1040];
    if (!c->path[0]) return;
    snprintf(temporary, sizeof(temporary), "%s.tmp", c->path);
    FILE *f = fopen(temporary, "wb");
    if (!f) { event("save_failed"); return; }
    bool ok = fwrite(c->download ? c->download : "", 1, c->downloaded, f) == c->downloaded;
    if (fclose(f)) ok = false;
    if (!ok || !sl_file_replace(temporary, c->path)) {
        remove(temporary);
        event("save_failed");
    } else
        event("saved");
}
static size_t receive(char *p, size_t size, size_t count, void *context) {
    sl_sns_config_cache *c = context;
    if (size && count > SIZE_MAX / size) return 0;
    size_t bytes = size * count;
    if (bytes > CONFIG_LIMIT - c->downloaded) return 0;
    char *data = realloc(c->download, c->downloaded + bytes + 1);
    if (!data) return 0;
    if (bytes) memcpy(data + c->downloaded, p, bytes);
    c->download = data;
    c->downloaded += bytes;
    data[c->downloaded] = 0;
    return bytes;
}
static void stop_request(sl_sns_config_cache *c) {
    if (!c->request) return;
    if (c->request_added) curl_multi_remove_handle(c->http, c->request);
    c->request_added = false;
    curl_easy_cleanup(c->request);
    c->request = NULL;
    sl_http_route_clear(&c->route);
}
sl_sns_config_cache *sl_sns_config_cache_create(const char *directory) {
    sl_sns_config_cache *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    if (directory && *directory) {
        int n = snprintf(c->path, sizeof(c->path), "%s/sdr_config.txt", directory);
        if (n < 0 || n >= (int)sizeof(c->path)) c->path[0] = 0;
    }
    load(c);
    c->global = sl_http_global_acquire();
    c->http = c->global ? curl_multi_init() : NULL;
    c->request = c->http ? curl_easy_init() : NULL;
    if (c->request) {
        curl_easy_setopt(c->request, CURLOPT_URL,
            "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=353380");
        curl_easy_setopt(c->request, CURLOPT_WRITEFUNCTION, receive);
        curl_easy_setopt(c->request, CURLOPT_WRITEDATA, c);
        sl_sns_config_http_options(c->request);
        bool ready = sl_http_route_begin_async(&c->route, c->request,
            "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=353380", 25000);
        if (ready) {
            event("begin");
        } else {
            curl_easy_cleanup(c->request);
            c->request = NULL;
            sl_http_route_clear(&c->route);
        }
    }
    return c;
}
void sl_sns_config_cache_update(sl_sns_config_cache *c) {
    if (!c || !c->request) return;
    if (!c->request_added && c->route.error == CURLE_OK) {
        int ready = sl_http_route_poll(&c->route, c->request);
        if (!ready) return;
        if (ready > 0 && curl_multi_add_handle(c->http, c->request) == CURLM_OK)
            c->request_added = true;
        else if (c->route.error == CURLE_OK) c->route.error = CURLE_FAILED_INIT;
    }
    int running = 0, remaining = 0;
    CURLMcode result = c->request_added ? curl_multi_perform(c->http, &running) : CURLM_OK;
    bool done = c->route.error != CURLE_OK || result != CURLM_OK, success = false;
    CURLMsg *message;
    while ((message = curl_multi_info_read(c->http, &remaining))) {
        if (message->msg != CURLMSG_DONE || message->easy_handle != c->request) continue;
        CURLcode code = message->data.result; /* CURLMsg expires on removal. */
        if (c->request_added) curl_multi_remove_handle(c->http, c->request);
        c->request_added = false;
        if (sl_http_route_retry(&c->route, c->request, code)) {
            int ready = sl_http_route_poll(&c->route, c->request);
            if (!ready) return;
            if (ready > 0 && curl_multi_add_handle(c->http, c->request) == CURLM_OK) {
                c->request_added = true;
                return;
            }
        }
        done = true;
        success = code == CURLE_OK;
#if NSL_DIAGNOSTICS
        long status = 0, verified = 0;
        char *remote = NULL, line[224];
        curl_easy_getinfo(c->request, CURLINFO_RESPONSE_CODE, &status);
        curl_easy_getinfo(c->request, CURLINFO_SSL_VERIFYRESULT, &verified);
        curl_easy_getinfo(c->request, CURLINFO_PRIMARY_IP, &remote);
        snprintf(line, sizeof(line), "sns_config_cache curl=%d http=%ld verify=%ld ip=%.64s",
            (int)code, status, verified, remote ? remote : "");
        sl_dns_policy_report(line);
#endif
    }
    if (!done) return;
    stop_request(c);
    if (success) {
        save(c); /* Save failure must not prevent use of the response. */
        publish(c, c->download, c->downloaded);
        c->download = NULL;
        event("complete");
    } else event("download_failed");
    free(c->download);
    c->download = NULL;
    c->downloaded = 0;
}
const char *sl_sns_config_cache_data(const sl_sns_config_cache *c, size_t *size) {
    *size = c ? c->size : 0;
    return c ? c->data : NULL;
}
void sl_sns_config_cache_destroy(sl_sns_config_cache *c) {
    if (!c) return;
    stop_request(c);
    if (c->http) curl_multi_cleanup(c->http);
    if (c->global)
        sl_http_global_release();
    free(c->data);
    free(c->download);
    free(c);
}
