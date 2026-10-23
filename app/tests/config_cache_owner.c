/* Real cache file/owner/curl paths. Only URL routing, individual file failures
 * and deterministic cancellation are supplied by this fixture. No SDK/media. */
#include "../platforms/common/sns_config_cache.c"
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <time.h>

static const char *target, *fault;
static long follow, fail_http;
CURLcode __real_curl_easy_setopt(CURL *, CURLoption, ...);
CURLcode __wrap_curl_easy_setopt(CURL *e, CURLoption option, ...) {
    va_list args;
    va_start(args, option);
    CURLcode ret;
    if (option == CURLOPT_WRITEFUNCTION)
        ret = __real_curl_easy_setopt(e, option, va_arg(args, curl_write_callback));
    else if (option >= CURLOPTTYPE_OBJECTPOINT && option < CURLOPTTYPE_FUNCTIONPOINT) {
        void *p = va_arg(args, void *);
        ret = __real_curl_easy_setopt(e, option, option == CURLOPT_URL ? (const void *)target : p);
    } else {
        assert(option < CURLOPTTYPE_OBJECTPOINT);
        long v = va_arg(args, long);
        if (option == CURLOPT_FOLLOWLOCATION) follow = v;
        if (option == CURLOPT_FAILONERROR) fail_http = v;
        ret = __real_curl_easy_setopt(e, option, v);
    }
    va_end(args);
    return ret;
}
size_t __real_fwrite(const void *, size_t, size_t, FILE *);
size_t __wrap_fwrite(const void *p, size_t s, size_t n, FILE *f) {
    if (!strcmp(fault, "write")) return 0;
    return __real_fwrite(p, s, n, f);
}
int __real_rename(const char *, const char *);
int __wrap_rename(const char *a, const char *b) {
    if (!strcmp(fault, "rename")) {
        errno = EIO;
        return -1;
    }
    struct stat st;
    if (!strncmp(fault, "switch-", 7) && !stat(b, &st)) {
        errno = EEXIST;
        return -1;
    }
    if (!strcmp(fault, "switch-publish-fails") && strstr(a, ".tmp")) {
        errno = EIO;
        return -1;
    }
    return __real_rename(a, b);
}
static void output(const char *stage, sl_sns_config_cache *c) {
    size_t n;
    const char *data = sl_sns_config_cache_data(c, &n);
    printf("{\"stage\":\"%s\",\"data\":\"", stage);
    for (size_t i = 0; i < n; ++i) printf("%02x", (unsigned char)data[i]);
    printf("\",\"active\":%s,\"follow\":%ld,\"fail_http\":%ld}\n",
           c->request ? "true" : "false", follow, fail_http);
}
int main(int argc, char **argv) {
    assert(argc == 4);
    target = argv[2]; fault = argv[3];
    for (unsigned round = 0; round < 2; ++round) {
        sl_sns_config_cache *c = sl_sns_config_cache_create(argv[1]);
        assert(c);
        output("loaded", c);
        if (strcmp(fault, "cancel")) {
            for (unsigned i = 0; c->request && i < 3000; ++i) {
                sl_sns_config_cache_update(c);
                struct timespec pause = {0, 1000000}; nanosleep(&pause, NULL);
            }
            assert(!c->request);
            output("complete", c);
            // A finished Shell prefetch must not restart/retry on later ticks.
            for (unsigned i = 0; i < 3; ++i) sl_sns_config_cache_update(c);
            assert(!c->request);
        }
        sl_sns_config_cache_destroy(c);
    }
    puts("{\"clean\":true}");
}
