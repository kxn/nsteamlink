#include "platform/system.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>

bool sl_system_init(void) {
    return true;
}
bool sl_system_running(void) {
    return true;
}
void sl_system_shutdown(void) {
}
bool sl_system_random(void *data, size_t size) {
    unsigned char *p = data;
    while (size) {
        ssize_t n = getrandom(p, size, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        p += n;
        size -= n;
    }
    return true;
}
const char *sl_system_data_dir(void) {
    const char *env = getenv("NSL_DATA_DIR");
    if (env && *env)
        return env;
    static char path[512];
    const char *home = getenv("HOME");
    snprintf(path, sizeof(path), "%s/.nsteamlink", home ? home : ".");
    return path;
}
const void *sl_system_font(int index, size_t *size, const char **path) {
    *size = 0;
    *path = NULL;
    if (index > 1)
        return NULL;
    const char *custom = getenv("NSL_FONT");
    *path = custom       ? custom
            : index == 0 ? "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
                         : "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc";
    return NULL;
}
uint64_t sl_system_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void sl_system_log(const char *message) {
    (void)message;
}

uint32_t sl_system_dns_begin(void) {
    return 0;
}
void sl_system_dns_cancel(uint32_t handle) {
    (void)handle;
}

const char *sl_system_locale(void) {
    const char *locale = getenv("LC_ALL");
    if (!locale || !*locale)
        locale = getenv("LC_MESSAGES");
    if (!locale || !*locale)
        locale = getenv("LANG");
    return locale && *locale ? locale : "en";
}

#ifndef NSL_PREFLIGHT_TEST
bool sl_system_preflight(void) {
    return true;
}

#endif
