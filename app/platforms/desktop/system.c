#include "platform/system.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

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

sl_system_stream_info sl_system_streaming_info(void) {
    sl_system_stream_info info = {.decoder_info = "FFmpeg software decoding",
                                  .can_suspend = true,
                                  .form_factor = SL_STREAM_FORM_COMPUTER};
    struct utsname machine;
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    long pages = sysconf(_SC_PHYS_PAGES), page_size = sysconf(_SC_PAGESIZE);
    if (uname(&machine) == 0) {
        /* Linux OSType and architecture are known. GPU, physical core count and
         * display details are not measured here, so do not invent them. */
        char cpu_info[80] = "", memory_info[80] = "";
        if (cpus > 0)
            snprintf(cpu_info, sizeof(cpu_info), "\t\"LogicalCPUCount\"\t\"%ld\"\n", cpus);
        if (pages > 0 && page_size > 0)
            snprintf(memory_info, sizeof(memory_info), "\t\"SystemRAM\"\t\"%llu\"\n",
                     (unsigned long long)pages * (unsigned long long)page_size / (1024 * 1024));
        snprintf(info.system_info, sizeof(info.system_info),
                 "\"SystemInfo\"\n{\n\t\"OSType\"\t\"-203\"\n"
                 "\t\"CPUID\"\t\"%s\"\n%s%s}\n",
                 machine.machine, cpu_info, memory_info);
    }
    return info;
}
