#include "special_settings.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool paths(const char *dir, char *path, char *tmp, char *backup) {
    return snprintf(path, 512, "%s/special.conf", dir) < 512 &&
           snprintf(tmp, 512, "%s/special.tmp", dir) < 512 &&
           snprintf(backup, 512, "%s/special.bak", dir) < 512;
}
sl_guide_key sl_special_settings_load(const char *dir) {
    char path[512], tmp[512], backup[512], text[64] = {0};
    if (!paths(dir, path, tmp, backup))
        return SL_GUIDE_KEY_OFF;
    FILE *file = fopen(path, "rb");
    if (!file && errno == ENOENT) {
        file = fopen(backup, "rb");
        if (!file && errno == ENOENT)
            return SL_GUIDE_KEY_CAPTURE; /* Existing profiles predate this setting. */
    }
    if (!file)
        return SL_GUIDE_KEY_OFF;
    size_t size = fread(text, 1, sizeof(text) - 1, file);
    bool ok = !ferror(file) && fgetc(file) == EOF;
    if (fclose(file))
        ok = false;
    if (!ok)
        return SL_GUIDE_KEY_OFF;
    /* Exact schemas only. v1 OFF and v2 OFF both preserve screenshots; unknown
     * versions/values and trailing data must never enable interception. */
    const char *v1_capture = "version=1\ncapture_guide=1\n";
    const char *v2_capture = "version=2\nguide_key=capture\n";
    if ((size == strlen(v1_capture) && !memcmp(text, v1_capture, size)) ||
        (size == strlen(v2_capture) && !memcmp(text, v2_capture, size)))
        return SL_GUIDE_KEY_CAPTURE;
    return SL_GUIDE_KEY_OFF;
}
bool sl_special_settings_save(const char *dir, sl_guide_key key) {
    if (!sl_guide_key_valid(key))
        return false;
    char path[512], tmp[512], backup[512];
    if (!paths(dir, path, tmp, backup) || (mkdir(dir, 0700) && errno != EEXIST))
        return false;
    FILE *file = fopen(tmp, "wb");
    if (!file)
        return false;
    bool ok = fprintf(file, "version=2\nguide_key=%s\n",
                      key == SL_GUIDE_KEY_CAPTURE ? "capture" : "off") > 0;
    if (fflush(file))
        ok = false;
    if (ok && fsync(fileno(file)) && errno != ENOSYS && errno != EINVAL)
        ok = false;
    if (fclose(file))
        ok = false;
    if (ok && rename(tmp, path)) {
        ok = false;
        if (errno == EEXIST || errno == ENOTEMPTY) {
            if ((remove(backup) == 0 || errno == ENOENT) && rename(path, backup) == 0) {
                ok = rename(tmp, path) == 0;
                if (!ok)
                    rename(backup, path);
            }
        }
    }
    if (ok)
        remove(backup);
    else
        remove(tmp);
    return ok;
}
