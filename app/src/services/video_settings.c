#include "video_settings.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool paths(const char *dir, char *path, char *tmp, char *backup) {
    return snprintf(path, 512, "%s/video.conf", dir) < 512 &&
           snprintf(tmp, 512, "%s/video.tmp", dir) < 512 &&
           snprintf(backup, 512, "%s/video.bak", dir) < 512;
}
sl_resolution sl_video_settings_load(const char *dir) {
    char path[512], tmp[512], backup[512], text[32] = {0};
    if (!paths(dir, path, tmp, backup))
        return SL_RESOLUTION_AUTO;
    FILE *file = fopen(path, "rb");
    if (!file && errno == ENOENT)
        file = fopen(backup, "rb");
    if (!file)
        return SL_RESOLUTION_AUTO;
    size_t size = fread(text, 1, sizeof(text) - 1, file);
    bool ok = !ferror(file) && fgetc(file) == EOF;
    if (fclose(file))
        ok = false;
    if (ok && size == 16 && !memcmp(text, "resolution=1080\n", size))
        return SL_RESOLUTION_1080;
    if (ok && size == 15 && !memcmp(text, "resolution=720\n", size))
        return SL_RESOLUTION_720;
    return SL_RESOLUTION_AUTO;
}
bool sl_video_settings_save(const char *dir, sl_resolution resolution) {
    if (!sl_resolution_valid(resolution))
        return false;
    char path[512], tmp[512], backup[512];
    if (!paths(dir, path, tmp, backup) || (mkdir(dir, 0700) && errno != EEXIST))
        return false;
    FILE *file = fopen(tmp, "wb");
    if (!file)
        return false;
    bool ok = fprintf(file, "resolution=%u\n", (unsigned)resolution) > 0;
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
