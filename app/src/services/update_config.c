#include "update_config.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool sl_update_config_load(const char *dir) {
    char path[512], line[32] = {0};
    snprintf(path, sizeof(path), "%s/update.conf", dir);
    FILE *f = fopen(path, "r");
    if (!f)
        return true;
    bool read = fgets(line, sizeof(line), f) != NULL;
    fclose(f);
    return !read || strncmp(line, "check=0", 7) != 0;
}
bool sl_update_config_save(const char *dir, bool enabled) {
    if (mkdir(dir, 0700) && errno != EEXIST)
        return false;
    char path[512], tmp[512], backup[512];
    snprintf(path, sizeof(path), "%s/update.conf", dir);
    snprintf(tmp, sizeof(tmp), "%s/update.tmp", dir);
    snprintf(backup, sizeof(backup), "%s/update.bak", dir);
    FILE *f = fopen(tmp, "w");
    if (!f)
        return false;
    bool ok = fprintf(f, "check=%d\n", enabled ? 1 : 0) > 0;
    if (fflush(f))
        ok = false;
    if (ok && fsync(fileno(f)) && errno != ENOSYS && errno != EINVAL)
        ok = false;
    if (fclose(f))
        ok = false;
    if (ok && rename(tmp, path)) {
        /* Horizon does not replace existing files. Keep a recoverable backup. */
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
