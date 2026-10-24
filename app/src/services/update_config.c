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
static bool save_config(const char *dir, const char *name, const char *contents) {
    if (mkdir(dir, 0700) && errno != EEXIST)
        return false;
    char path[512], tmp[512], backup[512];
    snprintf(path, sizeof(path), "%s/%s.conf", dir, name);
    snprintf(tmp, sizeof(tmp), "%s/%s.tmp", dir, name);
    snprintf(backup, sizeof(backup), "%s/%s.bak", dir, name);
    FILE *f = fopen(tmp, "w");
    if (!f)
        return false;
    bool ok = fputs(contents, f) >= 0;
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
bool sl_update_config_save(const char *dir, bool enabled) {
    return save_config(dir, "update", enabled ? "check=1\n" : "check=0\n");
}
static bool valid_version(const char *version) {
    size_t n = strlen(version);
    if (!n || n >= 16)
        return false;
    unsigned dots = 0, digits = 0;
    for (size_t i = 0; i < n; ++i) {
        if (version[i] >= '0' && version[i] <= '9')
            ++digits;
        else if (version[i] == '.' && digits && dots < 2) {
            ++dots;
            digits = 0;
        } else
            return false;
    }
    return dots == 2 && digits;
}
void sl_update_ignored_load(const char *dir, char version[16]) {
    char path[512], line[32] = {0};
    version[0] = 0;
    snprintf(path, sizeof(path), "%s/update_ignored.conf", dir);
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    bool read = fgets(line, sizeof(line), f) != NULL;
    fclose(f);
    line[strcspn(line, "\r\n")] = 0;
    if (read && valid_version(line))
        strcpy(version, line);
}
bool sl_update_ignored_save(const char *dir, const char *version) {
    if (!valid_version(version))
        return false;
    char contents[17];
    snprintf(contents, sizeof(contents), "%s\n", version);
    return save_config(dir, "update_ignored", contents);
}
