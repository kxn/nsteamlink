#include "file_replace.h"
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
static bool backup_path(const char *path, char old[1100]) {
    int n = snprintf(old, 1100, "%s.old", path);
    if (n < 0 || n >= 1100) {
        errno = ENAMETOOLONG;
        return false;
    }
    return true;
}
bool sl_file_replace(const char *temporary, const char *path) {
    if (!rename(temporary, path))
        return true;
    if (errno != EEXIST && errno != ENOTEMPTY)
        return false;
    char old[1100];
    if (!backup_path(path, old))
        return false;
    if (remove(old) && errno != ENOENT)
        return false;
    if (rename(path, old))
        return false;
    if (!rename(temporary, path)) {
        remove(old);
        return true;
    }
    int error = errno;
    rename(old, path); /* If rollback fails, recovery still has the complete backup. */
    errno = error;
    return false;
}
bool sl_file_replace_recover(const char *path) {
    struct stat st;
    if (!stat(path, &st))
        return true;
    if (errno != ENOENT)
        return false;
    char old[1100];
    if (!backup_path(path, old))
        return false;
    if (!rename(old, path))
        return true;
    return errno == ENOENT;
}
