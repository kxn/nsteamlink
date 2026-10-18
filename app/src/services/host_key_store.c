#include "host_key_store.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool paths(const char *dir, uint64_t client, uint64_t steam, char path[512], char tmp[512],
                  char backup[512]) {
    /* Match the official little-endian identity hex namespace, in a flat
     * directory. Atomic publication is a local platform implementation choice. */
    char ids[33];
    for (unsigned n = 0; n < 8; ++n)
        snprintf(ids + 2 * n, 3, "%02x", (unsigned)((client >> (8 * n)) & 255));
    for (unsigned n = 0; n < 8; ++n)
        snprintf(ids + 16 + 2 * n, 3, "%02x", (unsigned)((steam >> (8 * n)) & 255));
    int count = snprintf(path, 512, "%s/key-%s.txt", dir, ids);
    if (count < 0 || count >= 508)
        return false;
    snprintf(tmp, 512, "%s.tmp", path);
    snprintf(backup, 512, "%s.bak", path);
    return true;
}
static bool replace(const char *tmp, const char *path, const char *backup) {
    if (!rename(tmp, path))
        return true;
    if (errno != EEXIST && errno != ENOTEMPTY)
        return false;
    if (remove(backup) && errno != ENOENT)
        return false;
    if (rename(path, backup))
        return false;
    if (!rename(tmp, path)) {
        remove(backup);
        return true;
    }
    int error = errno;
    rename(backup, path);
    errno = error;
    return false;
}
bool sl_host_key_save(const char *dir, uint64_t client, uint64_t steam, const uint8_t key[32]) {
    char path[512], tmp[512], backup[512];
    if (!client || !paths(dir, client, steam, path, tmp, backup) ||
        (mkdir(dir, 0700) && errno != EEXIST))
        return false;
    char text[66];
    for (unsigned n = 0; n < 32; ++n)
        snprintf(text + n * 2, 3, "%02x", key[n]);
    text[64] = '\n';
    FILE *file = fopen(tmp, "wb");
    if (!file)
        return false;
    bool ok = fwrite(text, 1, 65, file) == 65;
    if (fflush(file))
        ok = false;
    if (ok && fsync(fileno(file)) && errno != ENOSYS && errno != EINVAL)
        ok = false;
    if (fclose(file))
        ok = false;
    if (ok)
        ok = replace(tmp, path, backup);
    if (!ok)
        remove(tmp);
    return ok;
}
static int nibble(int c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}
int sl_host_key_load(const char *dir, uint64_t client, uint64_t steam, uint8_t key[32]) {
    char path[512], tmp[512], backup[512];
    if (!client || !paths(dir, client, steam, path, tmp, backup))
        return -1;
    FILE *file = fopen(path, "rb");
    bool recovered = false;
    if (!file && errno == ENOENT) {
        file = fopen(backup, "rb");
        recovered = file != NULL;
    }
    if (!file)
        return errno == ENOENT ? 1 : -1;
    char text[65];
    bool ok = fread(text, 1, sizeof(text), file) == sizeof(text) && fgetc(file) == EOF &&
              !ferror(file) && text[64] == '\n';
    if (fclose(file))
        ok = false;
    uint8_t selected[32];
    for (unsigned n = 0; ok && n < 32; ++n) {
        int hi = nibble((unsigned char)text[n * 2]), lo = nibble((unsigned char)text[n * 2 + 1]);
        ok = hi >= 0 && lo >= 0;
        if (ok)
            selected[n] = (uint8_t)(hi * 16 + lo);
    }
    if (ok && recovered)
        ok = !rename(backup, path);
    if (ok)
        memcpy(key, selected, 32);
    memset(selected, 0, sizeof(selected));
    return ok ? 0 : -1;
}
