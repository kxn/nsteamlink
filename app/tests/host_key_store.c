#include "services/host_key_store.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static bool horizon_rename;
int __real_rename(const char *, const char *);
int __wrap_rename(const char *from, const char *to) {
    if (horizon_rename && !access(to, F_OK)) {
        errno = EEXIST;
        return -1;
    }
    return __real_rename(from, to);
}
static void expect(const char *dir, uint64_t client, uint64_t steam, const uint8_t key[32]) {
    uint8_t out[32];
    memset(out, 0xa5, sizeof(out));
    assert(sl_host_key_load(dir, client, steam, out) == 0 && !memcmp(out, key, 32));
}
int main(void) {
    char dir[] = "/tmp/nsl-host-key-XXXXXX";
    assert(mkdtemp(dir));
    uint8_t a[32], b[32], out[32], sentinel[32];
    for (unsigned n = 0; n < 32; ++n) {
        a[n] = n;
        b[n] = n + 32;
    }
    memset(sentinel, 0xa5, 32);
    memcpy(out, sentinel, 32);
    assert(sl_host_key_load(dir, 123, 0, out) == 1 && !memcmp(out, sentinel, 32));
    assert(!sl_host_key_save(dir, 0, 0, a));
    assert(sl_host_key_save(dir, 123, 0, a));
    assert(sl_host_key_save(dir, 123, 2, b));
    assert(sl_host_key_save(dir, 456, 0, b));
    expect(dir, 123, 0, a);
    expect(dir, 123, 2, b);
    expect(dir, 456, 0, b);
    char path[512], tmp[512], bak[512];
    snprintf(path, sizeof(path), "%s/key-7b000000000000000000000000000000.txt", dir);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    snprintf(bak, sizeof(bak), "%s.bak", path);
    FILE *file = fopen(path, "rb");
    assert(file);
    char text[66] = {0};
    assert(fread(text, 1, sizeof(text), file) == 65 && !ferror(file));
    assert(!fclose(file) &&
           !strcmp(text, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"));
    assert(sl_host_key_save(dir, 123, 0, b));
    horizon_rename = true;
    assert(sl_host_key_save(dir, 123, 0, a));
    assert(access(bak, F_OK));
    expect(dir, 123, 0, a);
    /* An unopenable temporary destination must preserve the last good key. */
    assert(!mkdir(tmp, 0700));
    assert(!sl_host_key_save(dir, 123, 0, b));
    expect(dir, 123, 0, a);
    if (!access(tmp, F_OK))
        assert(!rmdir(tmp));
    /* Interrupted Horizon publication: only a complete old backup exists. */
    assert(!rename(path, bak));
    expect(dir, 123, 0, a);
    assert(!access(path, F_OK) && access(bak, F_OK));
    assert(sl_host_key_save(dir, 123, 0, b));
    expect(dir, 123, 0, b);
    /* Partial, invalid hex, overlong files never become a selected secret. */
    for (unsigned n = 0; n < 3; ++n) {
        file = fopen(path, "wb");
        assert(file);
        text[10] = n == 1 ? 'g' : '0';
        assert(fwrite(text, 1,
                      n == 0   ? 64
                      : n == 1 ? 65
                               : 66,
                      file) == (n == 0   ? 64u
                                : n == 1 ? 65u
                                         : 66u));
        assert(!fclose(file));
        memcpy(out, sentinel, 32);
        assert(sl_host_key_load(dir, 123, 0, out) == -1 && !memcmp(out, sentinel, 32));
    }
    expect(dir, 123, 2, b);
    DIR *directory = opendir(dir);
    assert(directory);
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] == '.')
            continue;
        char remove_path[512];
        snprintf(remove_path, sizeof(remove_path), "%s/%s", dir, entry->d_name);
        assert(!unlink(remove_path));
    }
    closedir(directory);
    assert(!rmdir(dir));
    puts("Identity keys: namespaces, exact bytes, repeated publication, Horizon "
         "replacement/recovery, write/read failures verified");
    return 0;
}
