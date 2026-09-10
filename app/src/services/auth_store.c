#include "auth_store.h"
#include "platform/system.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct __attribute__((packed)) legacy_auth {
    char magic[8];
    uint32_t version, size;
    uint64_t device_id;
    uint8_t secret[32];
    char name[64];
    uint64_t steam_id;
    char hostname[64];
    uint8_t ip[4];
    uint16_t port;
    uint8_t reserved[30];
} legacy_auth;
/* Frozen v2 layout: do not use the growing runtime structure to read old identities. */
typedef struct auth_store_v2 {
    uint64_t device_id;
    uint8_t secret[32];
    char device_name[64];
    sl_host_registry registry;
    uint32_t quality;
    bool sound;
} auth_store_v2;
typedef struct disk_store_v2 {
    char magic[8];
    uint32_t version, size, checksum;
    auth_store_v2 data;
} disk_store_v2;
typedef struct disk_store {
    char magic[8];
    uint32_t version, size, checksum;
    sl_auth_store data;
} disk_store;
static uint32_t checksum(const void *ptr, size_t n) {
    const uint8_t *p = ptr;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; ++i)
        h = (h ^ p[i]) * 16777619u;
    return h;
}
static bool store_error(const char *stage) {
    int error = errno;
    char line[128];
    snprintf(line, sizeof(line), "storage: stage=%s errno=%d", stage, error);
    sl_system_log(line);
    errno = error;
    return false;
}
/* Horizon RenameFile does not replace an existing destination. Preserve the
 * old file as a recovery record before publishing the new complete file. */
static bool replace_profile(const char *tmp, const char *path, const char *backup) {
    if (rename(tmp, path) == 0)
        return true;
    if (errno != EEXIST && errno != ENOTEMPTY)
        return store_error("replace");
    if (remove(backup) && errno != ENOENT)
        return store_error("remove-old-backup");
    if (rename(path, backup))
        return store_error("backup");
    if (rename(tmp, path) == 0) {
        remove(backup);
        return true;
    }
    int error = errno;
    rename(backup, path); /* On failure the backup remains recoverable on load. */
    errno = error;
    return store_error("publish");
}
bool sl_auth_save(const sl_auth_store *s, const char *dir) {
    if (mkdir(dir, 0700) && errno != EEXIST)
        return store_error("mkdir");
    char path[512], tmp[512], backup[512];
    snprintf(path, sizeof(path), "%s/profile.bin", dir);
    snprintf(tmp, sizeof(tmp), "%s/profile.tmp", dir);
    snprintf(backup, sizeof(backup), "%s/profile.bak", dir);
    disk_store d = {0};
    memcpy(d.magic, "NSLUI03", 8);
    d.version = 3;
    d.size = sizeof(d);
    d.data = *s;
    if (!sl_bitrate_valid(d.data.bitrate_kbps))
        d.data.bitrate_kbps = 6000;
    for (int i = 0; i < d.data.registry.count; ++i) {
        d.data.registry.hosts[i].observed = false;
        d.data.registry.hosts[i].last_seen = 0;
    }
    d.checksum = checksum(&d.data, sizeof(d.data));
    FILE *f = fopen(tmp, "wb");
    if (!f)
        return store_error("open-temp");
    bool ok = fwrite(&d, 1, sizeof(d), f) == sizeof(d);
    if (!ok)
        store_error("write-temp");
    if (fflush(f))
        ok = store_error("flush-temp");
    if (ok && fsync(fileno(f)) && errno != ENOSYS && errno != EINVAL)
        ok = store_error("sync-temp");
    if (fclose(f))
        ok = store_error("close-temp");
    if (ok)
        ok = replace_profile(tmp, path, backup);
    if (!ok)
        remove(tmp);
    return ok;
}
int sl_auth_load(sl_auth_store *s, const char *dir) {
    memset(s, 0, sizeof(*s));
    sl_host_registry_init(&s->registry);
    s->sound = true;
    s->bitrate_kbps = 6000;
    char path[512];
    snprintf(path, sizeof(path), "%s/profile.bin", dir);
    FILE *f = fopen(path, "rb");
    bool recovered = false;
    char backup[512];
    snprintf(backup, sizeof(backup), "%s/profile.bak", dir);
    if (!f && errno == ENOENT) {
        f = fopen(backup, "rb");
        recovered = f != NULL;
    }
    if (f) {
        disk_store d = {0};
        char magic[8];
        bool ok = fread(magic, 1, sizeof(magic), f) == sizeof(magic);
        rewind(f);
        if (ok && !memcmp(magic, "NSLUI02", 8)) {
            disk_store_v2 old;
            ok = fread(&old, 1, sizeof(old), f) == sizeof(old) && fgetc(f) == EOF;
            ok = ok && old.version == 2 && old.size == sizeof(old) &&
                 old.checksum == checksum(&old.data, sizeof(old.data)) && old.data.quality <= 2;
            if (ok) {
                d.data.device_id = old.data.device_id;
                memcpy(d.data.secret, old.data.secret, sizeof(d.data.secret));
                memcpy(d.data.device_name, old.data.device_name, sizeof(d.data.device_name));
                d.data.registry = old.data.registry;
                d.data.quality = old.data.quality;
                d.data.sound = old.data.sound;
                const uint32_t old_rates[] = {6000, 4000, 10000};
                d.data.bitrate_kbps = old_rates[old.data.quality];
            }
        } else if (ok && !memcmp(magic, "NSLUI03", 8)) {
            ok = fread(&d, 1, sizeof(d), f) == sizeof(d) && fgetc(f) == EOF;
            ok = ok && d.version == 3 && d.size == sizeof(d) &&
                 d.checksum == checksum(&d.data, sizeof(d.data));
        } else {
            ok = false;
        }
        fclose(f);
        if (!ok || !d.data.device_id || d.data.registry.count < 0 ||
            d.data.registry.count > SL_HOST_LIMIT || d.data.quality > 2 ||
            !sl_bitrate_valid(d.data.bitrate_kbps))
            return -2;
        if (recovered && rename(backup, path)) {
            store_error("recover");
            return -1;
        }
        *s = d.data;
        s->device_name[63] = 0;
        s->registry.selected = s->registry.count ? 0 : -1;
        for (int i = 0; i < s->registry.count; ++i) {
            sl_host *h = &s->registry.hosts[i];
            h->observed = false;
            h->last_seen = 0;
            h->name[63] = h->address[63] = h->system[23] = 0;
            for (int j = 0; j < SL_RECENT_LIMIT; ++j)
                h->games[j].name[127] = 0;
        }
        return 0;
    }
    if (errno != ENOENT)
        return -1;
    snprintf(path, sizeof(path), "%s/auth.bin", dir);
    f = fopen(path, "rb");
    if (f) {
        legacy_auth old;
        bool ok = fread(&old, 1, sizeof(old), f) == sizeof(old) && fgetc(f) == EOF;
        fclose(f);
        if (!ok || memcmp(old.magic, "NSLAUTH", 8) || old.version != 1 || old.size != sizeof(old) ||
            !old.device_id)
            return -2;
        s->device_id = old.device_id;
        memcpy(s->secret, old.secret, 32);
        memcpy(s->device_name, old.name, 64);
        s->device_name[63] = 0;
        /* Identity is preserved. An address-only v1 record cannot authorize an
         * arbitrary newly discovered host; re-pair binds its verified clientId. */
    } else {
        if (errno != ENOENT)
            return -1;
        if (!sl_system_random(&s->device_id, 8) || !sl_system_random(s->secret, 32))
            return -1;
        s->device_id = (s->device_id & UINT64_C(0x00ffffffffffffff)) | UINT64_C(0x5300000000000000);
        snprintf(s->device_name, sizeof(s->device_name), "nsteamlink");
    }
    return sl_auth_save(s, dir) ? 1 : -1;
}

bool sl_auth_discovery_hint(const sl_auth_store *s, const char *dir, char *address, size_t size) {
    char path[512];
    snprintf(path, sizeof(path), "%s/auth.bin", dir);
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    legacy_auth old;
    bool ok = fread(&old, 1, sizeof(old), f) == sizeof(old) && fgetc(f) == EOF;
    fclose(f);
    if (!ok || memcmp(old.magic, "NSLAUTH", 8) || old.version != 1 || old.size != sizeof(old) ||
        old.device_id != s->device_id || memcmp(old.secret, s->secret, 32) || !old.ip[0] ||
        old.ip[0] >= 224)
        return false;
    snprintf(address, size, "%u.%u.%u.%u", old.ip[0], old.ip[1], old.ip[2], old.ip[3]);
    return true;
}
