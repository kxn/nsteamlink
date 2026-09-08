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
bool sl_auth_save(const sl_auth_store *s, const char *dir) {
    if (mkdir(dir, 0700) && errno != EEXIST)
        return false;
    char path[512], tmp[512];
    snprintf(path, sizeof(path), "%s/profile.bin", dir);
    snprintf(tmp, sizeof(tmp), "%s/profile.tmp", dir);
    disk_store d = {0};
    memcpy(d.magic, "NSLUI02", 8);
    d.version = 2;
    d.size = sizeof(d);
    d.data = *s;
    for (int i = 0; i < d.data.registry.count; ++i) {
        d.data.registry.hosts[i].observed = false;
        d.data.registry.hosts[i].last_seen = 0;
    }
    d.checksum = checksum(&d.data, sizeof(d.data));
    FILE *f = fopen(tmp, "wb");
    if (!f)
        return false;
    bool ok = fwrite(&d, 1, sizeof(d), f) == sizeof(d);
    ok = fflush(f) == 0 && ok;
    if (ok && fsync(fileno(f)) && errno != ENOSYS && errno != EINVAL)
        ok = false;
    ok = fclose(f) == 0 && ok;
    if (ok)
        ok = rename(tmp, path) == 0;
    if (!ok)
        remove(tmp);
    return ok;
}
int sl_auth_load(sl_auth_store *s, const char *dir) {
    memset(s, 0, sizeof(*s));
    sl_host_registry_init(&s->registry);
    s->sound = true;
    char path[512];
    snprintf(path, sizeof(path), "%s/profile.bin", dir);
    FILE *f = fopen(path, "rb");
    if (f) {
        disk_store d;
        bool ok = fread(&d, 1, sizeof(d), f) == sizeof(d) && fgetc(f) == EOF;
        fclose(f);
        if (!ok || memcmp(d.magic, "NSLUI02", 8) || d.version != 2 || d.size != sizeof(d) ||
            d.checksum != checksum(&d.data, sizeof(d.data)) || !d.data.device_id ||
            d.data.registry.count < 0 || d.data.registry.count > SL_HOST_LIMIT ||
            d.data.quality > 2)
            return -2;
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
