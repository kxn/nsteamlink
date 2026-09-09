#include "platform/shortcut.h"
#include "shortcut_package.h"
#include <assert.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <switch.h>
#include <sys/stat.h>
#include <unistd.h>
static int calls, fail_at, live, content, placeholders, metadata, home, conflict, fail_cleanup;
static int step(void) {
    return ++calls == fail_at ? 0x1234 : 0;
}
static int open_service(Service *s) {
    int r = step();
    if (!r) {
        s->active = 1;
        live++;
    }
    return r;
}
void serviceClose(Service *s) {
    if (s->active) {
        --live;
        s->active = 0;
    }
}
Result ncmInitialize(void) {
    int r = step();
    if (!r)
        ++live;
    return r;
}
void ncmExit(void) {
    --live;
}
Result nsInitialize(void) {
    return ncmInitialize();
}
void nsExit(void) {
    --live;
}
Result splCryptoInitialize(void) {
    return ncmInitialize();
}
void splCryptoExit(void) {
    --live;
}
Result splCryptoGenerateAesKek(const void *p, u32 a, u32 b, void *out) {
    (void)a;
    (void)b;
    memcpy(out, p, 16);
    return step();
}
Result splCryptoGenerateAesKey(const void *a, const void *b, void *out) {
    (void)a;
    memcpy(out, b, 16);
    return step();
}
void aes128XtsContextCreate(Aes128XtsContext *c, const void *a, const void *b, bool e) {
    (void)c;
    (void)a;
    (void)b;
    (void)e;
}
void aes128XtsContextResetSector(Aes128XtsContext *c, u64 s, bool n) {
    (void)c;
    (void)s;
    (void)n;
}
void aes128XtsEncrypt(Aes128XtsContext *c, void *o, const void *i, size_t n) {
    (void)c;
    memmove(o, i, n);
}
void sha256CalculateHash(void *o, const void *i, size_t n) {
    SHA256(i, n, o);
}
Result nsGetApplicationManagerInterface(Service *s) {
    return open_service(s);
}
Result nsListApplicationRecord(NsApplicationRecord *r, s32 n, s32 offset, s32 *count) {
    (void)n;
    (void)offset;
    *count = conflict == 4;
    if (*count)
        r[0].application_id = SL_SHORTCUT_ID;
    return step();
}
Result nsIsAnyApplicationEntityInstalled(u64 id, bool *out) {
    assert(id == SL_SHORTCUT_ID);
    *out = conflict == 1;
    return step();
}
Result ncmOpenContentMetaDatabase(NcmContentMetaDatabase *s, int storage) {
    (void)storage;
    return open_service(s);
}
Result ncmOpenContentStorage(NcmContentStorage *s, int storage) {
    assert(storage == 5);
    return open_service(s);
}
Result ncmContentMetaDatabaseList(NcmContentMetaDatabase *d, s32 *total, s32 *count,
                                  NcmContentMetaKey *keys, s32 size, int type, u64 id, u64 min,
                                  u64 max, int install) {
    (void)d;
    (void)keys;
    (void)size;
    (void)type;
    (void)install;
    assert(id == SL_SHORTCUT_ID && min == id && max == id);
    *total = *count = conflict == 2;
    return step();
}
Result ncmContentStorageHas(NcmContentStorage *s, bool *out, const NcmContentId *id) {
    (void)s;
    (void)id;
    *out = conflict == 3;
    return step();
}
Result ncmContentStorageGeneratePlaceHolderId(NcmContentStorage *s, NcmPlaceHolderId *id) {
    (void)s;
    memset(id, 0, sizeof(*id));
    return step();
}
Result ncmContentStorageCreatePlaceHolder(NcmContentStorage *s, const NcmContentId *id,
                                          const NcmPlaceHolderId *p, int64_t n) {
    (void)s;
    (void)id;
    (void)p;
    assert(n > 0);
    int r = step();
    if (!r)
        ++placeholders;
    return r;
}
Result ncmContentStorageWritePlaceHolder(NcmContentStorage *s, const NcmPlaceHolderId *p, u64 off,
                                         const void *data, size_t n) {
    (void)s;
    (void)p;
    (void)off;
    assert(data && n);
    return step();
}
Result ncmContentStorageRegister(NcmContentStorage *s, const NcmContentId *id,
                                 const NcmPlaceHolderId *p) {
    (void)s;
    (void)id;
    (void)p;
    int r = step();
    if (!r) {
        ++content;
        --placeholders;
    }
    return r;
}
Result ncmContentStorageDeletePlaceHolder(NcmContentStorage *s, const NcmPlaceHolderId *p) {
    (void)s;
    (void)p;
    --placeholders;
    return 0;
}
Result ncmContentStorageDelete(NcmContentStorage *s, const NcmContentId *id) {
    (void)s;
    (void)id;
    --content;
    return 0;
}
Result ncmContentMetaDatabaseSet(NcmContentMetaDatabase *d, const NcmContentMetaKey *k,
                                 const void *data, u64 n) {
    (void)d;
    assert(k->id == SL_SHORTCUT_ID && n == 96 && data);
    int r = step();
    if (!r)
        metadata = 1;
    return r;
}
Result ncmContentMetaDatabaseRemove(NcmContentMetaDatabase *d, const NcmContentMetaKey *k) {
    (void)d;
    (void)k;
    if (fail_cleanup)
        return 0x4321;
    metadata = 0;
    return 0;
}
Result ncmContentMetaDatabaseCommit(NcmContentMetaDatabase *d) {
    (void)d;
    return step();
}
Result fake_push(u64 id) {
    assert(id == SL_SHORTCUT_ID);
    int r = step();
    if (!r)
        home = 1;
    return r;
}
int main(void) {
    char temp[] = "/tmp/nsl-shortcut-XXXXXX";
    assert(mkdtemp(temp) && !chdir(temp));
    assert(!mkdir("sdmc:", 0700));
    FILE *f = fopen("sdmc:/source.nro", "wb");
    assert(f);
    unsigned char nro[128] = {0};
    memcpy(nro + 16, "NRO0", 4);
    nro[24] = 128;
    assert(fwrite(nro, 1, 128, f) == 128);
    fclose(f);
    char *argv[] = {"sdmc:/source.nro"};
    sl_shortcut_source(1, argv);
    char detail[64];
    assert(sl_shortcut_install(detail, sizeof(detail)) == SL_T_SHORTCUT_ADDED);
    int steps = calls;
    assert(home && content == 3 && metadata && !placeholders && !live);
    for (int fail = 1; fail <= steps; ++fail) {
        calls = live = content = placeholders = metadata = home = 0;
        fail_at = fail;
        assert(sl_shortcut_install(detail, sizeof(detail)) == SL_T_SHORTCUT_FAILED);
        assert(!live && !content && !placeholders && !metadata && !home);
    }
    calls = live = content = placeholders = metadata = home = 0;
    fail_at = steps; /* HOME registration fails, then metadata rollback fails. */
    fail_cleanup = 1;
    assert(sl_shortcut_install(detail, sizeof(detail)) == SL_T_SHORTCUT_CLEANUP_FAILED);
    assert(!live && content == 3 && metadata && !home); /* Keep referenced content. */
    fail_cleanup = content = metadata = 0;
    fail_at = 0;
    for (conflict = 1; conflict <= 4; ++conflict) {
        calls = 0;
        assert(sl_shortcut_install(detail, sizeof(detail)) == SL_T_SHORTCUT_EXISTS);
        assert(!live && !content && !metadata && !home);
    }
    conflict = 0;
    unlink("sdmc:/source.nro");
    assert(sl_shortcut_install(detail, sizeof(detail)) == SL_T_SHORTCUT_NRO_REQUIRED);
    assert(!live && !content && !metadata && !home);
    unlink(SL_SHORTCUT_PATH);
    rmdir("sdmc:/switch/nsteamlink");
    rmdir("sdmc:/switch");
    rmdir("sdmc:");
    chdir("/");
    rmdir(temp);
    printf("PASS install, %d injected service failures, collision and missing NRO cleanup\n",
           steps);
}
