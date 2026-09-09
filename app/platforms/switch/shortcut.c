#include "platform/shortcut.h"
#include "../common/shortcut_package.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <switch.h>
#include <sys/stat.h>
#include <unistd.h>
extern const unsigned char sl_shortcut_template[];
extern const size_t sl_shortcut_template_size;
static char source_path[1024];
void sl_shortcut_source(int argc, char **argv) {
    source_path[0] = 0;
    if (argc > 0 && argv && argv[0] && !strncmp(argv[0], "sdmc:/", 6) &&
        strlen(argv[0]) < sizeof(source_path))
        strcpy(source_path, argv[0]);
}
static void wipe(void *ptr, size_t size) {
    volatile unsigned char *p = ptr;
    while (size--)
        *p++ = 0;
}
static bool seal(void *key, unsigned char *header) {
    Aes128XtsContext ctx;
    aes128XtsContextCreate(&ctx, key, (unsigned char *)key + 16, true);
    for (unsigned i = 0; i < 6; ++i) {
        aes128XtsContextResetSector(&ctx, i, true);
        aes128XtsEncrypt(&ctx, header + 512 * i, header + 512 * i, 512);
    }
    wipe(&ctx, sizeof(ctx));
    return true;
}
/* Only public SPL derivation sources; derived secrets never leave this stack. */
static Result header_key(unsigned char key[32]) {
    static const unsigned char source[16] = {0x1f, 0x12, 0x91, 0x3a, 0x4a, 0xcb, 0xf0, 0x0d,
                                             0x4c, 0xde, 0x3a, 0xf6, 0xd5, 0x23, 0x88, 0x2a};
    static const unsigned char wrapped[32] = {0x5a, 0x3e, 0xd8, 0x4f, 0xde, 0xc0, 0xd8, 0x26,
                                              0x31, 0xf7, 0xe2, 0x5d, 0x19, 0x7b, 0xf5, 0xd0,
                                              0x1c, 0x9b, 0x7b, 0xfa, 0xf6, 0x28, 0x18, 0x3d,
                                              0x71, 0xf6, 0x4d, 0x73, 0xf1, 0x50, 0xb9, 0xd2};
    unsigned char kek[16] = {0};
    Result rc = splCryptoInitialize();
    if (R_FAILED(rc))
        return rc;
    rc = splCryptoGenerateAesKek(source, 0, 0, kek);
    if (R_SUCCEEDED(rc))
        rc = splCryptoGenerateAesKey(kek, wrapped, key);
    if (R_SUCCEEDED(rc))
        rc = splCryptoGenerateAesKey(kek, wrapped + 16, key + 16);
    wipe(kek, sizeof(kek));
    splCryptoExit();
    return rc;
}
static bool valid_nro(FILE *f) {
    unsigned char h[32];
    struct stat st;
    if (fstat(fileno(f), &st) || st.st_size < 128 || fread(h, 1, sizeof(h), f) != sizeof(h))
        return false;
    uint32_t size;
    memcpy(&size, h + 24, 4);
    rewind(f);
    return !memcmp(h + 16, "NRO0", 4) && size >= 128 && size <= st.st_size;
}
static bool prepare_nro(void) {
    /* No fallback to an unrelated older file when a netloader path is unavailable. */
    FILE *in = source_path[0] ? fopen(source_path, "rb") : NULL;
    if (!in)
        return false;
    if (!valid_nro(in)) {
        fclose(in);
        return false;
    }
    if (!strcmp(source_path, SL_SHORTCUT_PATH)) {
        fclose(in);
        return true;
    }
    if ((mkdir("sdmc:/switch", 0777) && errno != EEXIST) ||
        (mkdir("sdmc:/switch/nsteamlink", 0777) && errno != EEXIST)) {
        fclose(in);
        return false;
    }
    const char *temp = SL_SHORTCUT_PATH ".installing";
    /* Exclusive creation: do not overwrite a file left by another operation. */
    FILE *out = fopen(temp, "wbx");
    if (!out) {
        fclose(in);
        return false;
    }
    unsigned char *buffer = malloc(65536);
    if (!buffer) {
        fclose(in);
        fclose(out);
        unlink(temp);
        return false;
    }
    size_t n;
    bool ok = true;
    while ((n = fread(buffer, 1, 65536, in)))
        if (fwrite(buffer, 1, n, out) != n) {
            ok = false;
            break;
        }
    if (ferror(in))
        ok = false;
    free(buffer);
    fclose(in);
    if (fflush(out) || fsync(fileno(out)))
        ok = false;
    if (fclose(out))
        ok = false;
    if (ok && rename(temp, SL_SHORTCUT_PATH))
        ok = false;
    if (!ok)
        unlink(temp);
    return ok;
}
static Result database_empty(NcmContentMetaDatabase *db, bool *empty) {
    NcmContentMetaKey key;
    s32 total = 0, count = 0;
    Result rc = ncmContentMetaDatabaseList(db, &total, &count, &key, 1, NcmContentMetaType_Unknown,
                                           SL_SHORTCUT_ID, SL_SHORTCUT_ID, SL_SHORTCUT_ID,
                                           NcmContentInstallType_Full);
    *empty = total == 0;
    return rc;
}
sl_text_id sl_shortcut_install(char *detail, size_t capacity) {
    Result rc = 0;
    const char *stage = "services";
    sl_text_id result = SL_T_SHORTCUT_FAILED;
    bool ncm = false, ns = false, metadata = false, cleanup_failed = false, installed[3] = {false};
    NcmContentStorage storage = {0};
    NcmContentMetaDatabase db = {0}, other = {0};
    Service manager = {0};
    NcmContentId ids[3] = {0};
    NcmContentMetaKey key = {.id = SL_SHORTCUT_ID, .type = NcmContentMetaType_Application};
    sl_shortcut_package package = {0};
    unsigned char secret[32] = {0};
    if (capacity)
        detail[0] = 0;
#define TRY(call)                                                                                  \
    do {                                                                                           \
        rc = (call);                                                                               \
        if (R_FAILED(rc))                                                                          \
            goto done;                                                                             \
    } while (0)
    TRY(ncmInitialize());
    ncm = true;
    TRY(nsInitialize());
    ns = true;
    TRY(nsGetApplicationManagerInterface(&manager));
    bool exists = false, empty = false;
    TRY(nsIsAnyApplicationEntityInstalled(SL_SHORTCUT_ID, &exists));
    if (exists) {
        result = SL_T_SHORTCUT_EXISTS;
        goto done;
    }
    /* Include archived application records, not only installed content. */
    for (s32 offset = 0;;) {
        NsApplicationRecord records[32];
        s32 count = 0;
        TRY(nsListApplicationRecord(records, 32, offset, &count));
        for (s32 i = 0; i < count; ++i)
            if (records[i].application_id == SL_SHORTCUT_ID) {
                result = SL_T_SHORTCUT_EXISTS;
                goto done;
            }
        if (count < 32)
            break;
        offset += count;
        if (offset >= 4096)
            goto done;
    }
    TRY(ncmOpenContentMetaDatabase(&db, NcmStorageId_SdCard));
    TRY(database_empty(&db, &empty));
    if (!empty) {
        result = SL_T_SHORTCUT_EXISTS;
        goto done;
    }
    TRY(ncmOpenContentMetaDatabase(&other, NcmStorageId_BuiltInUser));
    TRY(database_empty(&other, &empty));
    if (!empty) {
        result = SL_T_SHORTCUT_EXISTS;
        goto done;
    }
    TRY(ncmOpenContentStorage(&storage, NcmStorageId_SdCard));
    stage = "SPL";
    TRY(header_key(secret));
    stage = "template";
    if (!sl_shortcut_materialize(&package, sl_shortcut_template, sl_shortcut_template_size,
                                 sha256CalculateHash, seal, secret))
        goto done;
    wipe(secret, sizeof(secret));
    for (int i = 0; i < 3; ++i) {
        memcpy(&ids[i], package.hashes[i], 16);
        TRY(ncmContentStorageHas(&storage, &exists, &ids[i]));
        if (exists) {
            result = SL_T_SHORTCUT_EXISTS;
            goto done;
        }
    }
    stage = "NRO";
    if (!prepare_nro()) {
        result = SL_T_SHORTCUT_NRO_REQUIRED;
        goto done;
    }
    stage = "content";
    for (int i = 0; i < 3; ++i) {
        NcmPlaceHolderId placeholder;
        TRY(ncmContentStorageGeneratePlaceHolderId(&storage, &placeholder));
        TRY(ncmContentStorageCreatePlaceHolder(&storage, &ids[i], &placeholder, package.size[i]));
        for (size_t off = 0; off < package.size[i]; off += 0x10000) {
            size_t len = package.size[i] - off;
            if (len > 0x10000)
                len = 0x10000;
            rc = ncmContentStorageWritePlaceHolder(&storage, &placeholder, off,
                                                   package.data[i] + off, len);
            if (R_FAILED(rc))
                break;
        }
        if (R_SUCCEEDED(rc))
            rc = ncmContentStorageRegister(&storage, &ids[i], &placeholder);
        if (R_SUCCEEDED(rc))
            installed[i] = true;
        if (R_FAILED(rc) && R_FAILED(ncmContentStorageDeletePlaceHolder(&storage, &placeholder)))
            cleanup_failed = true;
        if (R_FAILED(rc))
            goto done;
    }
    stage = "metadata";
    TRY(ncmContentMetaDatabaseSet(&db, &key, package.database, sizeof(package.database)));
    metadata = true;
    TRY(ncmContentMetaDatabaseCommit(&db));
    stage = "HOME";
    struct {
        NcmContentMetaKey key;
        u8 storage;
        u8 padding[7];
    } record = {key, NcmStorageId_SdCard, {0}};
    struct {
        u8 event;
        u8 padding[7];
        u64 id;
    } input = {3, {0}, SL_SHORTCUT_ID};
    TRY(serviceDispatchIn(&manager, 16, input,
                          .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_In},
                          .buffers = {{&record, sizeof(record)}}));
    result = SL_T_SHORTCUT_ADDED;
done:
    if (result != SL_T_SHORTCUT_ADDED) {
        bool rollback_ok = true;
        if (metadata) {
            rollback_ok = R_SUCCEEDED(ncmContentMetaDatabaseRemove(&db, &key));
            if (R_FAILED(ncmContentMetaDatabaseCommit(&db)))
                rollback_ok = false;
        }
        /* If metadata removal failed, retain its content to avoid dangling references. */
        if (rollback_ok)
            for (int i = 0; i < 3; ++i)
                if (installed[i] && R_FAILED(ncmContentStorageDelete(&storage, &ids[i])))
                    rollback_ok = false;
        if (!rollback_ok || cleanup_failed)
            result = SL_T_SHORTCUT_CLEANUP_FAILED;
        if (capacity && (R_FAILED(rc) || result == SL_T_SHORTCUT_FAILED))
            snprintf(detail, capacity, "%s · %08X", stage, rc);
    }
    wipe(secret, sizeof(secret));
    sl_shortcut_package_free(&package);
    serviceClose(&manager);
    ncmContentMetaDatabaseClose(&other);
    ncmContentMetaDatabaseClose(&db);
    ncmContentStorageClose(&storage);
    if (ns)
        nsExit();
    if (ncm)
        ncmExit();
    return result;
#undef TRY
}
