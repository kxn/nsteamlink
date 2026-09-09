#include "shortcut_package.h"
#include <stdlib.h>
#include <string.h>
static uint64_t le(const unsigned char *p, int n) {
    uint64_t v = 0;
    for (int i = n - 1; i >= 0; --i)
        v = (v << 8) | p[i];
    return v;
}
static void put(unsigned char *p, uint64_t v, int n) {
    for (int i = 0; i < n; ++i) {
        p[i] = (unsigned char)v;
        v >>= 8;
    }
}
static bool range(uint64_t offset, uint64_t length, size_t total) {
    return offset <= total && length <= total - offset;
}
void sl_shortcut_package_free(sl_shortcut_package *p) {
    free(p->allocation);
    memset(p, 0, sizeof(*p));
}
bool sl_shortcut_materialize(sl_shortcut_package *p, const unsigned char *blob, size_t size,
                             sl_shortcut_hash hash, sl_shortcut_seal seal, void *context) {
    memset(p, 0, sizeof(*p));
    if (size < 20 || size > 16 * 1024 * 1024 || memcmp(blob, "NSLFWD01", 8))
        return false;
    size_t pos = 20;
    const int types[3] = {0, 2, 1};
    for (int i = 0; i < 3; ++i) {
        size_t n = le(blob + 8 + 4 * i, 4);
        if (n < 0xc00 || !range(pos, n, size))
            return false;
        const unsigned char *h = blob + pos;
        if (memcmp(h + 0x200, "NCA3", 4) || h[0x205] != types[i] || le(h + 0x208, 8) != n ||
            le(h + 0x210, 8) != SL_SHORTCUT_ID || h[0x404] != 1)
            return false;
        p->size[i] = n;
        pos += n;
    }
    if (pos != size || !(p->allocation = malloc(size)))
        return false;
    memcpy(p->allocation, blob, size);
    pos = 20;
    for (int i = 0; i < 3; ++i) {
        p->data[i] = p->allocation + pos;
        pos += p->size[i];
    }
    unsigned char *meta = p->data[2], *fs = meta + 0x400, *sb = fs + 8;
    uint64_t section = le(meta + 0x240, 4) * 512;
    uint64_t end = le(meta + 0x244, 4) * 512;
    uint64_t table = le(sb + 0x28, 8), table_size = le(sb + 0x30, 8);
    uint64_t offset = le(sb + 0x38, 8), length = le(sb + 0x40, 8);
    uint64_t block = le(sb + 0x20, 4);
    if (section < 0xc00 || end > p->size[2] || end < section || fs[2] != 1 || fs[3] != 2 ||
        !range(table, table_size, end - section) || !range(offset, length, end - section) ||
        !block || block > 0x100000 || length < 40 || table + table_size > offset ||
        table_size != ((length + block - 1) / block) * 32)
        goto fail;
    unsigned char *pfs = meta + section + offset;
    if (memcmp(pfs, "PFS0", 4) || le(pfs + 4, 4) != 1)
        goto fail;
    uint64_t data = 40 + le(pfs + 8, 4);
    uint64_t file_off = le(pfs + 16, 8), file_size = le(pfs + 24, 8);
    if (!range(data, file_off, length) || !range(data + file_off, file_size, length) ||
        file_size != 192)
        goto fail;
    unsigned char *cnmt = pfs + data + file_off;
    if (le(cnmt, 8) != SL_SHORTCUT_ID || le(cnmt + 8, 4) != 0 || cnmt[12] != 0x80 ||
        le(cnmt + 14, 2) != 16 || le(cnmt + 16, 2) != 2 || le(cnmt + 18, 2) != 0)
        goto fail;
    const int content_types[3] = {1, 3, 0};
    for (int i = 0; i < 2; ++i) {
        if (!seal(context, p->data[i]))
            goto fail;
        hash(p->hashes[i], p->data[i], p->size[i]);
        unsigned char *record = cnmt + 48 + 56 * i;
        memcpy(record, p->hashes[i], 32);
        memcpy(record + 32, p->hashes[i], 16);
        put(record + 48, p->size[i], 6);
        record[54] = content_types[i];
        record[55] = 0;
    }
    hash(cnmt + 160, cnmt, 160);
    for (uint64_t off = 0, i = 0; off < length; off += block, ++i)
        hash(meta + section + table + i * 32, pfs + off,
             length - off < block ? length - off : block);
    hash(sb, meta + section + table, table_size);
    hash(meta + 0x280, fs, 512);
    memcpy(p->database + 8, cnmt + 32, 16);
    if (!seal(context, meta))
        goto fail;
    hash(p->hashes[2], meta, p->size[2]);
    put(p->database, 16, 2);
    put(p->database + 2, 3, 2);
    for (int i = 0; i < 3; ++i) {
        int index = (i + 2) % 3;
        unsigned char *info = p->database + 24 + i * 24;
        memcpy(info, p->hashes[index], 16);
        put(info + 16, p->size[index], 6);
        info[22] = content_types[index];
    }
    return true;
fail:
    sl_shortcut_package_free(p);
    return false;
}
