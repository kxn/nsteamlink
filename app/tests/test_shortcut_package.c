#include "shortcut_package.h"
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void hash(void *out, const void *data, size_t size) {
    SHA256(data, size, out);
}
static bool crypt_header(void *context, unsigned char *data) {
    bool encrypt = *(bool *)context;
    unsigned char key[32];
    for (int i = 0; i < 32; ++i)
        key[i] = 31 - i;
    for (int sector = 0; sector < 6; ++sector) {
        unsigned char iv[16] = {0};
        iv[15] = sector;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        assert(ctx);
        int n = 0, tail = 0;
        assert(EVP_CipherInit_ex(ctx, EVP_aes_128_xts(), NULL, key, iv, encrypt));
        assert(EVP_CipherUpdate(ctx, data + sector * 512, &n, data + sector * 512, 512));
        assert(EVP_CipherFinal_ex(ctx, data + sector * 512 + n, &tail));
        assert(n + tail == 512);
        EVP_CIPHER_CTX_free(ctx);
    }
    return true;
}
static void put(unsigned char *p, uint64_t v, int bytes) {
    for (int i = 0; i < bytes; ++i) {
        p[i] = v;
        v >>= 8;
    }
}
static uint64_t get(const unsigned char *p, int bytes) {
    uint64_t v = 0;
    for (int i = bytes - 1; i >= 0; --i)
        v = (v << 8) | p[i];
    return v;
}
static unsigned char *fixture(size_t *size) {
    *size = 20 + 3 * 8192;
    unsigned char *b = calloc(1, *size);
    assert(b);
    memcpy(b, "NSLFWD01", 8);
    const int types[] = {0, 2, 1};
    for (int i = 0; i < 3; ++i) {
        put(b + 8 + i * 4, 8192, 4);
        unsigned char *n = b + 20 + i * 8192;
        memcpy(n + 0x200, "NCA3", 4);
        n[0x205] = types[i];
        put(n + 0x208, 8192, 8);
        put(n + 0x210, SL_SHORTCUT_ID, 8);
        n[0x404] = 1;
    }
    unsigned char *m = b + 20 + 2 * 8192, *sb = m + 0x408;
    put(m + 0x240, 6, 4);
    put(m + 0x244, 16, 4);
    m[0x402] = 1;
    m[0x403] = 2;
    put(sb + 0x20, 0x1000, 4);
    put(sb + 0x30, 32, 8);
    put(sb + 0x38, 512, 8);
    put(sb + 0x40, 256, 8);
    unsigned char *pfs = m + 0xe00;
    memcpy(pfs, "PFS0", 4);
    put(pfs + 4, 1, 4);
    put(pfs + 8, 24, 4);
    put(pfs + 24, 192, 8);
    unsigned char *cnmt = pfs + 64;
    put(cnmt, SL_SHORTCUT_ID, 8);
    cnmt[12] = 0x80;
    cnmt[14] = 16;
    cnmt[16] = 2;
    put(cnmt + 32, SL_SHORTCUT_ID + 0x800, 8);
    return b;
}
static void verify(const unsigned char *blob, size_t size) {
    sl_shortcut_package p;
    bool encrypt = true;
    assert(sl_shortcut_materialize(&p, blob, size, hash, crypt_header, &encrypt));
    unsigned char digest[32];
    for (int i = 0; i < 3; ++i) {
        hash(digest, p.data[i], p.size[i]);
        assert(!memcmp(digest, p.hashes[i], 32));
        assert(memcmp(p.data[i] + 0x200, "NCA3", 4));
    }
    encrypt = false;
    for (int i = 0; i < 3; ++i) {
        crypt_header(&encrypt, p.data[i]);
        assert(!memcmp(p.data[i] + 0x200, "NCA3", 4));
    }
    unsigned char *m = p.data[2], *sb = m + 0x408;
    uint64_t section = get(m + 0x240, 4) * 512;
    uint64_t table = get(sb + 0x28, 8), table_size = get(sb + 0x30, 8);
    unsigned char *pfs = m + section + get(sb + 0x38, 8);
    uint64_t len = get(sb + 0x40, 8), block = get(sb + 0x20, 4);
    for (uint64_t off = 0, i = 0; off < len; off += block, ++i) {
        hash(digest, pfs + off, len - off < block ? len - off : block);
        assert(!memcmp(digest, m + section + table + i * 32, 32));
    }
    hash(digest, m + section + table, table_size);
    assert(!memcmp(digest, sb, 32));
    hash(digest, m + 0x400, 512);
    assert(!memcmp(digest, m + 0x280, 32));
    unsigned char *cnmt = pfs + 40 + get(pfs + 8, 4) + get(pfs + 16, 8);
    hash(digest, cnmt, 160);
    assert(!memcmp(digest, cnmt + 160, 32));
    for (int i = 0; i < 2; ++i)
        assert(!memcmp(p.hashes[i], cnmt + 48 + i * 56, 32));
    assert(get(p.database, 2) == 16 && get(p.database + 2, 2) == 3);
    const int types[3] = {0, 1, 3};
    for (int i = 0; i < 3; ++i) {
        unsigned char *info = p.database + 24 + i * 24;
        assert(!memcmp(info, p.hashes[(i + 2) % 3], 16));
        assert(info[22] == types[i]);
        assert(get(info + 16, 6) == p.size[(i + 2) % 3]);
    }
    sl_shortcut_package_free(&p);
    assert(!p.allocation);
}
int main(int argc, char **argv) {
    size_t size;
    unsigned char *b = fixture(&size);
    verify(b, size);
    sl_shortcut_package p;
    bool enc = true;
    for (size_t n = 0; n < size; n += 67)
        assert(!sl_shortcut_materialize(&p, b, n, hash, crypt_header, &enc));
    const size_t offsets[] = {0,
                              8,
                              12,
                              16,
                              20 + 0x200,
                              20 + 0x210,
                              20 + 16384 + 0x240,
                              20 + 16384 + 0x438,
                              20 + 16384 + 0x440,
                              20 + 16384 + 0xe04};
    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
        size_t off = offsets[i];
        unsigned char old = b[off];
        b[off] = 0xff;
        assert(!sl_shortcut_materialize(&p, b, size, hash, crypt_header, &enc));
        b[off] = old;
    }
    free(b);
    if (argc > 1) {
        FILE *f = fopen(argv[1], "rb");
        assert(f);
        fseek(f, 0, SEEK_END);
        size = ftell(f);
        rewind(f);
        b = malloc(size);
        assert(b && fread(b, 1, size, f) == size);
        fclose(f);
        verify(b, size);
        free(b);
    }
    puts("PASS template rejection, AES-XTS sealing, CNMT hashes, integrity tree and NCM database");
}
