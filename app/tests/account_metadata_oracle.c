/* Production list/file and connected-session code; no policy model here. */
#include "host_accounts.h"
#include "remote_protocol.h"
#include "remote_wire.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static bool no_replace;
int __real_rename(const char *, const char *);
int __wrap_rename(const char *from, const char *to) {
    if (no_replace && !access(to, F_OK)) { errno = EEXIST; return -1; }
    return __real_rename(from, to);
}
static void storage(void) {
    char dir[] = "/tmp/nsl-account-storage-XXXXXX", path[256], tmp[260], backup[260];
    assert(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/steamid.txt", dir);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    snprintf(backup, sizeof(backup), "%s.bak", path);
    sl_account_list list = {0}, restored = {0};
    bool added;
    for (uint64_t i = 0; i < 40; ++i) assert(sl_accounts_pair(&list, i, &added) && added);
    /* A loaded duplicate must survive serialization in its original position. */
    assert(sl_accounts_reserve(&list, list.count + 1));
    list.ids[list.count++] = 3;
    assert(sl_accounts_save(&list, path) && !sl_accounts_load(&restored, path));
    assert(restored.count == 41 && !memcmp(list.ids, restored.ids, 41 * sizeof(uint64_t)));
    FILE *f = fopen(path, "wb");
    assert(f && fwrite("001\n", 1, 4, f) == 4 && !fclose(f));
    assert(sl_accounts_load(&restored, path) == -1 && restored.count == 41 && restored.ids[40] == 3);
    assert(sl_accounts_save(&list, path) && !rename(path, backup));
    assert(!sl_accounts_load(&restored, path) && !access(path, F_OK) && access(backup, F_OK));
    no_replace = true; /* Horizon publication cannot replace an existing path. */
    assert(sl_accounts_authorize(&list, 22, &added) && added && sl_accounts_save(&list, path));
    assert(!sl_accounts_load(&restored, path) && restored.ids[0] == 22 && restored.count == 41);
    assert(!mkdir(tmp, 0700) && !sl_accounts_save(&list, path));
    assert(!sl_accounts_load(&restored, path) && restored.ids[0] == 22);
    assert(!rmdir(tmp) && !unlink(path));
    assert(sl_accounts_load(&restored, path) == 1 && restored.ids[0] == 22);
    sl_accounts_destroy(&restored);
    sl_accounts_destroy(&list);
    assert(!rmdir(dir));
    puts("PASS 41 ordered IDs/duplicate/zero, invalid file preserves old value, backup recovery, Horizon replacement and real temporary-file failure");
}
static void hex(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
}
static bool sent(const uint8_t *p, size_t n, void *ctx) {
    (void)ctx;
    if (n && (p[0] >> 3) == 5) { putchar('"'); hex(p, n); puts("\""); }
    return true;
}
static void session(int argc, char **argv) {
    assert(argc == 5);
    unsigned state = (unsigned)atoi(argv[2]), universe = (unsigned)atoi(argv[3]);
    bool reconnect = atoi(argv[4]) != 0;
    size_t count;
    assert(scanf("%zu", &count) == 1 && count <= 128);
    uint64_t accounts[128];
    for (size_t i = 0; i < count; ++i) assert(scanf("%" SCNu64, &accounts[i]) == 1);
    uint8_t secret[32] = {0};
    IHS_ClientConfig config = {.deviceId = 42, .secretKey = secret, .deviceName = "account fixture"};
    sl_remote_callbacks cb = {.send = sent};
    sl_remote *r = sl_remote_create(&config, &cb, NULL);
    assert(r && sl_remote_set_paired_accounts(r, reconnect ? accounts : NULL, reconnect ? count : 0));
    if (state == 5) {
        assert(sl_remote_open(r));
        uint8_t body[32], wire[64];
        sl_proto_writer b = {body, 0, sizeof(body), false}, out = {wire, 0, sizeof(wire), false};
        sl_proto_fixed64(&b, 1, UINT64_C(0x123456789abcdef));
        sl_proto_uint(&b, 2, universe);
        sl_proto_uint(&out, 1, 1);
        sl_proto_bytes(&out, 2, body, b.size);
        assert(!b.invalid && !out.invalid && sl_remote_receive(r, wire, out.size));
    }
    if (!reconnect)
        for (size_t i = 0; i < count; ++i) assert(sl_remote_register_status(r, accounts[i]));
    /* Replacing a reconnect snapshot must not emit live subscriptions. */
    assert(sl_remote_set_paired_accounts(r, NULL, 0));
    sl_remote_close(r);
    sl_remote_destroy(r);
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "storage")) { storage(); return 0; }
    if (argc > 1) { assert(!strcmp(argv[1], "session")); session(argc, argv); return 0; }
    size_t count, steps;
    assert(scanf("%zu %zu", &count, &steps) == 2 && count <= 128 && steps <= 128);
    sl_account_list list = {0};
    assert(sl_accounts_reserve(&list, count));
    list.count = count;
    for (size_t i = 0; i < count; ++i) assert(scanf("%" SCNu64, &list.ids[i]) == 1);
    char dir[] = "/tmp/nsl-accounts-XXXXXX", path[256];
    assert(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/steamid.txt", dir);
    while (steps--) {
        unsigned kind;
        uint64_t id;
        bool added = false, ok = false;
        assert(scanf("%u %" SCNu64, &kind, &id) == 2);
        if (kind == 0) ok = sl_accounts_status(&list, id, &added);
        if (kind == 1) ok = sl_accounts_pair(&list, id, &added);
        if (kind == 2) ok = sl_accounts_authorize(&list, id, &added);
        assert(ok);
        if (added) assert(sl_accounts_save(&list, path));
        printf("{\"added\":%s,\"ids\":[", added ? "true" : "false");
        for (size_t i = 0; i < list.count; ++i) printf("%s%" PRIu64, i ? "," : "", list.ids[i]);
        printf("],\"file\":");
        FILE *f = fopen(path, "rb");
        if (!f) printf("null");
        else {
            putchar('"'); int c;
            while ((c = fgetc(f)) != EOF) printf("%02x", (unsigned char)c);
            assert(!ferror(f) && !fclose(f)); putchar('"');
            sl_account_list restored = {0};
            assert(!sl_accounts_load(&restored, path));
            /* Existing status reorder alone need not have been published. */
            if (added) assert(restored.count == list.count &&
                               (!list.count || !memcmp(restored.ids, list.ids, list.count * 8)));
            sl_accounts_destroy(&restored);
        }
        puts("}");
    }
    sl_accounts_destroy(&list);
    unlink(path);
    assert(!rmdir(dir));
    return 0;
}
