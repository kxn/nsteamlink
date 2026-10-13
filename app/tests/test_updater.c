#include "updater.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Horizon's rename() refuses to replace an existing file. */
static bool no_replace;
int __real_rename(const char *from, const char *to);
int __wrap_rename(const char *from, const char *to) {
    if (no_replace && access(to, F_OK) == 0) {
        errno = EEXIST;
        return -1;
    }
    return __real_rename(from, to);
}

#define DL          "https://github.com/kxn/nsteamlink/releases/download/v0.2.2/"
#define PAYLOAD     "NRO payload v0.2.2\n"
#define PAYLOAD_SHA "6c6824fbc5e4bfad2461fd0205b76e7f52805a71dfec72eb4edd8f48d48b0862"
static const char release_json[] =
    "{\"url\":\"https://api.github.com/repos/kxn/nsteamlink/releases/1\",\"tag_name\":\"v0.2.2\","
    "\"name\":\"NSteamLink v0.2.2\",\"draft\":false,\"prerelease\":false,"
    "\"body\":\"# NSteamLink v0.2.2\\n\\n\\u4e2d\\u6587 \\\"quoted\\\" {not: json}\","
    "\"assets\":[{\"name\":\"build_identity.json\",\"size\":137,\"browser_download_url\":\"" DL
    "build_identity.json\"},{\"name\":\"NSteamLink-0.2.2+abcdef0.nro\",\"size\":19,"
    "\"uploader\":{\"login\":\"x\",\"size\":5},\"browser_download_url\":\"" DL
    "NSteamLink-0.2.2%2Babcdef0.nro\"},{\"name\":\"SHA256SUMS\",\"size\":270,"
    "\"browser_download_url\":\"" DL "SHA256SUMS\"}]}";
static const char sums[] =
    "f0125ddd3108c2ee585fcaa49900e7839c0f289ac6c7d49c97f32db6d1c2af65  "
    "build_identity.json\r\n" PAYLOAD_SHA "  NSteamLink-0.2.2+abcdef0.nro\r\n";

static void parse(void) {
    sl_update_release r;
    assert(sl_update_parse_release((const void *)release_json, strlen(release_json), &r));
    assert(!strcmp(r.version, "0.2.2") && r.nro_size == 19);
    assert(!strcmp(r.nro_name, "NSteamLink-0.2.2+abcdef0.nro"));
    assert(!strcmp(r.nro_url, DL "NSteamLink-0.2.2%2Babcdef0.nro"));
    assert(!strcmp(r.sums_url, DL "SHA256SUMS"));

    /* Each of these must be rejected. */
    const char *bad[][2] = {
        {"\"prerelease\":false", "\"prerelease\":true"},
        {"\"draft\":false", "\"draft\":true"},
        {"\"tag_name\":\"v0.2.2\"", "\"tag_name\":\"0.2.2\""},
        {"\"tag_name\":\"v0.2.2\"", "\"tag_name\":\"v0.2.2-rc1\""},
        {"\"name\":\"SHA256SUMS\"", "\"name\":\"SHA256SUMS.txt\""},
        /* An asset hosted outside this repository's release downloads. */
        {DL "NSteamLink-0.2.2%2Babcdef0.nro", "https://example.com/NSteamLink-0.2.2%2Babcdef0.nro"},
        /* An NRO for a different version than the tag. */
        {"\"name\":\"NSteamLink-0.2.2+abcdef0.nro\"", "\"name\":\"NSteamLink-0.2.1+abcdef0.nro\""},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        char json[2048];
        const char *at = strstr(release_json, bad[i][0]);
        assert(at);
        snprintf(json, sizeof(json), "%.*s%s%s", (int)(at - release_json), release_json, bad[i][1],
                 at + strlen(bad[i][0]));
        assert(!sl_update_parse_release((const void *)json, strlen(json), &r));
    }
    assert(!sl_update_parse_release((const void *)"{", 1, &r));
    assert(!sl_update_parse_release((const void *)"[]", 2, &r));
}

static void versions(void) {
    assert(sl_update_newer("0.2.2", "0.2.1"));
    assert(sl_update_newer("0.10.0", "0.9.9"));
    assert(sl_update_newer("1.0.0", "0.99.99"));
    assert(!sl_update_newer("0.2.1", "0.2.1"));
    assert(!sl_update_newer("0.2.0", "0.2.1"));
    assert(!sl_update_newer("0.2", "0.1.0"));
    assert(!sl_update_newer("0.2.2-rc1", "0.2.1"));
    assert(!sl_update_newer("0.2.2", "0.2.1+abc"));
    assert(!sl_update_newer("a.b.c", "0.0.1"));
}

static void digests(void) {
    uint8_t d[32];
    assert(
        sl_update_find_digest((const void *)sums, strlen(sums), "NSteamLink-0.2.2+abcdef0.nro", d));
    assert(d[0] == 0x6c && d[31] == 0x62);
    assert(!sl_update_find_digest((const void *)sums, strlen(sums), "NSteamLink-0.2.2+abcdef0", d));
    assert(!sl_update_find_digest((const void *)sums, strlen(sums), "SHA256SUMS", d));
    const char binary[] = PAYLOAD_SHA " *name.nro\n";
    assert(sl_update_find_digest((const void *)binary, strlen(binary), "name.nro", d));
    const char bad_hex[] = "zz" PAYLOAD_SHA "  name.nro\n";
    assert(!sl_update_find_digest((const void *)bad_hex, strlen(bad_hex), "name.nro", d));
}

/* Fake network: one release, its checksums and a download body. */
typedef struct fake {
    const char *json, *payload;
    bool fail_download;
    int api_calls;
} fake;
static bool fake_fetch(const char *url, size_t limit, unsigned char **data, size_t *size,
                       void *ctx) {
    fake *f = ctx;
    const char *body = !strcmp(url, SL_UPDATE_API)     ? (++f->api_calls, f->json)
                       : !strcmp(url, DL "SHA256SUMS") ? sums
                                                       : NULL;
    if (!body || strlen(body) > limit)
        return false;
    *size = strlen(body);
    *data = malloc(*size);
    memcpy(*data, body, *size);
    return true;
}
static bool fake_download(const char *url, uint64_t limit, int fd, void *ctx) {
    fake *f = ctx;
    assert(!strcmp(url, DL "NSteamLink-0.2.2%2Babcdef0.nro") && limit == 19);
    if (f->fail_download)
        return false;
    return write(fd, f->payload, strlen(f->payload)) == (ssize_t)strlen(f->payload);
}

static sl_update_status wait_for(sl_updater *u, sl_update_state state) {
    sl_update_status s = {0};
    for (int i = 0; i < 5000; ++i) {
        if (sl_updater_poll(u, &s) && s.state == state)
            return s;
        usleep(1000);
    }
    fprintf(stderr, "timed out waiting for update state %d (last %d)\n", state, s.state);
    abort();
}
static void write_text(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    assert(f && fputs(text, f) >= 0 && fclose(f) == 0);
}
static bool has_text(const char *path, const char *text) {
    char buffer[64] = {0};
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(buffer, 1, sizeof(buffer) - 1, f);
    fclose(f);
    return n == strlen(text) && !memcmp(buffer, text, n);
}
static bool exists(const char *path) {
    return access(path, F_OK) == 0;
}

static void install(bool horizon) {
    no_replace = horizon;
    char dir[] = "/tmp/nsl-updater-XXXXXX", launched[256], shortcut[256], leftover[300];
    assert(mkdtemp(dir));
    snprintf(launched, sizeof(launched), "%s/launched.nro", dir);
    snprintf(shortcut, sizeof(shortcut), "%s/nsteamlink.nro", dir);
    write_text(launched, "old");
    write_text(shortcut, "old");
    const char *targets[] = {launched, shortcut, launched};
    fake f = {.json = release_json, .payload = PAYLOAD};
    sl_updater *u = sl_updater_create("0.2.1", targets, 3, fake_fetch, fake_download, &f);
    assert(u);
    sl_update_status s = wait_for(u, SL_UPDATE_AVAILABLE);
    assert(!strcmp(s.version, "0.2.2"));
    assert(sl_updater_install(u));
    /* Polling reports the latest state; INSTALLING may already be over. */
    s = wait_for(u, SL_UPDATE_INSTALLED);
    assert(s.error == SL_UPDATE_OK);
    assert(has_text(launched, PAYLOAD) && has_text(shortcut, PAYLOAD));
    const char *suffixes[] = {".download", ".old"};
    for (int i = 0; i < 2; ++i) {
        snprintf(leftover, sizeof(leftover), "%s%s", launched, suffixes[i]);
        assert(!exists(leftover));
        snprintf(leftover, sizeof(leftover), "%s%s", shortcut, suffixes[i]);
        assert(!exists(leftover));
    }
    sl_updater_destroy(u);
    assert(f.api_calls == 1);
    unlink(launched);
    unlink(shortcut);
    rmdir(dir);
    no_replace = false;
}

/* A failed install leaves the installed NRO untouched and can be retried. */
static void failures(void) {
    no_replace = true;
    char dir[] = "/tmp/nsl-updater-XXXXXX", launched[256], leftover[300];
    assert(mkdtemp(dir));
    snprintf(launched, sizeof(launched), "%s/launched.nro", dir);
    write_text(launched, "old");
    const char *targets[] = {launched};

    fake f = {.json = release_json, .payload = "NRO payload v0.2.X\n"};
    sl_updater *u = sl_updater_create("0.2.1", targets, 1, fake_fetch, fake_download, &f);
    wait_for(u, SL_UPDATE_AVAILABLE);
    assert(sl_updater_install(u));
    sl_update_status s = wait_for(u, SL_UPDATE_FAILED);
    assert(s.error == SL_UPDATE_ERROR_VERIFY && has_text(launched, "old"));

    f.fail_download = true;
    assert(sl_updater_install(u));
    s = wait_for(u, SL_UPDATE_FAILED);
    assert(s.error == SL_UPDATE_ERROR_DOWNLOAD && has_text(launched, "old"));

    f.fail_download = false;
    f.payload = PAYLOAD;
    assert(sl_updater_install(u));
    wait_for(u, SL_UPDATE_INSTALLED);
    assert(has_text(launched, PAYLOAD));
    snprintf(leftover, sizeof(leftover), "%s.download", launched);
    assert(!exists(leftover));
    sl_updater_destroy(u);
    unlink(launched);
    rmdir(dir);
    no_replace = false;
}

static void nothing_to_install(void) {
    /* Already current: nothing offered, install refused. */
    fake f = {.json = release_json, .payload = PAYLOAD};
    const char *targets[] = {"/nonexistent/launched.nro"};
    sl_updater *u = sl_updater_create("0.2.2", targets, 1, fake_fetch, fake_download, &f);
    wait_for(u, SL_UPDATE_CURRENT);
    assert(!sl_updater_install(u));
    sl_updater_destroy(u);

    /* No NRO to replace: no check at all. */
    assert(!sl_updater_create("0.2.1", NULL, 0, fake_fetch, fake_download, &f));
    assert(!sl_updater_create("0.2.1", targets, 0, fake_fetch, fake_download, &f));

    /* A check that fails offers nothing. */
    f.json = "not json";
    u = sl_updater_create("0.2.1", targets, 1, fake_fetch, fake_download, &f);
    wait_for(u, SL_UPDATE_CURRENT);
    sl_updater_destroy(u);
}

int main(void) {
    parse();
    versions();
    digests();
    install(false);
    install(true);
    failures();
    nothing_to_install();
    printf("updater tests OK\n");
    return 0;
}
