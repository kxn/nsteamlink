#include "updater.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define JSMN_STATIC
#define JSMN_STRICT
#include "jsmn.h"

static bool equal(const char *s, const jsmntok_t *t, const char *value) {
    return (size_t)(t->end - t->start) == strlen(value) &&
           !memcmp(s + t->start, value, strlen(value));
}
/* Index of the value token after `index`'s whole subtree. */
static int skip(const jsmntok_t *t, int count, int index) {
    int end = t[index].end;
    ++index;
    while (index < count && t[index].start < end)
        ++index;
    return index;
}
static int member(const char *s, const jsmntok_t *t, int count, int object, const char *key) {
    if (object < 0 || t[object].type != JSMN_OBJECT)
        return -1;
    for (int i = object + 1; i + 1 < count && t[i].start < t[object].end;) {
        if (t[i].type != JSMN_STRING)
            return -1;
        if (equal(s, &t[i], key))
            return i + 1;
        i = skip(t, count, i + 1);
    }
    return -1;
}
/* Printable ASCII only: names and URLs we accept have no escapes. */
static bool ascii(const char *s, const jsmntok_t *t, char *out, size_t cap) {
    size_t n = (size_t)(t->end - t->start);
    if (t->type != JSMN_STRING || !n || n >= cap)
        return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = s[t->start + i];
        if (c < 33 || c > 126 || c == '\\')
            return false;
        out[i] = (char)c;
    }
    out[n] = 0;
    return true;
}
static bool parse_version(const char *v, unsigned part[3]) {
    for (int i = 0; i < 3; ++i) {
        if (*v < '0' || *v > '9')
            return false;
        char *end;
        unsigned long n = strtoul(v, &end, 10);
        if (n > 99999 || (i < 2 && *end != '.') || (i == 2 && *end))
            return false;
        part[i] = (unsigned)n;
        v = end + (i < 2);
    }
    return true;
}
bool sl_update_newer(const char *candidate, const char *current) {
    unsigned a[3], b[3];
    if (!candidate || !current || !parse_version(candidate, a) || !parse_version(current, b))
        return false;
    for (int i = 0; i < 3; ++i)
        if (a[i] != b[i])
            return a[i] > b[i];
    return false;
}
/* Release assets must come from this repository's download path; GitHub
 * percent-encodes the build hash separator of NSteamLink-X.Y.Z+hash.nro. */
static bool release_url(const char *url, const char *tag) {
    char prefix[160];
    snprintf(prefix, sizeof(prefix), "%s%s/", SL_UPDATE_DOWNLOADS, tag);
    return !strncmp(url, prefix, strlen(prefix)) && !strstr(url, "..") &&
           strspn(url + strlen(prefix), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                                        "0123456789._-%") == strlen(url + strlen(prefix));
}
bool sl_update_parse_release(const unsigned char *json, size_t size, sl_update_release *out) {
    memset(out, 0, sizeof(*out));
    if (!json || !size || size > 262144)
        return false;
    const char *s = (const char *)json;
    jsmn_parser p;
    jsmn_init(&p);
    int count = jsmn_parse(&p, s, size, NULL, 0);
    if (count <= 0 || count > 16384)
        return false;
    jsmntok_t *t = malloc(sizeof(*t) * (size_t)count);
    if (!t)
        return false;
    jsmn_init(&p);
    bool ok = jsmn_parse(&p, s, size, t, (unsigned)count) == count;
    char tag[24];
    int tag_index = ok ? member(s, t, count, 0, "tag_name") : -1;
    int draft = ok ? member(s, t, count, 0, "draft") : -1;
    int prerelease = ok ? member(s, t, count, 0, "prerelease") : -1;
    int assets = ok ? member(s, t, count, 0, "assets") : -1;
    ok = tag_index >= 0 && assets >= 0 && t[assets].type == JSMN_ARRAY &&
         ascii(s, &t[tag_index], tag, sizeof(tag)) && (tag[0] == 'v' || tag[0] == 'V') &&
         strlen(tag + 1) < sizeof(out->version) && (draft < 0 || equal(s, &t[draft], "false")) &&
         (prerelease < 0 || equal(s, &t[prerelease], "false"));
    if (ok) {
        unsigned parts[3];
        strcpy(out->version, tag + 1);
        ok = parse_version(out->version, parts);
    }
    char nro_prefix[48];
    snprintf(nro_prefix, sizeof(nro_prefix), "NSteamLink-%s+", out->version);
    for (int i = assets + 1, n = 0; ok && n < t[assets].size && i < count; ++n) {
        int name = member(s, t, count, i, "name"),
            url = member(s, t, count, i, "browser_download_url"),
            bytes = member(s, t, count, i, "size");
        char asset_name[128], asset_url[512];
        if (name >= 0 && url >= 0 && ascii(s, &t[name], asset_name, sizeof(asset_name)) &&
            ascii(s, &t[url], asset_url, sizeof(asset_url)) && release_url(asset_url, tag)) {
            size_t len = strlen(asset_name);
            if (!strcmp(asset_name, "SHA256SUMS")) {
                strcpy(out->sums_url, asset_url);
            } else if (!strncmp(asset_name, nro_prefix, strlen(nro_prefix)) && len > 4 &&
                       !strcmp(asset_name + len - 4, ".nro") && bytes >= 0 &&
                       t[bytes].type == JSMN_PRIMITIVE) {
                strcpy(out->nro_name, asset_name);
                strcpy(out->nro_url, asset_url);
                out->nro_size = strtoull(s + t[bytes].start, NULL, 10);
            }
        }
        i = skip(t, count, i);
    }
    free(t);
    /* Both are required: never install an NRO without its published checksum. */
    ok = ok && out->nro_url[0] && out->sums_url[0] && out->nro_size > 0;
    if (!ok)
        memset(out, 0, sizeof(*out));
    return ok;
}
static int hex(int c) {
    return c >= '0' && c <= '9'   ? c - '0'
           : c >= 'a' && c <= 'f' ? c - 'a' + 10
           : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                  : -1;
}
/* sha256sum format: 64 hex digits, two spaces (or space and *), file name. */
bool sl_update_find_digest(const unsigned char *sums, size_t size, const char *name,
                           uint8_t digest[32]) {
    const char *s = (const char *)sums, *end = s + size;
    size_t name_len = strlen(name);
    while (s < end) {
        const char *eol = memchr(s, '\n', (size_t)(end - s));
        if (!eol)
            eol = end;
        size_t len = (size_t)(eol - s);
        if (len && s[len - 1] == '\r')
            --len;
        if (len == 66 + name_len && (s[65] == ' ' || s[65] == '*') && s[64] == ' ' &&
            !memcmp(s + 66, name, name_len)) {
            for (int i = 0; i < 32; ++i) {
                int hi = hex(s[2 * i]), lo = hex(s[2 * i + 1]);
                if (hi < 0 || lo < 0)
                    return false;
                digest[i] = (uint8_t)(hi << 4 | lo);
            }
            return true;
        }
        s = eol + 1;
    }
    return false;
}
