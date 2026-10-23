#include "host_accounts.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void sl_accounts_destroy(sl_account_list *list) {
    free(list->ids);
    *list = (sl_account_list){0};
}
bool sl_accounts_reserve(sl_account_list *list, size_t count) {
    if (count <= list->capacity) return true;
    if (count > SIZE_MAX / sizeof(*list->ids)) return false;
    size_t capacity = list->capacity < 8 ? 8 : list->capacity;
    while (capacity < count) {
        if (capacity > SIZE_MAX / 2 / sizeof(*list->ids)) { capacity = count; break; }
        capacity *= 2;
    }
    uint64_t *ids = realloc(list->ids, capacity * sizeof(*ids));
    if (!ids) return false;
    list->ids = ids;
    list->capacity = capacity;
    return true;
}
static size_t find(const sl_account_list *list, uint64_t id) {
    size_t i = 0;
    while (i < list->count && list->ids[i] != id) ++i;
    return i;
}
bool sl_accounts_status(sl_account_list *list, uint64_t id, bool *added) {
    *added = false;
    if (!id) return true;
    size_t i = find(list, id);
    if (i < list->count) {
        list->ids[i] = list->ids[0];
        list->ids[0] = id;
        return true;
    }
    if (list->count == SIZE_MAX || !sl_accounts_reserve(list, list->count + 1)) return false;
    memmove(list->ids + 1, list->ids, list->count * sizeof(*list->ids));
    list->ids[0] = id;
    ++list->count;
    *added = true;
    return true;
}
bool sl_accounts_authorize(sl_account_list *list, uint64_t id, bool *changed) {
    *changed = false;
    if (list->count && list->ids[0] == id) return true;
    size_t i = find(list, id);
    if (i == list->count) {
        if (list->count == SIZE_MAX || !sl_accounts_reserve(list, list->count + 1)) return false;
    } else
        list->ids[i] = list->ids[--list->count];
    memmove(list->ids + 1, list->ids, list->count * sizeof(*list->ids));
    list->ids[0] = id;
    ++list->count;
    *changed = true;
    return true;
}
bool sl_accounts_pair(sl_account_list *list, uint64_t id, bool *added) {
    *added = false;
    if (find(list, id) != list->count) return true;
    if (list->count == SIZE_MAX || !sl_accounts_reserve(list, list->count + 1)) return false;
    list->ids[list->count++] = id;
    *added = true;
    return true;
}
void sl_account_hex(uint64_t id, char out[17]) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 8; ++i) {
        unsigned byte = (unsigned)(id >> (8 * i)) & 255;
        out[2*i] = hex[byte >> 4];
        out[2*i+1] = hex[byte & 15];
    }
    out[16] = 0;
}
static int nibble(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
int sl_accounts_load(sl_account_list *list, const char *path) {
    char backup[512];
    if (snprintf(backup, sizeof(backup), "%s.bak", path) >= (int)sizeof(backup)) return -1;
    FILE *f = fopen(path, "rb");
    bool recovered = false;
    if (!f && errno == ENOENT) { f = fopen(backup, "rb"); recovered = f != NULL; }
    if (!f) return errno == ENOENT ? 1 : -1;
    sl_account_list next = {0};
    bool ok = true;
    for (;;) {
        char line[17];
        size_t n = fread(line, 1, sizeof(line), f);
        if (!n) { ok = !ferror(f); break; }
        if (n != sizeof(line) || line[16] != '\n' || next.count == SIZE_MAX ||
            !sl_accounts_reserve(&next, next.count + 1)) { ok = false; break; }
        uint64_t id = 0;
        for (unsigned i = 0; i < 8; ++i) {
            int hi = nibble(line[2*i]), lo = nibble(line[2*i+1]);
            if (hi < 0 || lo < 0) { ok = false; break; }
            id |= (uint64_t)(hi * 16 + lo) << (8*i);
        }
        if (!ok) break;
        next.ids[next.count++] = id; /* Loaded order/duplicates are retained. */
    }
    if (fclose(f)) ok = false;
    if (ok && recovered) ok = !rename(backup, path);
    if (!ok) { sl_accounts_destroy(&next); return -1; }
    sl_accounts_destroy(list);
    *list = next;
    return 0;
}
bool sl_accounts_save(const sl_account_list *list, const char *path) {
    char tmp[512], backup[512];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp) ||
        snprintf(backup, sizeof(backup), "%s.bak", path) >= (int)sizeof(backup)) return false;
    FILE *f = fopen(tmp, "wb");
    if (!f) return false;
    bool ok = true;
    for (size_t i = 0; ok && i < list->count; ++i) {
        char line[18];
        sl_account_hex(list->ids[i], line);
        line[16] = '\n';
        ok = fwrite(line, 1, 17, f) == 17;
    }
    if (fflush(f)) ok = false;
    if (ok && fsync(fileno(f)) && errno != ENOSYS && errno != EINVAL) ok = false;
    if (fclose(f)) ok = false;
    if (ok && rename(tmp, path)) {
        ok = (errno == EEXIST || errno == ENOTEMPTY) &&
             (!remove(backup) || errno == ENOENT) && !rename(path, backup);
        if (ok && rename(tmp, path)) { int error = errno; rename(backup, path); errno = error; ok = false; }
        else if (ok) remove(backup);
    }
    if (!ok) remove(tmp);
    return ok;
}
