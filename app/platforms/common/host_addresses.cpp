#include "host_addresses.h"
#include "steam_address_sort.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace {
int64_t plus_three(int64_t n) {
    uint64_t bits = static_cast<uint64_t>(n) + 3;
    int64_t result;
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}
uint32_t ipv4(const IHS_IPAddress &ip) {
    const auto *b = ip.v4.data;
    return uint32_t(b[0]) << 24 | uint32_t(b[1]) << 16 | uint32_t(b[2]) << 8 | b[3];
}
struct Before {
    bool operator()(const sl_address_record &a, const sl_address_record &b) const {
        if (a.verified != b.verified) return a.verified;
        if (a.address.ip.family != b.address.ip.family)
            return a.address.ip.family == IHS_IPAddressFamilyIPv4;
        if (a.remote != b.remote) return !a.remote;
        if (a.timestamp > plus_three(b.timestamp)) return true;
        if (b.timestamp > plus_three(a.timestamp)) return false;
        if (a.address.ip.family == IHS_IPAddressFamilyIPv4)
            return ipv4(a.address.ip) < ipv4(b.address.ip);
        char left[64], right[64];
        sl_address_text(&a.address.ip, left);
        sl_address_text(&b.address.ip, right);
        return std::strcmp(left, right) < 0;
    }
};
}
extern "C" {
bool sl_address_has_ip(const IHS_IPAddress *ip) {
    size_t size = ip->family == IHS_IPAddressFamilyIPv4 ? 4
                  : ip->family == IHS_IPAddressFamilyIPv6 ? 16 : 0;
    const uint8_t *p = ip->family == IHS_IPAddressFamilyIPv4 ? ip->v4.data : ip->v6.data;
    for (size_t i = 0; i < size; ++i) if (p[i]) return true;
    return false;
}
void sl_address_text(const IHS_IPAddress *ip, char out[64]) {
    if (ip->family == IHS_IPAddressFamilyIPv4) {
        const auto *p = ip->v4.data;
        std::snprintf(out, 64, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
        return;
    }
    unsigned words[8];
    int best = -1, length = 1;
    for (int i = 0; i < 8; ++i)
        words[i] = unsigned(ip->v6.data[i*2]) << 8 | ip->v6.data[i*2+1];
    for (int i = 0; i < 8;) {
        if (words[i]) { ++i; continue; }
        int start = i;
        while (i < 8 && !words[i]) ++i;
        if (i-start > length) { best = start; length = i-start; }
    }
    char *p = out;
    for (int i = 0; i < 8;) {
        if (i == best) {
            *p++ = ':'; *p++ = ':';
            i += length;
        } else {
            if (p != out && p[-1] != ':') *p++ = ':';
            p += std::snprintf(p, 64-size_t(p-out), "%x", words[i++]);
        }
    }
    *p = 0;
}
bool sl_address_parse(IHS_SocketAddress *out, const char *text) {
    if (!text || !*text) return false;
    IHS_SocketAddress parsed = {};
    if (IHS_IPAddressFromString(&parsed.ip, text)) {
        *out = parsed;
        return true;
    }
    const char *port = nullptr;
    char ip[64];
    size_t length;
    if (text[0] == '[') {
        const char *end = std::strchr(text, ']');
        if (!end || end[1] != ':') return false;
        length = size_t(end-text-1);
        port = end+2;
        ++text;
    } else {
        const char *end = std::strchr(text, ':');
        if (!end || std::strchr(end+1, ':')) return false;
        length = size_t(end-text);
        port = end+1;
    }
    if (!length || length >= sizeof(ip) || !*port) return false;
    std::memcpy(ip, text, length); ip[length] = 0;
    unsigned value = 0;
    for (const char *p = port; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        value = value*10 + unsigned(*p-'0');
        if (value > 65535) return false;
    }
    if (!IHS_IPAddressFromString(&parsed.ip, ip)) return false;
    parsed.port = uint16_t(value);
    *out = parsed;
    return true;
}
void sl_addresses_destroy(sl_address_list *list) {
    std::free(list->entries);
    *list = {};
}
bool sl_addresses_reserve(sl_address_list *list, size_t count) {
    if (count <= list->capacity) return true;
    if (count > std::numeric_limits<size_t>::max()/sizeof(sl_address_record)) return false;
    size_t capacity = count;
    if (capacity < 8) capacity = 8;
    auto *p = static_cast<sl_address_record *>(std::realloc(list->entries, capacity*sizeof(sl_address_record)));
    if (!p) return false;
    list->entries = p;
    list->capacity = capacity;
    return true;
}
void sl_addresses_sort(sl_address_list *list, int depth) {
    if (list->count < 2) return;
    if (depth < 0) {
        depth = 0;
        for (size_t n = list->count; n > 1; n >>= 1) depth += 2;
    }
    Before before;
    nsl_address_sort::__introsort<nsl_address_sort::_ClassicAlgPolicy, Before&,
        sl_address_record *, false>(list->entries, list->entries+list->count, before, depth, true);
}
bool sl_addresses_add(sl_address_list *list, const IHS_SocketAddress *address,
                      bool verified, bool remote, int64_t now, bool *added) {
    *added = false;
    size_t i = 0;
    for (; i < list->count; ++i)
        if (!IHS_IPAddressCompare(&list->entries[i].address.ip, &address->ip)) break;
    if (i == list->count) {
        if (!sl_addresses_reserve(list, list->count+1)) return false;
        list->entries[list->count++] = {verified, remote, now, *address};
        *added = true;
    } else {
        auto &entry = list->entries[i];
        if (verified) {
            entry.verified = true;
            entry.timestamp = now;
            entry.address.port = address->port;
        }
        if (remote) entry.remote = true;
    }
    sl_addresses_sort(list, -1);
    return true;
}
void sl_addresses_clear_inactive(sl_address_list *list) {
    for (size_t i = list->count; i > 0; --i)
        if (!list->entries[i-1].verified)
            list->entries[i-1] = list->entries[--list->count];
}
bool sl_addresses_get(const sl_address_list *list, IHS_SocketAddress *out) {
    *out = {};
    if (!list->count || !list->entries[0].verified) return false;
    *out = list->entries[0].address;
    return true;
}
}
