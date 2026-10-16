#include "sdr_config.h"
#define JSMN_STRICT
#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#include "jsmn.h"
#include <stdlib.h>
#include <string.h>

typedef struct json {
    const char *text;
    jsmntok_t *tokens;
    int count;
} json;
static bool equal(const json *j, int index, const char *text) {
    const jsmntok_t *t = &j->tokens[index];
    return (size_t)(t->end - t->start) == strlen(text) &&
        !memcmp(j->text + t->start, text, strlen(text));
}
static int key(const json *j, int object, const char *name) {
    if (object < 0 || j->tokens[object].type != JSMN_OBJECT)
        return -1;
    for (int i = object + 1; i + 1 < j->count && j->tokens[i].start < j->tokens[object].end; ++i)
        if (j->tokens[i].parent == object && j->tokens[i].type == JSMN_STRING && equal(j, i, name))
            return i + 1;
    return -1;
}
static bool integer(const json *j, int index, uint64_t *out) {
    if (index < 0 || j->tokens[index].type != JSMN_PRIMITIVE)
        return false;
    const jsmntok_t *t = &j->tokens[index];
    uint64_t value = 0;
    if (t->start == t->end)
        return false;
    for (int n = t->start; n < t->end; ++n) {
        unsigned digit = (unsigned)(j->text[n] - '0');
        if (digit > 9 || value > (UINT64_MAX - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    *out = value;
    return true;
}
static int next(const json *j, int index) {
    int end = j->tokens[index].end;
    while (++index < j->count && j->tokens[index].start < end) {}
    return index;
}
static bool ipv4(const json *j, int index, uint32_t *out) {
    if (index < 0 || j->tokens[index].type != JSMN_STRING)
        return false;
    jsmntok_t t = j->tokens[index];
    uint32_t result = 0;
    unsigned parts = 0, number = 0, digits = 0;
    for (int at = t.start; at <= t.end; ++at) {
        char byte = at == t.end ? '.' : j->text[at];
        if (byte == '.') {
            if (!digits || ++parts > 4)
                return false;
            result = result << 8 | number;
            number = digits = 0;
        } else if (byte >= '0' && byte <= '9') {
            if (++digits > 3 || (number = number * 10 + (unsigned)(byte - '0')) > 255)
                return false;
        } else {
            return false;
        }
    }
    if (parts != 4 || !result)
        return false;
    *out = result;
    return true;
}
static int hex(char c) {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
         : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}
static bool parse(const json *j, sl_sdr_config *c) {
    int index = key(j, 0, "revision"), success = key(j, 0, "success");
    if (!integer(j, index, &c->revision) || success < 0 || !equal(j, success, "true"))
        return false;
    index = key(j, 0, "relay_public_key");
    if (index >= 0 && j->tokens[index].type == JSMN_STRING &&
        j->tokens[index].end - j->tokens[index].start == 64) {
        c->have_relay_key = true;
        for (int k = 0; k < 32; ++k) {
            int a = hex(j->text[j->tokens[index].start + k * 2]);
            int b = hex(j->text[j->tokens[index].start + k * 2 + 1]);
            if (a < 0 || b < 0) {
                c->have_relay_key = false;
                break;
            }
            c->relay_public_key[k] = (uint8_t)(a * 16 + b);
        }
    }
    int pops = key(j, 0, "pops");
    if (pops < 0 || j->tokens[pops].type != JSMN_OBJECT)
        return false;
    for (int name = pops + 1; name + 1 < j->count && j->tokens[name].start < j->tokens[pops].end;) {
        int object = name + 1;
        if (j->tokens[name].parent != pops || j->tokens[name].type != JSMN_STRING ||
            j->tokens[object].type != JSMN_OBJECT || c->pop_count == SL_SDR_POP_MAX)
            return false;
        int length = j->tokens[name].end - j->tokens[name].start;
        if (length < 1 || length > 4)
            return false;
        sl_sdr_pop *pop = &c->pops[c->pop_count];
        /* Valve CalculateSteamNetworkingPOPIDFromString preserves its legacy
         * three-byte encoding; character four occupies the high byte. */
        const unsigned shifts[] = {16, 8, 0, 24};
        for (int k = 0; k < length; ++k)
            pop->id |= (uint32_t)(uint8_t)j->text[j->tokens[name].start + k] << shifts[k];
        pop->tier = 1;
        uint64_t tier;
        index = key(j, object, "tier");
        if (index >= 0) {
            if (!integer(j, index, &tier) || tier > INT32_MAX)
                return false;
            pop->tier = (int)tier;
        }
        pop->first_endpoint = c->endpoint_count;
        int relays = key(j, object, "relays");
        if (relays >= 0) {
            if (j->tokens[relays].type != JSMN_ARRAY)
                return false;
            for (int relay = relays + 1; relay < j->count && j->tokens[relay].start < j->tokens[relays].end;
                 relay = next(j, relay)) {
                sl_sdr_endpoint ep = {.pop = (unsigned)c->pop_count};
                if (j->tokens[relay].type != JSMN_OBJECT ||
                    !ipv4(j, key(j, relay, "ipv4"), &ep.ipv4))
                    return false;
                int ports = key(j, relay, "port_range");
                uint64_t low, high;
                if (ports < 0 || j->tokens[ports].type != JSMN_ARRAY || j->tokens[ports].size != 2 ||
                    !integer(j, ports + 1, &low) || !integer(j, ports + 2, &high) ||
                    !low || low > high || high > UINT16_MAX || c->endpoint_count == SL_SDR_ENDPOINT_MAX)
                    return false;
                ep.port_min = (uint16_t)low;
                ep.port_max = (uint16_t)high;
                c->endpoints[c->endpoint_count++] = ep;
            }
        }
        pop->endpoint_count = c->endpoint_count - pop->first_endpoint;
        ++c->pop_count;
        name = next(j, object);
    }
    return c->pop_count && c->endpoint_count;
}
bool sl_sdr_config_parse(const char *text, size_t size, sl_sdr_config *out) {
    if (!text || !out || size > 1024 * 1024)
        return false;
    json j = {.text = text, .tokens = malloc(sizeof(jsmntok_t) * 32768)};
    sl_sdr_config *c = calloc(1, sizeof(*c));
    bool ok = false;
    if (j.tokens && c) {
        jsmn_parser p;
        jsmn_init(&p);
        j.count = jsmn_parse(&p, text, size, j.tokens, 32768);
        if (j.count > 0 && j.tokens[0].type == JSMN_OBJECT && next(&j, 0) == j.count && parse(&j, c)) {
            *out = *c;
            ok = true;
        }
    }
    free(j.tokens);
    free(c);
    return ok;
}
