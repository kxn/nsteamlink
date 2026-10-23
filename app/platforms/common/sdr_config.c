#include "sdr_config.h"
#define JSMN_STRICT
#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#include "jsmn.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

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
static bool ascii_string(const json *j, int index, char *out, size_t capacity) {
    const jsmntok_t *t=&j->tokens[index];
    size_t length=0;
    for (int at=t->start; at<t->end; ++at) {
        unsigned byte=(unsigned char)j->text[at];
        if (byte == '\\') {
            if (++at >= t->end) return false;
            byte=(unsigned char)j->text[at];
            if (byte == 'u') {
                if (t->end-at <= 4) return false;
                byte=0;
                for (int k=0; k<4; ++k) {
                    int digit=hex(j->text[++at]);
                    if (digit < 0) return false;
                    byte=byte*16+(unsigned)digit;
                }
            } else if (byte == 'b') byte='\b';
            else if (byte == 'f') byte='\f';
            else if (byte == 'n') byte='\n';
            else if (byte == 'r') byte='\r';
            else if (byte == 't') byte='\t';
            else if (byte != '"' && byte != '\\' && byte != '/') return false;
        }
        // Native string consumers use C strings, including embedded NUL.
        if (!byte) break;
        if (length+1 >= capacity) return false;
        if (byte > 127) byte=255; /* Non-ASCII cannot match a flag or hex digit. */
        out[length++]=(char)byte;
    }
    out[length]=0;
    return true;
}
/* Missing/wrong JSON type leaves a POP key unavailable. An explicit string
 * must decode to 32 bytes, including an empty string being invalid. The native
 * HexDecode skips nonhex characters and discards a final unpaired nibble. */
static bool public_key(const json *j, int index, uint8_t *out, bool *have) {
    *have=false;
    if (index < 0 || j->tokens[index].type != JSMN_STRING) return true;
    size_t size=(size_t)(j->tokens[index].end-j->tokens[index].start)+1;
    char *text=malloc(size);
    if (!text) return false;
    if (!ascii_string(j,index,text,size)) { free(text); return false; }
    unsigned count=0;
    int high=-1;
    for (char *at=text; *at; ++at) {
        int digit=hex(*at);
        if (digit < 0) continue;
        if (high < 0) high=digit;
        else {
            if (count == 32) { free(text); return false; }
            out[count++]=(uint8_t)(high*16+digit);
            high=-1;
        }
    }
    free(text);
    if (count != 32) return false;
    *have=true;
    return true;
}
static bool interpreted_bool(const json *j, int index) {
    if (index < 0) return false;
    const jsmntok_t *t=&j->tokens[index];
    if (t->type == JSMN_PRIMITIVE) {
        if (equal(j,index,"true")) return true;
        if (equal(j,index,"false") || equal(j,index,"null")) return false;
        size_t size=(size_t)(t->end-t->start);
        for (size_t i=0; i<size; ++i) {
            char byte=j->text[t->start+i];
            if (!(byte >= '0' && byte <= '9') && byte != '-' && byte != '+' &&
                byte != '.' && byte != 'e' && byte != 'E') return false;
        }
        char *text=malloc(size+1), *end;
        if (!text) return false;
        memcpy(text,j->text+t->start,size); text[size]=0;
        double value=strtod(text,&end);
        bool result=end==text+size && !isnan(value) && value!=0.0;
        free(text);
        return result;
    }
    if (t->type != JSMN_STRING) return false;
    char value[5];
    if (!ascii_string(j,index,value,sizeof(value))) return false;
    for (char *at=value; *at; ++at)
        if (*at >= 'A' && *at <= 'Z') *at+=(char)('a'-'A');
    return !strcmp(value,"true") || !strcmp(value,"1");
}
static bool pop_id(const json *j, int index, uint32_t *out) {
    if (index < 0 || j->tokens[index].type != JSMN_STRING) return false;
    int length=j->tokens[index].end-j->tokens[index].start;
    if (length != 3 && length != 4) return false;
    const unsigned shifts[]={16,8,0,24};
    *out=0;
    for (int i=0; i<length; ++i)
        *out |= (uint32_t)(uint8_t)j->text[j->tokens[index].start+i] << shifts[i];
    return true;
}
static bool parse(const json *j, sl_sdr_config *c) {
    int index = key(j, 0, "revision"), success = key(j, 0, "success");
    if (!integer(j, index, &c->revision) || success < 0 || !equal(j, success, "true"))
        return false;
    if (!public_key(j,key(j,0,"relay_public_key"),c->relay_public_key,&c->have_relay_key) ||
        !c->have_relay_key) return false;
    int pops = key(j, 0, "pops");
    if (pops < 0 || j->tokens[pops].type != JSMN_OBJECT)
        return false;
    for (int name = pops + 1; name + 1 < j->count && j->tokens[name].start < j->tokens[pops].end;) {
        int object = name + 1;
        if (j->tokens[name].parent != pops || j->tokens[name].type != JSMN_STRING ||
            j->tokens[object].type != JSMN_OBJECT || c->pop_count == SL_SDR_POP_MAX)
            return false;
        sl_sdr_pop *pop = &c->pops[c->pop_count];
        /* Valve CalculateSteamNetworkingPOPIDFromString preserves its legacy
         * three-byte encoding; character four occupies the high byte. */
        if (!pop_id(j,name,&pop->id)) return false;
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
        pop->type=1+(interpreted_bool(j,key(j,object,"ping_only")) ||
                     interpreted_bool(j,key(j,object,"relay_ping_only")));
        if (!public_key(j,key(j,object,"relay_public_key"),pop->relay_public_key,&pop->have_relay_key) ||
            !pop->endpoint_count) {
            pop->type=0;
            c->endpoint_count=pop->first_endpoint;
            pop->endpoint_count=0;
        }
        int aliases=key(j,object,"aliases");
        if (aliases >= 0) {
            if (j->tokens[aliases].type != JSMN_ARRAY) return false;
            for (int alias=aliases+1; alias<j->count && j->tokens[alias].start<j->tokens[aliases].end;
                 alias=next(j,alias)) {
                uint32_t id;
                if (j->tokens[alias].type != JSMN_STRING) return false;
                if (!pop_id(j,alias,&id)) continue; /* Official parser ignores invalid alias lengths. */
                if (c->alias_count == SL_SDR_ALIAS_MAX) return false;
                c->aliases[c->alias_count++]=(sl_sdr_alias){id,(unsigned)c->pop_count};
            }
        }
        ++c->pop_count;
        name = next(j, object);
    }
    /* BuildLookupTables rejects collisions between canonical names/aliases.
     * A collision must not silently redirect a signed token to another POP. */
    for (size_t i=0; i<c->pop_count; ++i)
        for (size_t k=0; k<i; ++k)
            if (c->pops[i].id == c->pops[k].id) return false;
    for (size_t i=0; i<c->alias_count; ++i) {
        for (size_t k=0; k<c->pop_count; ++k)
            if (c->aliases[i].id == c->pops[k].id) return false;
        for (size_t k=0; k<i; ++k)
            if (c->aliases[i].id == c->aliases[k].id) return false;
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
const sl_sdr_pop *sl_sdr_config_pop(const sl_sdr_config *config, uint32_t id) {
    if (!config || config->pop_count > SL_SDR_POP_MAX || config->alias_count > SL_SDR_ALIAS_MAX) return NULL;
    for (size_t i=0; i<config->pop_count; ++i)
        if (config->pops[i].id == id) return &config->pops[i];
    for (size_t i=0; i<config->alias_count; ++i)
        if (config->aliases[i].id == id && config->aliases[i].pop < config->pop_count)
            return &config->pops[config->aliases[i].pop];
    return NULL;
}
uint32_t sl_sdr_config_canonical(const sl_sdr_config *config, uint32_t id) {
    const sl_sdr_pop *pop=sl_sdr_config_pop(config,id);
    return pop ? pop->id : id;
}
const uint8_t *sl_sdr_config_relay_key(const sl_sdr_config *config, uint32_t id) {
    const sl_sdr_pop *pop=sl_sdr_config_pop(config,id);
    if (!pop) return NULL;
    if (pop->have_relay_key) return pop->relay_public_key;
    return config->have_relay_key ? config->relay_public_key : NULL;
}
