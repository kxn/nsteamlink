#include "remote_connection.h"
#include "crypto.h"
#include "remote_wire.h"
#include "http_route.h"
#define JSMN_STRICT
#include "jsmn.h"
#include <curl/curl.h>
#include <mbedtls/base64.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if NSL_DIAGNOSTICS
#include <arpa/inet.h>
#endif

#define CM_LIMIT   32
#define FIFO_LIMIT 32
enum { NET_IDLE, NET_DIRECTORY, NET_TLS, NET_UPGRADE, NET_WEBSOCKET };
struct outgoing {
    uint8_t *data;
    size_t size, sent;
};
struct sl_remote_connection {
    sl_remote *protocol;
    sl_remote_callbacks callbacks;
    void *ctx;
    CURLM *multi;
    CURL *easy;
    sl_http_route route;
    bool easy_added, global;
    bool bridge_mode, suspended;
    int state;
    uint64_t retry_at, deadline;
    char endpoints[CM_LIMIT][128];
    size_t endpoint_count, endpoint_index;
    char expected[29];
    uint8_t *receive, *message;
    size_t received, message_size;
    bool fragmented;
    uint8_t ping[8];
    bool awaiting_pong;
    uint64_t next_ping, pong_deadline;
    struct outgoing fifo[FIFO_LIMIT];
    size_t head, count;
#if NSL_DIAGNOSTICS
    unsigned attempts_logged;
#endif
};
static const char directory_url[] = "https://api.steampowered.com/ISteamDirectory/"
                                    "GetCMListForConnect/v1/?cellid=0&cmtype=websockets";
#if NSL_DIAGNOSTICS
static const char *stage_name(int state) {
    static const char *names[] = {"idle", "directory", "tls", "upgrade", "websocket"};
    return state >= NET_IDLE && state <= NET_WEBSOCKET ? names[state] : "invalid";
}
static int network_trace(CURL *easy, curl_infotype type, char *data, size_t size, void *context) {
    (void)easy;
    sl_remote_connection *c = context;
    /* curl 7.69.1 connect.c emits this before connect(). Unlike PRIMARY_IP,
     * it remains observable when TCP never connects. Never forward raw trace:
     * even TEXT can contain credentials; headers and payload are ignored. */
    static const char prefix[] = "  Trying ";
    if (type != CURLINFO_TEXT || !c->callbacks.diagnostic || c->attempts_logged >= 16 ||
        size <= sizeof(prefix) - 1 || memcmp(data, prefix, sizeof(prefix) - 1))
        return 0;
    data += sizeof(prefix) - 1;
    size -= sizeof(prefix) - 1;
    char address[80];
    size_t n = 0;
    while (n < size && n < sizeof(address) - 1) {
        if (n + 3 <= size && !memcmp(data + n, "...", 3))
            break;
        ++n;
    }
    if (n + 3 > size || n >= sizeof(address) - 1 || memcmp(data + n, "...", 3))
        return 0;
    memcpy(address, data, n);
    address[n] = 0;
    char *port = strrchr(address, ':');
    if (!port || !port[1])
        return 0;
    *port++ = 0;
    unsigned number = 0;
    for (const char *p = port; *p; ++p) {
        if (*p < '0' || *p > '9' || number > 6553)
            return 0;
        number = number * 10 + (unsigned)(*p - '0');
    }
    if (!number || number > 65535)
        return 0;
    char *ip = address;
    size_t length = strlen(ip);
    if (length > 2 && ip[0] == '[' && ip[length - 1] == ']') {
        ip[length - 1] = 0;
        ++ip;
    }
    unsigned char numeric[16];
    int family = strchr(ip, ':') ? AF_INET6 : AF_INET;
    if (inet_pton(family, ip, numeric) != 1)
        return 0;
    char line[160];
    snprintf(line, sizeof(line), "cloud_try stage=%s ip=%s port=%u", stage_name(c->state), ip,
             number);
    ++c->attempts_logged;
    c->callbacks.diagnostic(line, c->ctx);
    return 0;
}
static void network_event(sl_remote_connection *c, const char *event, int result) {
    if (!c->callbacks.diagnostic)
        return;
    long http = 0, os_error = 0, verification = 0;
    double total = 0, dns = 0, tcp = 0, tls = 0;
    char *local = NULL, *remote = NULL;
    if (c->easy) {
        curl_easy_getinfo(c->easy, CURLINFO_RESPONSE_CODE, &http);
        curl_easy_getinfo(c->easy, CURLINFO_OS_ERRNO, &os_error);
        curl_easy_getinfo(c->easy, CURLINFO_SSL_VERIFYRESULT, &verification);
        curl_easy_getinfo(c->easy, CURLINFO_TOTAL_TIME, &total);
        curl_easy_getinfo(c->easy, CURLINFO_NAMELOOKUP_TIME, &dns);
        curl_easy_getinfo(c->easy, CURLINFO_CONNECT_TIME, &tcp);
        curl_easy_getinfo(c->easy, CURLINFO_APPCONNECT_TIME, &tls);
        curl_easy_getinfo(c->easy, CURLINFO_LOCAL_IP, &local);
        curl_easy_getinfo(c->easy, CURLINFO_PRIMARY_IP, &remote);
    }
    char line[224];
    snprintf(line, sizeof(line),
             "cloud_net event=%s stage=%s curl=%d http=%ld os=%ld verify=%ld candidate=%zu/%zu",
             event, stage_name(c->state), (int)result, http, os_error, verification,
             c->endpoint_index, c->endpoint_count);
    c->callbacks.diagnostic(line, c->ctx);
    snprintf(line, sizeof(line), "cloud_time total_ms=%.0f dns_ms=%.0f tcp_ms=%.0f tls_ms=%.0f",
             total * 1000, dns * 1000, tcp * 1000, tls * 1000);
    c->callbacks.diagnostic(line, c->ctx);
    if ((local && local[0]) || (remote && remote[0])) {
        snprintf(line, sizeof(line), "cloud_addr local=%.64s remote=%.64s", local ? local : "",
                 remote ? remote : "");
        c->callbacks.diagnostic(line, c->ctx);
    }
}
void sl_remote_connection_describe(const sl_remote_connection *c, uint64_t now, char *out,
                                   size_t capacity) {
    if (!capacity)
        return;
    if (!c) {
        snprintf(out, capacity, "state=absent ready=0");
        return;
    }
    snprintf(out, capacity, "state=%s ready=%d candidate=%zu/%zu retry_ms=%llu suspended=%d",
             stage_name(c->state), sl_remote_ready(c->protocol), c->endpoint_index,
             c->endpoint_count, (unsigned long long)(c->retry_at > now ? c->retry_at - now : 0),
             c->suspended);
}
#else
#define network_event(c, event, result) ((void)0)
#endif
static void erase_free(void *p, size_t n) {
    if (p) {
        volatile uint8_t *q = p;
        while (n--)
            *q++ = 0;
        free(p);
    }
}
static bool queue_raw(sl_remote_connection *c, const void *data, size_t size) {
    if (c->count == FIFO_LIMIT)
        return false;
    uint8_t *copy = malloc(size);
    if (!copy)
        return false;
    memcpy(copy, data, size);
    c->fifo[(c->head + c->count++) % FIFO_LIMIT] = (struct outgoing){copy, size, 0};
    return true;
}
static bool queue_frame(sl_remote_connection *c, unsigned op, const void *data, size_t size) {
    if (c->state != NET_WEBSOCKET || c->count == FIFO_LIMIT)
        return false;
    uint8_t mask[4];
    if (IHS_CryptoRandomBytes(mask, 4))
        return false;
    uint8_t *frame = malloc(size + 14);
    if (!frame)
        return false;
    size_t length = sl_ws_encode(frame, size + 14, op, data, size, mask);
    bool ok = length && queue_raw(c, frame, length);
    erase_free(frame, size + 14);
    return ok;
}
static bool send_binary(const uint8_t *p, size_t n, void *ctx) {
    return queue_frame(ctx, 2, p, n);
}
/* Forwarding adapters keep the application context separate from the provider. */
static void diagnostic(const char *message, void *ctx) {
    sl_remote_connection *c = ctx;
    if (c->callbacks.diagnostic)
        c->callbacks.diagnostic(message, c->ctx);
}
static void connected(bool state, void *ctx) {
    sl_remote_connection *c = ctx;
    if (c->callbacks.connected)
        c->callbacks.connected(state, c->ctx);
}
static void disconnecting(void *ctx) {
    sl_remote_connection *c = ctx;
    c->callbacks.disconnecting(c->ctx);
}
static bool begin_pairing(void *ctx) {
    sl_remote_connection *c = ctx;
    return c->callbacks.begin_pairing(c->ctx);
}
static bool prepare_pairing(IHS_SteamUniverse universe, const char *pin, uint8_t **body,
                            size_t *size, void *ctx) {
    sl_remote_connection *c = ctx;
    return c->callbacks.prepare_pairing(universe, pin, body, size, c->ctx);
}
static void abort_pairing(void *ctx) {
    sl_remote_connection *c = ctx;
    c->callbacks.abort_pairing(c->ctx);
}
static bool control_packet(const uint8_t *wire, size_t size, void *ctx) {
    sl_remote_connection *c = ctx;
    return c->callbacks.control_packet(wire, size, c->ctx);
}
static void host(const sl_remote_host *h, void *ctx) {
    sl_remote_connection *c = ctx;
    if (c->callbacks.host)
        c->callbacks.host(h, c->ctx);
}
static void offline(uint64_t id, void *ctx) {
    sl_remote_connection *c = ctx;
    if (c->callbacks.offline)
        c->callbacks.offline(id, c->ctx);
}
static void pair_code(const char *pin, void *ctx) {
    sl_remote_connection *c = ctx;
    if (c->callbacks.pair_code)
        c->callbacks.pair_code(pin, c->ctx);
}
static bool save_key(const sl_remote_peer *peer, void *ctx) {
    sl_remote_connection *c = ctx;
    return c->callbacks.save_key && c->callbacks.save_key(peer, c->ctx);
}
static void paired(const sl_remote_peer *peer, void *ctx) {
    sl_remote_connection *c = ctx;
    if (c->callbacks.paired)
        c->callbacks.paired(peer, c->ctx);
}
static void pair_failed(IHS_AuthorizationResult result, void *ctx) {
    sl_remote_connection *c = ctx;
    if (c->callbacks.pair_failed)
        c->callbacks.pair_failed(result, c->ctx);
}
static void stream_result(IHS_StreamingResult result, const sl_remote_material *m, void *ctx) {
    sl_remote_connection *c = ctx;
    if (c->callbacks.stream_result)
        c->callbacks.stream_result(result, m, c->ctx);
}
static void transport_signal(uint64_t id, const uint8_t *p, size_t n, void *ctx) {
    sl_remote_connection *c = ctx;
    if (c->callbacks.transport_signal)
        c->callbacks.transport_signal(id, p, n, c->ctx);
}
static void clear_easy(sl_remote_connection *c) {
    if (c->easy) {
        if (c->easy_added)
            curl_multi_remove_handle(c->multi, c->easy);
        curl_easy_cleanup(c->easy);
        c->easy = NULL;
        sl_http_route_clear(&c->route);
    }
    c->easy_added = false;
    for (size_t i = 0; i < c->count; ++i) {
        struct outgoing *q = &c->fifo[(c->head + i) % FIFO_LIMIT];
        erase_free(q->data, q->size);
        *q = (struct outgoing){0};
    }
    c->head = c->count = 0;
    memset(c->receive, 0, SL_REMOTE_FRAME_MAX + 16384);
    memset(c->message, 0, SL_REMOTE_FRAME_MAX);
    c->received = c->message_size = 0;
    c->fragmented = false;
    c->awaiting_pong = false;
    c->next_ping = c->pong_deadline = 0;
}
static void fail_connection(sl_remote_connection *c, uint64_t now) {
    /* Established disconnect reconnects immediately; initialization failures use
     * official 10–30s jitter. Pending pairing is never replayed. */
    bool established = sl_remote_ready(c->protocol);
    if (c->callbacks.diagnostic)
        c->callbacks.diagnostic(established ? "cloud: session reset; reconnecting"
                                            : "cloud: initialization failed; retry scheduled",
                                c->ctx);
    clear_easy(c);
    sl_remote_close(c->protocol);
    c->state = NET_IDLE;
    uint32_t random = IHS_CryptoRandomUInt32();
    c->retry_at = established ? now : now + 10000 + (uint64_t)random * 20000 / UINT32_MAX;
#if NSL_DIAGNOSTICS
    if (c->callbacks.diagnostic) {
        char line[128];
        snprintf(line, sizeof(line), "cloud_net event=retry established=%d delay_ms=%llu",
                 established, (unsigned long long)(c->retry_at - now));
        c->callbacks.diagnostic(line, c->ctx);
    }
#endif
    c->endpoint_count = c->endpoint_index = 0;
}
static size_t directory_write(char *data, size_t size, size_t count, void *ctx) {
    sl_remote_connection *c = ctx;
    if (size && count > SIZE_MAX / size)
        return 0;
    size_t n = size * count;
    if (n > SL_REMOTE_FRAME_MAX - c->received)
        return 0;
    memcpy(c->receive + c->received, data, n);
    c->received += n;
    return n;
}
static bool setup_easy(sl_remote_connection *c, const char *url, bool tls_only) {
    c->easy = curl_easy_init();
    if (!c->easy)
        return false;
    /* Local shutdown/resource policy, not constants recovered from Valve.
     * HTTP/1.1 is required for our RFC6455 Upgrade over CONNECT_ONLY TLS. */
#define SET(option, value)                                                                         \
    do {                                                                                           \
        if (curl_easy_setopt(c->easy, option, value) != CURLE_OK)                                  \
            return false;                                                                          \
    } while (0)
    SET(CURLOPT_URL, url);
    SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    SET(CURLOPT_TIMEOUT_MS, 20000L);
    SET(CURLOPT_SSL_VERIFYPEER, 1L);
    SET(CURLOPT_SSL_VERIFYHOST, 2L);
    SET(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    SET(CURLOPT_FOLLOWLOCATION, 0L);
    SET(CURLOPT_USERAGENT, "NSteamLink/0.3");
#if NSL_DIAGNOSTICS
    c->attempts_logged = 0;
    SET(CURLOPT_DEBUGFUNCTION, network_trace);
    SET(CURLOPT_DEBUGDATA, c);
    SET(CURLOPT_VERBOSE, 1L);
#endif
    if (tls_only)
        SET(CURLOPT_CONNECT_ONLY, 1L);
    else {
        SET(CURLOPT_WRITEFUNCTION, directory_write);
        SET(CURLOPT_WRITEDATA, c);
    }
#undef SET
    if (!sl_http_route_begin(&c->route, c->easy, url, 20000)) return false;
    if (c->route.count) c->deadline += SL_HTTP_ROUTE_BUDGET_MS - 20000;
    if (curl_multi_add_handle(c->multi, c->easy) != CURLM_OK)
        return false;
    c->easy_added = true;
    return true;
}
static bool parse_directory(sl_remote_connection *c) {
    jsmn_parser parser;
    jsmn_init(&parser);
    jsmntok_t tokens[4096];
    int count = jsmn_parse(&parser, (const char *)c->receive, c->received, tokens,
                           sizeof(tokens) / sizeof(tokens[0]));
    if (count < 1 || tokens[0].type != JSMN_OBJECT)
        return false;
    c->endpoint_count = c->endpoint_index = 0;
    for (int i = 1; i + 1 < count && c->endpoint_count < CM_LIMIT; ++i) {
        if (tokens[i].type != JSMN_STRING || tokens[i].end - tokens[i].start != 8 ||
            memcmp(c->receive + tokens[i].start, "endpoint", 8) ||
            tokens[i + 1].type != JSMN_STRING)
            continue;
        const uint8_t *p = c->receive + tokens[i + 1].start;
        size_t n = tokens[i + 1].end - tokens[i + 1].start;
        if (n < 5 || n >= sizeof(c->endpoints[0]) || memcmp(p + n - 4, ":443", 4))
            continue;
        bool valid = true;
        for (size_t j = 0; j < n - 4; ++j)
            if (!((p[j] >= 'a' && p[j] <= 'z') || (p[j] >= 'A' && p[j] <= 'Z') ||
                  (p[j] >= '0' && p[j] <= '9') || p[j] == '.' || p[j] == '-'))
                valid = false;
        if (!valid)
            continue;
        memcpy(c->endpoints[c->endpoint_count], p, n);
        c->endpoints[c->endpoint_count++][n] = 0;
    }
    return c->endpoint_count != 0;
}
static bool next_endpoint(sl_remote_connection *c, uint64_t now) {
    clear_easy(c);
    if (c->endpoint_index == c->endpoint_count)
        return false;
    char url[192];
    snprintf(url, sizeof(url), "https://%s/remoteplay/", c->endpoints[c->endpoint_index++]);
#if NSL_DIAGNOSTICS
    if (c->callbacks.diagnostic) {
        char line[192];
        snprintf(line, sizeof(line), "cloud_net event=candidate index=%zu/%zu endpoint=%s",
                 c->endpoint_index, c->endpoint_count, c->endpoints[c->endpoint_index - 1]);
        c->callbacks.diagnostic(line, c->ctx);
    }
#endif
    c->state = NET_TLS;
    c->deadline = now + 20000;
    return setup_easy(c, url, true);
}
static bool start_upgrade(sl_remote_connection *c, uint64_t now) {
    uint8_t nonce[16];
    char key[25], request[512];
    size_t length;
    if (IHS_CryptoRandomBytes(nonce, sizeof(nonce)) ||
        mbedtls_base64_encode((uint8_t *)key, sizeof(key), &length, nonce, sizeof(nonce)) ||
        length != 24)
        return false;
    key[24] = 0;
    if (!sl_ws_accept(key, c->expected))
        return false;
    int n = snprintf(
        request, sizeof(request),
        "GET /remoteplay/ HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
        c->endpoints[c->endpoint_index - 1], key);
    c->state = NET_UPGRADE;
    c->deadline = now + 20000;
    return n > 0 && (size_t)n < sizeof(request) && queue_raw(c, request, (size_t)n);
}
static bool drain_outgoing(sl_remote_connection *c) {
    for (unsigned budget = 0; c->count && budget < 8; ++budget) {
        struct outgoing *q = &c->fifo[c->head];
        size_t sent = 0;
        CURLcode result = curl_easy_send(c->easy, q->data + q->sent, q->size - q->sent, &sent);
        if (result == CURLE_AGAIN)
            return true;
        if (result != CURLE_OK || !sent) {
            network_event(c, "send_failed", result);
            if (c->callbacks.diagnostic)
                c->callbacks.diagnostic(curl_easy_strerror(result), c->ctx);
            return false;
        }
        q->sent += sent;
        if (q->sent != q->size)
            return true;
        erase_free(q->data, q->size);
        *q = (struct outgoing){0};
        c->head = (c->head + 1) % FIFO_LIMIT;
        --c->count;
    }
    return true;
}
static bool consume_frames(sl_remote_connection *c) {
    for (unsigned budget = 0; budget < 32; ++budget) {
        sl_ws_frame frame;
        int decoded = sl_ws_decode(c->receive, c->received, &frame);
        if (decoded <= 0)
            return decoded == 0;
        if (frame.opcode == 8) {
            if (c->callbacks.diagnostic)
                c->callbacks.diagnostic("cloud: peer closed WebSocket", c->ctx);
            return false;
        }
        if (frame.opcode == 9) {
            if (!queue_frame(c, 10, frame.payload, frame.size))
                return false;
        } else if (frame.opcode == 10 && c->awaiting_pong && frame.size == sizeof(c->ping) &&
                   !memcmp(frame.payload, c->ping, sizeof(c->ping))) {
            c->awaiting_pong = false;
        } else if (frame.opcode == 2 || frame.opcode == 0) {
            if ((frame.opcode == 0) != c->fragmented ||
                frame.size > SL_REMOTE_FRAME_MAX - c->message_size)
                return false;
            memcpy(c->message + c->message_size, frame.payload, frame.size);
            c->message_size += frame.size;
            c->fragmented = !frame.final;
            if (frame.final) {
                /* Malformed protobuf is dropped without tearing down a healthy
                 * WebSocket. Session creation failure has a separate state. */
                sl_remote_receive(c->protocol, c->message, c->message_size);
                memset(c->message, 0, c->message_size);
                c->message_size = 0;
            }
        }
        memmove(c->receive, c->receive + frame.consumed, c->received - frame.consumed);
        c->received -= frame.consumed;
    }
    return true;
}
static bool receive_bytes(sl_remote_connection *c, uint64_t now) {
    size_t available = SL_REMOTE_FRAME_MAX + 16384 - c->received;
    if (!available)
        return false;
    size_t received = 0;
    CURLcode result = curl_easy_recv(c->easy, c->receive + c->received, available, &received);
    if (result != CURLE_AGAIN) {
        if (result != CURLE_OK || !received) {
            network_event(c, "receive_failed", result);
            if (c->callbacks.diagnostic)
                c->callbacks.diagnostic(
                    result != CURLE_OK ? curl_easy_strerror(result) : "cloud: TLS EOF", c->ctx);
            return false;
        }
        c->received += received;
    }
    if (c->state == NET_UPGRADE) {
        size_t end = 0;
        for (size_t i = 0; i + 3 < c->received; ++i)
            if (!memcmp(c->receive + i, "\r\n\r\n", 4)) {
                end = i + 4;
                break;
            }
        if (!end)
            return c->received < 16384;
        if (!sl_ws_upgrade_valid(c->receive, end, c->expected))
            return false;
        memmove(c->receive, c->receive + end, c->received - end);
        c->received -= end;
        c->state = NET_WEBSOCKET;
        c->deadline = now + 20000;
        c->next_ping = now + 30000;
        if (!sl_remote_open(c->protocol))
            return false;
    }
    return consume_frames(c);
}
sl_remote_connection *sl_remote_connection_create(const IHS_ClientConfig *config,
                                                  const sl_remote_callbacks *cb, void *ctx) {
    if (!cb)
        return NULL;
    sl_remote_connection *c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->callbacks = *cb;
    c->ctx = ctx;
    c->receive = calloc(1, SL_REMOTE_FRAME_MAX + 16384);
    c->message = calloc(1, SL_REMOTE_FRAME_MAX);
    c->global = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
    if (c->global)
        c->multi = curl_multi_init();
    sl_remote_callbacks adapters = {.diagnostic = diagnostic,
                                    .send = send_binary,
                                    .connected = connected,
                                    .host = host,
                                    .offline = offline,
                                    .pair_code = pair_code,
                                    .save_key = save_key,
                                    .paired = paired,
                                    .pair_failed = pair_failed,
                                    .stream_result = stream_result,
                                    .transport_signal = transport_signal};
    /* Pointer presence selects the shared manager strategy. Standalone probes
     * and transport bridges must retain their NULL/legacy behavior. */
    adapters.disconnecting = cb->disconnecting ? disconnecting : NULL;
    adapters.begin_pairing = cb->begin_pairing ? begin_pairing : NULL;
    adapters.prepare_pairing = cb->prepare_pairing ? prepare_pairing : NULL;
    adapters.abort_pairing = cb->abort_pairing ? abort_pairing : NULL;
    adapters.control_packet = cb->control_packet ? control_packet : NULL;
    c->protocol = sl_remote_create(config, &adapters, c);
    if (!c->receive || !c->message || !c->multi || !c->protocol) {
        sl_remote_connection_destroy(c);
        return NULL;
    }
    return c;
}
sl_remote *sl_remote_connection_protocol(sl_remote_connection *c) {
    return c ? c->protocol : NULL;
}
void sl_remote_connection_update(sl_remote_connection *c, uint64_t now) {
    if (!c || c->suspended)
        return;
    if (c->state == NET_IDLE) {
        if (!c->bridge_mode && now < c->retry_at)
            return;
        c->state = NET_DIRECTORY;
        c->deadline = now + 20000;
        network_event(c, "directory_begin", -1);
        if (!setup_easy(c, directory_url, false)) {
            network_event(c, "setup_failed", CURLE_FAILED_INIT);
            fail_connection(c, now);
            return;
        }
    }
    if (c->state == NET_DIRECTORY || c->state == NET_TLS) {
        int running = 0;
        if (curl_multi_perform(c->multi, &running) != CURLM_OK) {
            network_event(c, "multi_failed", CURLE_FAILED_INIT);
            fail_connection(c, now);
            return;
        }
        int remaining;
        CURLMsg *msg;
        while ((msg = curl_multi_info_read(c->multi, &remaining))) {
            if (msg->msg != CURLMSG_DONE || msg->easy_handle != c->easy)
                continue;
            CURLcode result = msg->data.result;
            network_event(c, "transfer_done", result);
            /* DONE handles must leave the multi before changing RESOLVE and
             * re-adding. Do not reset the outer deadline on each candidate. */
            if (result != CURLE_OK) {
                curl_multi_remove_handle(c->multi, c->easy);
                c->easy_added = false;
            }
            if (sl_http_route_retry(&c->route, c->easy, result)) {
                if (curl_multi_add_handle(c->multi, c->easy) == CURLM_OK) {
                    c->easy_added = true;
                    break;
                }
                fail_connection(c, now);
                break;
            }
            if (c->state == NET_DIRECTORY) {
                long status_code = 0;
                curl_easy_getinfo(c->easy, CURLINFO_RESPONSE_CODE, &status_code);
                if (result != CURLE_OK || status_code != 200 || !parse_directory(c) ||
                    !next_endpoint(c, now))
                    fail_connection(c, now);
            } else if (result != CURLE_OK || !start_upgrade(c, now)) {
                if (!next_endpoint(c, now))
                    fail_connection(c, now);
            }
            break;
        }
    }
    if (c->state == NET_UPGRADE || c->state == NET_WEBSOCKET) {
        if (!drain_outgoing(c) || !receive_bytes(c, now) || sl_remote_failed(c->protocol)) {
            network_event(c, "stream_failed", -1);
            if (c->state == NET_UPGRADE && next_endpoint(c, now))
                return;
            fail_connection(c, now);
            return;
        }
        sl_remote_update(c->protocol, (int64_t)time(NULL));
        /* Provider liveness policy. This is RFC6455 ping/pong, independent of
         * streaming transport pings and not an inferred Valve timing constant. */
        if (c->state == NET_WEBSOCKET && sl_remote_ready(c->protocol)) {
            if (c->awaiting_pong && now >= c->pong_deadline) {
                if (c->callbacks.diagnostic)
                    c->callbacks.diagnostic("cloud: WebSocket pong timed out", c->ctx);
                fail_connection(c, now);
                return;
            }
            if (!c->awaiting_pong && now >= c->next_ping) {
                if (IHS_CryptoRandomBytes(c->ping, sizeof(c->ping)) ||
                    !queue_frame(c, 9, c->ping, sizeof(c->ping))) {
                    fail_connection(c, now);
                    return;
                }
                c->awaiting_pong = true;
                c->pong_deadline = now + 15000;
                c->next_ping = now + 30000;
            }
        }
    }
    if (c->state != NET_IDLE && now >= c->deadline && !sl_remote_ready(c->protocol)) {
        network_event(c, "deadline", CURLE_OPERATION_TIMEDOUT);
        fail_connection(c, now);
    }
}
void sl_remote_connection_set_bridge_mode(sl_remote_connection *c, bool enabled) {
    if (c)
        c->bridge_mode = enabled;
}
void sl_remote_connection_set_active(sl_remote_connection *c, bool active) {
    if (!c || c->suspended == !active)
        return;
    c->suspended = !active;
    if (!active) {
        clear_easy(c);
        sl_remote_close(c->protocol);
        c->state = NET_IDLE;
    } else {
        c->retry_at = 0;
    }
}
void sl_remote_connection_destroy(sl_remote_connection *c) {
    if (!c)
        return;
    /* No new worker: the runtime owner has stopped pumping before destruction. */
    if (c->receive && c->message)
        clear_easy(c);
    if (c->multi)
        curl_multi_cleanup(c->multi);
    sl_remote_destroy(c->protocol);
    erase_free(c->receive, SL_REMOTE_FRAME_MAX + 16384);
    erase_free(c->message, SL_REMOTE_FRAME_MAX);
    if (c->global)
        curl_global_cleanup();
    free(c);
}
