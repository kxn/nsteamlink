#pragma once
#include "http_route.h"

typedef struct sl_http_bootstrap sl_http_bootstrap;
/* Only idempotent directory GET and pre-WebSocket TLS. Never application RPC,
 * pairing, open-stream or transport signals. One DNS plan, at most three live
 * TCP/TLS attempts, paced 250ms; each response has private bounded storage. */
typedef bool (*sl_http_bootstrap_options)(CURL *, bool tls_only, void *);
sl_http_bootstrap *sl_http_bootstrap_create(CURLM *, const char *url, bool tls_only,
                                            size_t body_limit, uint64_t now,
                                            sl_http_bootstrap_options, void *);
/* 0=pending, 1=completion (code may be error). On completion the caller takes
 * easy/route and body, and owns cleanup. A successful CONNECT_ONLY easy remains
 * attached to its original multi so send/recv work on curl 7.69. -1=factory or
 * request-wide failure, with no ownership transferred. */
int sl_http_bootstrap_poll(sl_http_bootstrap *, uint64_t now, CURL **, sl_http_route *,
                           uint8_t **body, size_t *size, CURLcode *code);
uint64_t sl_http_bootstrap_deadline(const sl_http_bootstrap *);
void sl_http_bootstrap_destroy(sl_http_bootstrap *);
