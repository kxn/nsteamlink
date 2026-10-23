#pragma once
#include "dns_refresh.h"
#include <curl/curl.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Local compatibility policy, not Steam retry policy. No threads/cache. Owners
 * call begin on their network worker, retry only after CURLMSG_DONE/removal,
 * and clear AFTER easy_cleanup (curl borrows the RESOLVE list). */
typedef struct {
    char host[254], addresses[SL_DNS_ADDRESSES_SIZE];
    unsigned port, index, count;
    long timeout_ms;
    CURLcode error; /* Preparation failure is still an HTTP completion to SNS. */
    uint64_t deadline;
    struct curl_slist *resolve;
} sl_http_route;
/* Allow all 20 candidates a 4s TCP/TLS attempt plus the DNS collection. */
#define SL_HTTP_ROUTE_BUDGET_MS 90000
bool sl_http_route_begin(sl_http_route *, CURL *, const char *url, long timeout_ms);
bool sl_http_route_retry(sl_http_route *, CURL *, CURLcode);
void sl_http_route_clear(sl_http_route *);
/* Same retry policy for existing blocking asset/update workers. */
CURLcode sl_http_route_perform(CURL *, const char *url, long timeout_ms);
#ifdef __cplusplus
}
#endif
