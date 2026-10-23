#pragma once
#include "dns_refresh.h"
#include <curl/curl.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Serialized process-wide curl lifetime; release only after all owned handles
 * and resolving workers have stopped. The last owner performs global cleanup. */
bool sl_http_global_acquire(void);
void sl_http_global_release(void);

/* Local compatibility policy, not Steam retry policy. No cross-network cache. Owners
 * call begin on their network worker, retry only after CURLMSG_DONE/removal,
 * and clear AFTER easy_cleanup (curl borrows the RESOLVE list). */
typedef struct {
    char host[254], addresses[SL_DNS_ADDRESSES_SIZE];
    unsigned port, index, count;
    long timeout_ms;
    CURLcode error, failure; /* Preparation failure is still an HTTP completion to SNS. */
    bool select_pending;
    uint64_t deadline;
    struct curl_slist *resolve;
    struct sl_http_dns *dns; /* Subscription to joinable in-flight DNS; never accesses CURL. */
} sl_http_route;
/* DNS waiting and all candidate attempts share one request-wide deadline. */
#define SL_HTTP_ROUTE_BUDGET_MS 90000
bool sl_http_route_begin(sl_http_route *, CURL *, const char *url, long timeout_ms);
/* Polled owners must use the async form: begin/poll never wait for DNS. */
bool sl_http_route_begin_async(sl_http_route *, CURL *, const char *url, long timeout_ms);
int sl_http_route_poll(sl_http_route *, CURL *); /* 0=pending, 1=ready, -1=error */
/* true means the failed request may continue; poll MUST return ready before
 * re-adding to multi. It may be waiting for an as-yet-unanswered provider. */
bool sl_http_route_retry(sl_http_route *, CURL *, CURLcode);
/* Shared transport/response boundary for serial requests and bootstrap racing. */
bool sl_http_route_transport_failure(CURL *, CURLcode);
/* Once connected, cancel/join remaining DNS without invalidating RESOLVE/TLS. */
void sl_http_route_stop_resolving(sl_http_route *);
void sl_http_route_clear(sl_http_route *);
/* Same retry policy for existing blocking asset/update workers. */
CURLcode sl_http_route_perform(CURL *, const char *url, long timeout_ms);
#ifdef __cplusplus
}
#endif
