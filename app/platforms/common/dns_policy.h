#pragma once
#include "dns_refresh.h"
#include <stdbool.h>
#include <stdint.h>
/* Switch's process-wide name-resolution policy. No added worker or cache.
 * Calls run on the existing resolving worker; all waits are cancellable. */
bool sl_dns_policy_init(void (*diagnostic)(const char *));
void sl_dns_policy_stop_all(void);
bool sl_dns_policy_shutdown(void); /* After all callers have joined. */
void sl_dns_policy_begin(uint32_t token);
void sl_dns_policy_end(uint32_t token);
void sl_dns_policy_cancel(uint32_t token);
/* Owned result; sockets always closed before returning. At most 3 seconds. */
bool sl_dns_policy_lookup(const char *host, sl_dns_refresh *result);
void sl_dns_policy_report(const char *);
