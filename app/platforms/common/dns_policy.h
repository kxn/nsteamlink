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
/* Owned result; sockets always closed before returning. FIFO admission waits
 * at most 48s (16 owners), then a batch has at most 3s of wire/resource time.
 * This blocking API belongs on a worker, never the runtime/render loop. */
bool sl_dns_policy_lookup(const char *host, sl_dns_refresh *result);
/* The caller owns context until return. Queue/wire bounds and global stop apply;
 * cancel is polled without blocking, allowing an owning DNS job to stop/join. */
bool sl_dns_policy_lookup_interruptible(const char *host, sl_dns_refresh *result,
                                       bool (*cancel)(void *), void *context);
bool sl_dns_policy_cancelled(void);
/* Dedupe and round-robin /24 groups; retain same-subnet fallback addresses. */
void sl_dns_policy_merge(sl_dns_refresh *out, const sl_dns_refresh *answers, unsigned count);
void sl_dns_policy_report(const char *);
