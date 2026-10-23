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
/* Owned result; sockets always closed before returning. Per-provider FIFO
 * admission, five live queries globally, paced starts 25ms apart. Each provider
 * has 3s wire/resource time; queue + collection has a separate 51s safety bound.
 * This blocking API belongs on a worker, never the runtime/render loop. */
bool sl_dns_policy_lookup(const char *host, sl_dns_refresh *result);
/* The caller owns context until return. Queue/wire bounds and global stop apply;
 * cancel is polled without blocking, allowing an owning DNS job to stop/join. */
bool sl_dns_policy_lookup_interruptible(const char *host, sl_dns_refresh *result,
                                       bool (*cancel)(void *), void *context);
/* Publish each newly accepted provider immediately on the resolving worker.
 * The callback must copy the answer and return promptly; it must not use CURL.
 * Result and context remain owned by the caller until return. */
bool sl_dns_policy_lookup_progressive(const char *host, sl_dns_refresh *result,
                                     bool (*cancel)(void *), void *context,
                                     void (*publish)(const sl_dns_refresh *, void *));
bool sl_dns_policy_cancelled(void);
/* Dedupe and round-robin /24 groups; retain same-subnet fallback addresses. */
void sl_dns_policy_merge(sl_dns_refresh *out, const sl_dns_refresh *answers, unsigned count);
void sl_dns_policy_report(const char *);
