/* Actual CM RPC protocol -> manager -> SDR material -> external datagram IHS
 * -> application/media recovery. CM service and SDK route/preparation are
 * explicit local providers, not real Valve DNS/TLS/certificate/SDR/NAT proof. */
#define NSL_RECOVERY_MANAGER 1
#define NSL_RECOVERY_CLOUD 1
#include "application_recovery_runtime.c"
#include "cloud_recovery_provider.h"
