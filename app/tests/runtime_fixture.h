#pragma once
#include "services/auth_store.h"
/* Main-thread-only private fixture configuration. Never linked by the product. */
bool sl_runtime_fixture_prepare(const char *directory, const sl_auth_store *store,
                                const char *lan_host, bool sdr_only);
int sl_runtime_fixture_result(void);
void sl_runtime_fixture_cloud_reconnect(void);
