#include "http_route.h"
#include "platform/application.h"
#include <assert.h>
#include <ihslib/client.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
static atomic_uint clients, attempts;
bool __wrap_sl_http_global_acquire(void) {
    ++attempts;
    return false;
}
IHS_Client *__real_IHS_ClientCreatePolled(const IHS_ClientConfig *);
IHS_Client *__wrap_IHS_ClientCreatePolled(const IHS_ClientConfig *config) {
    IHS_Client *client = __real_IHS_ClientCreatePolled(config);
    if (client)
        ++clients;
    return client;
}
int main(int argc, char **argv) {
    assert(argc == 2 && !setenv("NSL_DATA_DIR", argv[1], 1));
    assert(!setenv("SDL_VIDEODRIVER", "dummy", 1) && !setenv("SDL_AUDIODRIVER", "dummy", 1));
    assert(!setenv("SDL_RENDER_DRIVER", "software", 1));
    char *args[] = {"nsteamlink", "--frames", "40", NULL};
    for (unsigned i = 0; i < 2; ++i) {
        assert(sl_application_run(3, args) == 0);
        assert(clients == i + 1); // Real local IHS client, despite ALL HTTPS owners failing.
    }
    assert(attempts >= 2);
    puts("PASS two complete application launches with failed HTTPS initialization and live local "
         "discovery");
}
