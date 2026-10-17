#include "dns_refresh.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#ifdef __SWITCH__
#include <switch.h>
#endif
bool sl_dns_current_config(sl_dns_config *out) {
    memset(out, 0, sizeof(*out));
#ifdef __SWITCH__
    if (R_FAILED(nifmInitialize(NifmServiceType_User)))
        return false;
    uint32_t mask, gateway, primary, secondary;
    Result result = nifmGetCurrentIpConfigInfo(&out->local, &mask, &gateway, &primary, &secondary);
    nifmExit();
    if (R_FAILED(result))
        return false;
    const uint32_t servers[] = {primary, secondary};
    for (unsigned i = 0; i < 2; ++i) {
        if (!servers[i] || (i && servers[i] == servers[0]))
            continue;
        struct sockaddr_in *address = &out->servers[out->count++];
        address->sin_family = AF_INET;
        address->sin_port = htons(53);
        address->sin_addr.s_addr = servers[i];
    }
    return out->count != 0;
#else
    /* Other platforms keep their normal resolver. Tests supply explicit local
     * fixtures through the config seam, not an environment override. */
    return false;
#endif
}
