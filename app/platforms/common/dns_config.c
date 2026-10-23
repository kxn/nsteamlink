#include "dns_refresh.h"
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#ifdef __SWITCH__
#include <switch.h>
#endif
bool sl_dns_current_config(sl_dns_config *out) {
    memset(out, 0, sizeof(*out));
#ifdef __SWITCH__
    out->platform_error = nifmInitialize(NifmServiceType_User);
    if (R_FAILED(out->platform_error))
        return false;
    uint32_t mask, gateway, primary, secondary;
    Result result = nifmGetCurrentIpConfigInfo(&out->local, &mask, &gateway, &primary, &secondary);
    nifmExit();
    out->platform_error = result;
    if (R_FAILED(result))
        return false;
    /* User-requested resolver experiment (D-A095). Keep reading the current
     * interface above, but use one resolver for every wrapped hostname lookup.
     * A failed query must not silently fall back to DHCP/system DNS. */
    struct sockaddr_in *address = &out->servers[0];
    address->sin_family = AF_INET;
    address->sin_port = htons(53);
    if (inet_pton(AF_INET, "8.8.8.8", &address->sin_addr) != 1)
        return false;
    out->count = 1;
    return true;
#else
    /* Other platforms keep their normal resolver. Tests supply explicit local
     * fixtures through the config seam, not an environment override. */
    return false;
#endif
}
