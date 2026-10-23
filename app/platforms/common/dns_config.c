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
    /* Compatibility workaround, NOT recovered Valve policy (D-A097): observed
     * Steam CDN answers can ping yet fail TCP/TLS, and changing public DNS can
     * select a usable address. Query independent providers, not just mirrors
     * of one provider. No DHCP/system-cache fallback across Wi-Fi changes.
     * Provider-published addresses:
     * developers.google.com/speed/public-dns/docs/using
     * developers.cloudflare.com/1.1.1.1/ip-addresses/
     * docs.quad9.net/services/ ; www.alidns.com/
     * docs.dnspod.com/public-dns/public-dns-guide/
     * This does not prove DNS/MTU is the underlying fault. */
    static const char *const servers[SL_DNS_SERVERS] = {
        "8.8.8.8", "1.1.1.1", "9.9.9.9", "223.5.5.5", "119.29.29.29"};
    for (unsigned i = 0; i < SL_DNS_SERVERS; ++i) {
        out->servers[i].sin_family = AF_INET;
        out->servers[i].sin_port = htons(53);
        if (inet_pton(AF_INET, servers[i], &out->servers[i].sin_addr) != 1)
            return false;
    }
    out->count = SL_DNS_SERVERS;
    return true;
#else
    /* Other platforms keep their normal resolver. Tests supply explicit local
     * fixtures through the config seam, not an environment override. */
    return false;
#endif
}
