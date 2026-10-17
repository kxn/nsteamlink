#include "steamnetworkingsockets/clientlib/steamnetworkingsockets_lowlevel.h"
#include <switch.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

namespace SteamNetworkingSocketsLib {
/* Horizon supplies IPv4 UDP sockets, not AF_LOCAL socketpair. Both ends are
 * bound and connected before publication; SDK shutdown owns their close. */
int NSL_GNS_WakePair(int out[2]) {
    int sockets[2] = {-1, -1};
    sockaddr_in addresses[2] = {};
    for (int i = 0; i < 2; ++i) {
        sockets[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sockets[i] < 0)
            goto fail;
        addresses[i].sin_family = AF_INET;
        addresses[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(sockets[i], reinterpret_cast<sockaddr *>(&addresses[i]), sizeof(sockaddr_in)))
            goto fail;
        socklen_t size = sizeof(sockaddr_in);
        if (getsockname(sockets[i], reinterpret_cast<sockaddr *>(&addresses[i]), &size))
            goto fail;
    }
    for (int i = 0; i < 2; ++i)
        if (connect(sockets[i], reinterpret_cast<sockaddr *>(&addresses[1 - i]), sizeof(sockaddr_in)))
            goto fail;
    out[0] = sockets[0];
    out[1] = sockets[1];
    return 0;
fail:
    int saved = errno;
    for (int fd : sockets)
        if (fd >= 0)
            close(fd);
    errno = saved;
    return -1;
}
bool NSL_GNS_LocalAddresses(CUtlVector<LocalAddress_t> *out) {
    if (R_FAILED(nifmInitialize(NifmServiceType_User)))
        return false;
    u32 address = 0, mask = 0, gateway = 0, dns1 = 0, dns2 = 0;
    Result result = nifmGetCurrentIpConfigInfo(&address, &mask, &gateway, &dns1, &dns2);
    nifmExit();
    if (R_FAILED(result) || !address)
        return false;
    LocalAddress_t entry;
    entry.m_addr.Clear();
    entry.m_addr.SetIPv4(ntohl(address), 0);
    entry.m_nPrefixLen = __builtin_popcount(mask);
    out->AddToTail(entry);
    return true;
}
}
