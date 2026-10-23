#include "steamnetworkingsockets/clientlib/steamnetworkingsockets_lowlevel.h"
#include <switch.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

namespace SteamNetworkingSocketsLib {
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
