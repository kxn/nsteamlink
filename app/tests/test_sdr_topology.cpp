#include <steam/steamnetworkingsockets.h>
#include <cstdio>
extern "C" {
#include "sdr_probe.h"
void SteamNetworkingSockets_SetManualPollMode(bool);
}
int main() {
    SteamNetworkingErrMsg error;
    SteamNetworkingSockets_SetManualPollMode(true);
    if (!GameNetworkingSockets_Init(nullptr,error)) {
        SteamNetworkingSockets_SetManualPollMode(false);
        std::fprintf(stderr,"SDK initialization failed\n");
        return 1;
    }
    int stage=sl_gns_sdr_topology_fixture();
    GameNetworkingSockets_Kill();
    SteamNetworkingSockets_SetManualPollMode(false);
    std::printf("SDR_TOPOLOGY_FIXTURE stage=%d\n",stage);
    return stage ? 1 : 0;
}
