#pragma once
#include <stddef.h>
class CMsgSteamNetworkingP2PRendezvous;
namespace SteamNetworkingSocketsLib {
class CSteamNetworkConnectionP2P;
bool NSL_SDR_Configure(const char *json, size_t size);
bool NSL_SDR_Init(CSteamNetworkConnectionP2P &, char *error);
void NSL_SDR_Populate(CSteamNetworkConnectionP2P &, CMsgSteamNetworkingP2PRendezvous &, long long now);
void NSL_SDR_Process(CSteamNetworkConnectionP2P &, const CMsgSteamNetworkingP2PRendezvous &, long long now);
long long NSL_SDR_Wait(CSteamNetworkConnectionP2P &, long long now);
}
