#pragma once
/* Test-only local peer. Real prepared SDK/signaling/ICE; no Valve identity,
 * external STUN/relay or NAT. Private SDK types stay in its matching-build TU. */
#include <steam/steamnetworkingsockets.h>
#include <cstddef>
#include <sys/socket.h>
namespace local_p2p {
struct Pair;
struct Counts { unsigned signals, delivered, objects, released, accepted; };
Pair *create();
void start(Pair *);
void poll(Pair *);
ISteamNetworkingSockets *sockets(Pair *, unsigned peer);
HSteamNetConnection connection(Pair *, unsigned peer);
void cold_waits(Pair *, const long long *ages, long long *delays, size_t count);
void verify_selected_ice(Pair *);
bool owns_target(const Pair *, const sockaddr *);
Counts destroy(Pair *);
}
