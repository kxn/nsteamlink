#pragma once
#include <steam/steamnetworkingsockets.h>

namespace nsl {
/* Original BWait 0x800150..0x8001c4: count < 1 ends the batch, including
 * SDK errors. It neither changes connection state nor discards queued data.
 * Consumer owns/releases every message in each positive batch and returns
 * false only for a local resource limit. Poll/connection checks are separate. */
template<class Sockets, class Consume>
bool PumpSnsReceive(Sockets *sockets, HSteamNetConnection handle, Consume consume) {
    if (!handle) return true;
    SteamNetworkingMessage_t *messages[128];
    for (;;) {
        int count = sockets->ReceiveMessagesOnConnection(handle, messages, 128);
        if (count < 1) return true;
        if (!consume(messages, count)) return false;
        if (count < 128) return true;
    }
}
}
