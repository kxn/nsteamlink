/* Include the production owner to test its async initialization boundary and
 * real SDK invalid-handle failure. No connection, HTTP request or Steam host. */
#include "../platforms/common/sns_backend.cpp"
#include <cassert>

int main() {
    SteamNetworkingSockets_SetManualPollMode(true);
    SteamNetworkingErrMsg error;
    SteamNetworkingIdentity identity;
    identity.SetLocalHost();
    assert(GameNetworkingSockets_Init(&identity, error));
    SteamNetworkingUtils()->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_None, nullptr);
    sl_sns *b = new sl_sns;
    b->sockets = SteamNetworkingSockets();
    auto queues = b->q;
    assert(!check_connection(b));
    assert(b->q->state == SL_SNS_CONNECTING && b->q->owner);
    assert(b->stats.terminal_source == SL_SNS_TERMINAL_NONE);
    // No connection was created. This handle cannot resolve in the real SDK.
    b->connection_attempted = true;
    b->connection = 1;
    const uint8_t byte = 1;
    assert(b->q->tx.push(&byte, 1, DATAGRAM_MAX));
    assert(b->q->rx.push(&byte, 1, DATAGRAM_MAX));
    assert(!check_connection(b));
    assert(!b->connection && b->q->state == SL_SNS_FAILED);
    assert(b->stats.terminal_source == SL_SNS_TERMINAL_CONNECTION_INFO);
    // Query invalidation keeps signaling ownership until explicit destruction;
    // the old unconditional close_backend would already have unlinked it.
    assert(b->q->owner && b->q->tx.empty() && b->q->rx.empty());
    assert(wait_datagram(b, 0) == -1);
    assert(!send_datagram(b, &byte, 1));
    assert(!check_connection(b) && b->q->state == SL_SNS_FAILED);
    sl_sns_destroy(b);
    assert(!queues->owner && queues.use_count() == 1);
    GameNetworkingSockets_Kill();
    SteamNetworkingSockets_SetManualPollMode(false);
    puts("PASS SNS owner: pending config, real SDK invalidation, queue wake and explicit cleanup");
}
