/* Include the production owner to test its async initialization boundary and
 * real SDK invalid-handle failure. No connection, HTTP request or Steam host. */
#include "../platforms/common/sns_backend.cpp"
#include <cassert>
extern "C" {
#include <ihslib/session.h>
}
#include <thread>

static std::atomic<bool> ihs_initialized{false};
static std::atomic<unsigned> ihs_finalized{0};
static void initialized(IHS_Session *, void *) { ihs_initialized = true; }
static void finalized(IHS_Session *, void *) { ++ihs_finalized; }

int main() {
    IHS_Init();
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
    assert(!sl_sns_session_ready(b));
    assert(b->q->state == SL_SNS_CONNECTING && b->q->owner);
    assert(b->stats.terminal_source == SL_SNS_TERMINAL_NONE);
    // Config completion admits IHS even before the first SDK handle exists.
    b->config_ready = true;
    assert(sl_sns_session_ready(b));
    assert(wait_datagram(b, 1000) == 0);
    uint8_t receive[32]; size_t received = 0;
    assert(receive_datagram(b, receive, sizeof(receive), &received, 0) == 0);
    uint8_t secret[32] = {};
    IHS_ClientConfig config{}; config.deviceId = 42; config.secretKey = secret;
    IHS_SessionInfo info{}; info.sessionKeyLen = 32;
    assert(IHS_IPAddressFromString(&info.address.ip, "127.0.0.1"));
    IHS_Session *session = IHS_SessionCreate(&config, &info);
    assert(session && IHS_SessionSetDatagramTransport(session, sl_sns_datagram_transport(), b));
    IHS_StreamSessionCallbacks callbacks{};
    callbacks.initialized = initialized; callbacks.finalized = finalized;
    IHS_SessionSetSessionCallbacks(session, &callbacks, nullptr);
    assert(IHS_SessionConnect(session));
    auto deadline = std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while (!ihs_initialized) {
        assert(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    assert(!ihs_finalized && IHS_SessionIsConnectionPending(session));
    assert(!b->connection_attempted && !b->connection);
    // No connection was created. This handle cannot resolve in the real SDK.
    b->connection_attempted = true;
    b->connection = 1;
    const uint8_t byte = 1;
    {
        std::lock_guard<std::mutex> lock(b->q->mutex);
        assert(b->q->tx.push(&byte, 1, DATAGRAM_MAX));
        assert(b->q->rx.push(&byte, 1, DATAGRAM_MAX));
    }
    assert(!check_connection(b));
    assert(!b->connection && b->q->state == SL_SNS_FAILED);
    assert(!sl_sns_session_ready(b));
    IHS_SessionThreadedJoin(session);
    assert(ihs_finalized == 1 && !IHS_SessionIsConnectionPending(session));
    IHS_SessionDestroy(session);
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
    IHS_Quit();
    puts("PASS SNS owner: pending config/SDK route with real IHS worker, real SDK invalidation, queue wake and joined cleanup");
}
