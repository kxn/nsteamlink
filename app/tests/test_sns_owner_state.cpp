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

static void production_io() {
    // Entirely in-process SDK pipe. No UDP, CM, Steam host or authorization.
    for (unsigned launch = 0; launch < 2; ++launch) {
        HSteamNetConnection local, peer;
        auto sockets = SteamNetworkingSockets();
        assert(sockets->CreateSocketPair(&local, &peer, false, nullptr, nullptr));
        sl_sns *b = new sl_sns;
        b->sockets = sockets;
        b->connection = local;
        b->connection_attempted = b->config_ready = true;
        b->q->state = SL_SNS_CONNECTED;
        uint8_t data[] = {0x85, 1, 12, 34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 9, 8, 7, 6};
        assert(send_datagram(b, data, sizeof(data)));
        sl_sns_stats stats;
        sl_sns_get_stats(b, &stats);
        assert(stats.datagrams_sent == 1);
        SteamNetworkingMessage_t *message = nullptr;
        for (unsigned attempt = 0; !message && attempt < 100; ++attempt) {
            SteamNetworkingSockets_Poll(0);
            assert(sockets->ReceiveMessagesOnConnection(peer, &message, 1) >= 0);
            if (!message) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        assert(message && message->m_cbSize == sizeof(data));
        assert(!memcmp(message->m_pData, data, sizeof(data)));
        message->Release();
        std::atomic<bool> stop{false}, started{false};
        std::thread sender([&] {
            while (!stop) {
                if (!send_datagram(b, data, sizeof(data)))
                    assert(errno == EAGAIN || errno == EBADF || errno == EIO);
                started = true;
                std::this_thread::yield();
            }
        });
        while (!started) std::this_thread::yield();
        for (unsigned n = 0; n < 20; ++n) {
            assert(check_connection(b));
            assert(b->q->state == SL_SNS_CONNECTED);
            sl_sns_get_stats(b, &stats);
            assert(stats.datagrams_sent >= 1);
        }
        // Closing serializes with send, including SDK signaling callbacks;
        // context destruction still follows the producer join.
        close_backend(b, SL_SNS_CLOSED, SL_SNS_TERMINAL_NONE, 0,
            nsl::SnsDestroyedReason, nsl::SnsDestroyedDebug);
        stop = true;
        sender.join();
        assert(!b->connection && !b->q->owner && b->q->state == SL_SNS_CLOSED);
        errno = EMSGSIZE;
        assert(!send_datagram(b, data, sizeof(data)) && errno == EBADF);
        SteamNetConnectionInfo_t info{};
        assert(sockets->GetConnectionInfo(peer, &info));
        assert(info.m_eState == k_ESteamNetworkingConnectionState_ClosedByPeer);
        assert(info.m_eEndReason == 1001 && !strcmp(info.m_szEndDebug, "Destroyed"));
        assert(sockets->CloseConnection(peer, 1001, "test complete", false));
        sl_sns_destroy(b);
    }
}

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
    {
        std::lock_guard<std::mutex> lock(b->connection_mutex);
        b->connection = 1;
        b->q->state = SL_SNS_CONNECTED;
    }
    const uint8_t byte = 1;
    errno = EAGAIN;
    assert(!send_datagram(b, &byte, 1) && errno == EBADF);
    assert(b->connection == 1 && b->q->state == SL_SNS_CONNECTED);
    assert(b->stats.terminal_source == SL_SNS_TERMINAL_NONE);
    {
        std::lock_guard<std::mutex> lock(b->q->mutex);
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
    assert(b->q->owner && b->q->rx.empty());
    assert(wait_datagram(b, 0) == -1);
    assert(!send_datagram(b, &byte, 1));
    assert(!check_connection(b) && b->q->state == SL_SNS_FAILED);
    sl_sns_destroy(b);
    assert(!queues->owner && queues.use_count() == 1);
    production_io();
    GameNetworkingSockets_Kill();
    SteamNetworkingSockets_SetManualPollMode(false);
    IHS_Quit();
    puts("PASS SNS owner: real IHS worker/SDK invalidation; two SDK pipe send/parallel-check/close cycles, exact bytes and peer reason; joined cleanup");
}
