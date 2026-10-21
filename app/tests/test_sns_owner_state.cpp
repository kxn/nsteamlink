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

static void sdk_receive_error() {
    SteamNetworkingSockets_SetManualPollMode(true);
    sl_sns *b = new sl_sns;
    b->sockets = SteamNetworkingSockets();
    b->connection = 1; // Real SDK has no such connection, so Receive returns -1.
    b->connection_attempted = b->config_ready = b->initialized = true;
    b->q->state = SL_SNS_CONNECTED;
    b->last_check = SteamNetworkingUtils()->GetLocalTimestamp();
    uint8_t byte = 37, data = 0; size_t size = 0;
    assert(b->q->rx.push(&byte, 1, DATAGRAM_MAX));
    // CheckConnection is still inside its original one-second throttle.
    sl_sns_update(b, 0);
    assert(b->connection == 1 && b->q->state == SL_SNS_CONNECTED && b->q->owner);
    assert(b->stats.terminal_source == SL_SNS_TERMINAL_NONE);
    assert(receive_datagram(b, &data, 1, &size, 0) == 1 && data == byte && size == 1);
    // A subsequent connection check, not the negative SDK receive, retires it.
    b->last_check -= 1000001;
    assert(!check_connection(b) && b->q->state == SL_SNS_FAILED && !b->connection);
    assert(b->stats.terminal_source == SL_SNS_TERMINAL_CONNECTION_INFO);
    b->initialized = false; // SDK initialization is owned by main for its pipe tests.
    sl_sns_destroy(b);
}

static void udp_fragmented_message() {
    // Real SDK SNP over kernel UDP loopback; no Steam host or remote network.
    SteamNetworkingSockets_SetManualPollMode(true);
    auto sockets = SteamNetworkingSockets();
    HSteamNetConnection local, peer;
    assert(sockets->CreateSocketPair(&local, &peer, true, nullptr, nullptr));
    sl_sns *b = new sl_sns;
    b->sockets = sockets; b->connection = local;
    b->q->state = SL_SNS_CONNECTED;
    int data_mtu = sl_sns_set_mtu(b, 576);
    assert(data_mtu > 0 && data_mtu < 1472);
    assert(SteamNetworkingUtils()->SetConnectionConfigValueInt32(peer,
        k_ESteamNetworkingConfig_MTU_PacketSize, 576));
    std::vector<uint8_t> bytes(1472);
    for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = uint8_t(i*17+13);
    assert(send_datagram(b, bytes.data(), bytes.size()));
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    SteamNetworkingMessage_t *message = nullptr;
    while (!message) {
        assert(std::chrono::steady_clock::now() < deadline);
        SteamNetworkingSockets_Poll(0);
        assert(sockets->ReceiveMessagesOnConnection(peer, &message, 1) >= 0);
        if (!message) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(message->m_cbSize == 1472 && !memcmp(message->m_pData, bytes.data(), bytes.size()));
    message->Release();
    // Reverse direction exercises production SDK drain and receive callback.
    assert(sockets->SendMessageToConnection(peer, bytes.data(), bytes.size(), 0x15, nullptr) == k_EResultOK);
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (b->q->rx.empty()) {
        assert(std::chrono::steady_clock::now() < deadline);
        SteamNetworkingSockets_Poll(0);
        assert(receive_messages(b, sockets));
        if (b->q->rx.empty()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::vector<uint8_t> result(1472); size_t received = 0;
    assert(receive_datagram(b, result.data(), result.size(), &received, 0) == 1);
    assert(received == bytes.size() && result == bytes);
    sl_sns_destroy(b);
    assert(sockets->CloseConnection(peer, 1001, "test complete", false));
}

static void production_io() {
    // Entirely in-process SDK pipe. No UDP, CM, Steam host or authorization.
    for (unsigned launch = 0; launch < 2; ++launch) {
        SteamNetworkingSockets_SetManualPollMode(true);
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
        if (!launch)
            close_backend(b, SL_SNS_CLOSED, SL_SNS_TERMINAL_NONE, 0,
                nsl::SnsDestroyedReason, nsl::SnsDestroyedDebug);
        stop = true;
        sender.join();
        if (!launch) {
            assert(!b->connection && !b->q->owner && b->q->state == SL_SNS_CLOSED);
            errno = EMSGSIZE;
            assert(!send_datagram(b, data, sizeof(data)) && errno == EBADF);
        } else {
            // Execute the actual public destroy with a live handle. The test
            // externally owns SDK initialization, leaving the peer inspectable;
            // SDK Kill/identity lifetime is covered by sns_lifetime_owner.
            auto q = b->q;
            sl_sns_destroy(b);
            b = nullptr;
            assert(!q->owner && q->state == SL_SNS_CLOSED);
        }
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
    sdk_receive_error();
    udp_fragmented_message();
    production_io();
    GameNetworkingSockets_Kill();
    SteamNetworkingSockets_SetManualPollMode(false);
    IHS_Quit();
    puts("PASS SNS owner: real IHS worker/SDK invalidation; two SDK pipe send/parallel-check/close cycles, exact bytes and peer reason; joined cleanup");
}
