/* Test-only SDK network-loopback bridge. CreateSocketPair(true) uses real UDP,
 * SNP and crypto, but starts connected with localhost identities. It does not
 * execute ConnectP2PCustomSignaling, certificates from Valve, ICE or SDR. */
extern "C" {
#include "sns_backend.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
bool loopback_sdk_session_live(void);
int __real_socket(int, int, int);
ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
}
#include "sns_message_queue.h"
#include <steam/steamnetworkingsockets.h>
#include <steam/isteamnetworkingutils.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>

extern "C" void SteamNetworkingSockets_SetManualPollMode(bool);
extern "C" void SteamNetworkingSockets_Poll(int);
namespace {
thread_local unsigned sdk_scope;
struct Scope { Scope() { ++sdk_scope; } ~Scope() { --sdk_scope; } };
struct Provider {
    std::thread::id owner = std::this_thread::get_id();
    int fd = -1;
    sockaddr_in peer{};
    HSteamNetConnection connections[2]{};
    std::atomic<bool> started{false};
    std::atomic<unsigned> calls{0}, sent{0}, received{0};
    std::mutex lock;
    std::condition_variable wake;
    nsl::SnsMessageQueue rx;
    int end_reason = 0;
};
unsigned creates, starts, destroys, total_sent, total_received, pairs, closed_pairs;
unsigned peer_forwarded, client_delivered;
bool joined = true;
Provider *provider(sl_sns *s) { return reinterpret_cast<Provider *>(s); }
const Provider *provider(const sl_sns *s) { return reinterpret_cast<const Provider *>(s); }
struct Callback {
    Provider *p;
    explicit Callback(Provider *value) : p(value) { ++p->calls; }
    ~Callback() { --p->calls; }
};
bool send_message(void *ctx, const uint8_t *bytes, size_t size) {
    auto *p = static_cast<Provider *>(ctx); Callback call(p);
    if (!p->started) return false;
    Scope scope;
    EResult result = SteamNetworkingSockets()->SendMessageToConnection(p->connections[0], bytes,
        static_cast<uint32>(size), k_nSteamNetworkingSend_UnreliableNoNagle, nullptr);
    if (result == k_EResultOK) ++p->sent;
    return result == k_EResultOK;
}
int wait_message(void *ctx, uint32_t us) {
    auto *p = static_cast<Provider *>(ctx); Callback call(p);
    std::unique_lock<std::mutex> lock(p->lock);
    p->wake.wait_for(lock, std::chrono::microseconds(us), [&] { return !p->rx.empty(); });
    return p->rx.empty() ? 0 : 1;
}
int receive_message(void *ctx, uint8_t *bytes, size_t capacity, size_t *size, uint32_t us) {
    (void)us; auto *p = static_cast<Provider *>(ctx); Callback call(p);
    std::lock_guard<std::mutex> lock(p->lock);
    if (p->rx.empty()) return 0;
    const auto &message = p->rx.front();
    if (message.size() > capacity) return -1;
    *size = message.size(); if (*size) std::memcpy(bytes, message.data(), *size);
    p->rx.pop(); ++p->received;
    return 1;
}
size_t next_size(void *ctx) {
    auto *p = static_cast<Provider *>(ctx); Callback call(p);
    std::lock_guard<std::mutex> lock(p->lock);
    return p->rx.empty() ? 0 : p->rx.front().size();
}
}
extern "C" bool loopback_sdk_allow_socket(void) { return sdk_scope != 0; }
extern "C" sl_sns *__wrap_sl_sns_create_configured(const IHS_ClientConfig *c,
    const sl_remote_material *m, bool share, char *error, size_t error_size,
    const char *config, size_t config_size) {
    (void)error; (void)error_size; (void)config; (void)config_size;
    assert(creates == destroys && c->deviceId == 1 && share && !loopback_sdk_session_live());
    assert(m->client_id == 7 && m->steam_id == UINT64_C(76561198000000001) && m->transport == 4 && m->key_size == 32);
    assert(!std::strcmp(m->cert, "controlled-test-certificate") && !std::strcmp(m->stun_servers, "stun:fixture.invalid:3478"));
    auto *p = new Provider;
    p->fd = __real_socket(AF_INET, SOCK_DGRAM, 0); assert(p->fd >= 0);
    sockaddr_in local{}; local.sin_family = AF_INET; local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(!bind(p->fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)));
    assert(!fcntl(p->fd, F_SETFL, O_NONBLOCK));
    p->peer = local; p->peer.sin_port = htons(m->port);
    Scope scope;
    SteamNetworkingSockets_SetManualPollMode(true);
    SteamNetworkingIdentity identity; identity.SetLocalHost();
    SteamNetworkingErrMsg detail;
    assert(GameNetworkingSockets_Init(&identity, detail));
    ++creates; return reinterpret_cast<sl_sns *>(p);
}
extern "C" bool __wrap_sl_sns_session_ready(const sl_sns *s) { assert(s); return true; }
extern "C" bool __wrap_sl_sns_start_session(sl_sns *s) {
    auto *p = provider(s); assert(p->owner == std::this_thread::get_id() && loopback_sdk_session_live());
    Scope scope;
    assert(!p->started && SteamNetworkingSockets()->CreateSocketPair(&p->connections[0], &p->connections[1], true, nullptr, nullptr));
    for (auto connection : p->connections) {
        SteamNetConnectionInfo_t info;
        assert(SteamNetworkingSockets()->GetConnectionInfo(connection, &info));
        assert(info.m_eState == k_ESteamNetworkingConnectionState_Connected &&
               info.m_addrRemote.IsLocalHost() && info.m_addrRemote.m_port != 0);
    }
    ++pairs; ++starts; p->started = true; return true;
}
extern "C" sl_sns_state __wrap_sl_sns_get_state(const sl_sns *s) {
    auto *p = const_cast<Provider *>(provider(s));
    assert(p->owner == std::this_thread::get_id());
    if (!p->started) return SL_SNS_CONNECTING;
    Scope scope; SteamNetConnectionInfo_t info;
    if (!SteamNetworkingSockets()->GetConnectionInfo(p->connections[0], &info)) return SL_SNS_CLOSED;
    p->end_reason = info.m_eEndReason;
    if (info.m_eState == k_ESteamNetworkingConnectionState_Connected) return SL_SNS_CONNECTED;
    if (info.m_eState == k_ESteamNetworkingConnectionState_ClosedByPeer) return SL_SNS_CLOSED;
    if (info.m_eState == k_ESteamNetworkingConnectionState_ProblemDetectedLocally) return SL_SNS_FAILED;
    return SL_SNS_CONNECTING;
}
extern "C" int __wrap_sl_sns_end_reason(const sl_sns *s) { return provider(s)->end_reason; }
extern "C" void __wrap_sl_sns_get_stats(const sl_sns *s, sl_sns_stats *out) {
    auto *p = provider(s); *out = sl_sns_stats{};
    if (p) {
        out->datagrams_sent = p->sent; out->datagrams_received = p->received;
        if (p->started) {
            Scope scope; SteamNetConnectionInfo_t info;
            if (SteamNetworkingSockets()->GetConnectionInfo(p->connections[0], &info)) out->sdk_state = info.m_eState;
        }
    }
    // No Valve identity authentication or relay route assertion.
}
extern "C" void __wrap_sl_sns_update(sl_sns *s, uint64_t now) {
    (void)now; auto *p = provider(s); assert(p->owner == std::this_thread::get_id());
    Scope scope;
    SteamNetworkingSockets_Poll(0); SteamNetworkingSockets()->RunCallbacks();
    if (!p->started) return;
    SteamNetworkingMessage_t *messages[32];
    int count;
    while ((count = SteamNetworkingSockets()->ReceiveMessagesOnConnection(p->connections[1], messages, 32)) > 0) {
        for (int i = 0; i < count; ++i) {
            auto *m = messages[i];
            assert(!(m->m_nFlags & k_nSteamNetworkingSend_Reliable));
            assert(__real_sendto(p->fd, m->m_pData, static_cast<size_t>(m->m_cbSize), MSG_DONTWAIT,
                reinterpret_cast<const sockaddr *>(&p->peer), sizeof(p->peer)) == m->m_cbSize);
            m->Release();
            ++peer_forwarded;
        }
    }
    assert(count == 0);
    uint8_t bytes[65536]; ssize_t size;
    while ((size = recv(p->fd, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_TRUNC)) >= 0) {
        assert(size <= ssize_t(sizeof(bytes)));
        assert(SteamNetworkingSockets()->SendMessageToConnection(p->connections[1], bytes,
            static_cast<uint32>(size), k_nSteamNetworkingSend_UnreliableNoNagle, nullptr) == k_EResultOK);
    }
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    SteamNetworkingSockets_Poll(0); SteamNetworkingSockets()->RunCallbacks();
    while ((count = SteamNetworkingSockets()->ReceiveMessagesOnConnection(p->connections[0], messages, 32)) > 0) {
        std::lock_guard<std::mutex> lock(p->lock);
        for (int i = 0; i < count; ++i) {
            auto *m = messages[i];
            assert(!(m->m_nFlags & k_nSteamNetworkingSend_Reliable));
            assert(p->rx.push(static_cast<const uint8_t *>(m->m_pData), static_cast<size_t>(m->m_cbSize), k_cbMaxSteamNetworkingSocketsMessageSizeSend));
            m->Release();
            ++client_delivered;
        }
        p->wake.notify_all();
    }
    assert(count == 0);
}
extern "C" const IHS_DatagramTransport *__wrap_sl_sns_datagram_transport(void) {
    static const IHS_DatagramTransport transport{send_message, receive_message, wait_message,
        k_cbMaxSteamNetworkingSocketsMessageSizeSend, next_size};
    return &transport;
}
extern "C" void __wrap_sl_sns_destroy(sl_sns *s) {
    if (!s) return;
    auto *p = provider(s); assert(p->owner == std::this_thread::get_id() && !loopback_sdk_session_live());
    joined &= p->calls == 0; total_sent += p->sent; total_received += p->received;
    Scope scope;
    for (auto connection : p->connections)
        if (connection) assert(SteamNetworkingSockets()->CloseConnection(connection, 0, nullptr, false));
    if (p->started) ++closed_pairs;
    SteamNetworkingSockets_Poll(0); GameNetworkingSockets_Kill();
    SteamNetworkingSockets_SetManualPollMode(false);
    assert(!close(p->fd)); delete p; ++destroys;
}
extern "C" void loopback_sdk_counts(unsigned out[10]) {
    unsigned counts[] = {creates,starts,destroys,total_sent,total_received,unsigned(joined),pairs,closed_pairs,peer_forwarded,client_delivered};
    std::memcpy(out, counts, sizeof(counts));
}
