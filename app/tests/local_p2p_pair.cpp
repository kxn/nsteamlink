/* Compile with the prepared SDK's private include paths and layout macros.
 * In particular -UNDEBUG would change the SDK object ABI in a Release build.
 * This second-interface factory follows the actual SDK Init/Destroy source. */
#include "steamnetworkingsockets/clientlib/csteamnetworkingsockets.h"
#include "steamnetworkingsockets/clientlib/steamnetworkingsockets_p2p.h"
#include "steamnetworkingsockets/clientlib/steamnetworkingsockets_p2p_ice.h"
#include <steam/steamnetworkingcustomsignaling.h>
#include "local_p2p_pair.h"
#include "sdr_client.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <vector>

extern "C" void SteamNetworkingSockets_SetManualPollMode(bool);
extern "C" void SteamNetworkingSockets_Poll(int);
#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "local P2P check failed %s:%d: %s\n", __FILE__, __LINE__, #condition); \
    std::abort(); } } while (false)
using namespace SteamNetworkingSocketsLib;
namespace local_p2p {
struct Signal { unsigned target; std::vector<char> bytes; };
struct Pair {
    ISteamNetworkingSockets *peers[2]{};
    CSteamNetworkingSockets *second = nullptr;
    SteamNetworkingIdentity identities[2];
    HSteamNetConnection connections[2]{};
    HSteamListenSocket listener{};
    int relay = -1;
    std::vector<SteamNetworkingIPAddr> own_addresses;
    std::mutex queue_lock;
    std::deque<Signal> pending;
    std::atomic<unsigned> sent{0}, objects{0}, released{0};
    unsigned delivered = 0, accepted = 0;
};
class Signaling final : public ISteamNetworkingConnectionSignaling {
    Pair *pair;
    unsigned target;
public:
    Signaling(Pair *p, unsigned to) : pair(p), target(to) { ++pair->objects; }
    bool SendSignal(HSteamNetConnection, const SteamNetConnectionInfo_t &, const void *data, int size) override {
        CHECK(size > 0 && size <= 65536);
        std::lock_guard<std::mutex> lock(pair->queue_lock);
        CHECK(pair->pending.size() < 256);
        const char *bytes = static_cast<const char *>(data);
        pair->pending.push_back({target, {bytes, bytes+size}}); ++pair->sent;
        return true;
    }
    void Release() override { ++pair->released; delete this; }
};
class Context final : public ISteamNetworkingSignalingRecvContext {
    Pair *pair;
    unsigned local;
public:
    Context(Pair *p, unsigned n) : pair(p), local(n) {}
    ISteamNetworkingConnectionSignaling *OnConnectRequest(HSteamNetConnection conn,
            const SteamNetworkingIdentity &identity, int port) override {
        CHECK(local == 1 && identity == pair->identities[0] && port == 0 && !pair->connections[local]);
        pair->connections[local] = conn;
        CHECK(pair->peers[local]->AcceptConnection(conn) == k_EResultOK); ++pair->accepted;
        return new Signaling(pair, 1-local);
    }
    void SendRejectionSignal(const SteamNetworkingIdentity &, const void *, int) override {
        CHECK(false && "unexpected P2P rejection");
    }
};
Pair *create() {
    auto *p = new Pair;
    p->relay = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0); CHECK(p->relay >= 0);
    sockaddr_in address{}; address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(!bind(p->relay, reinterpret_cast<sockaddr *>(&address), sizeof(address)));
    socklen_t length = sizeof(address);
    CHECK(!getsockname(p->relay, reinterpret_cast<sockaddr *>(&address), &length));
    char config[512];
    std::snprintf(config, sizeof(config), "{\"success\":true,\"revision\":1,"
        "\"relay_public_key\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\","
        "\"pops\":{\"sin\":{\"relays\":[{\"ipv4\":\"127.0.0.1\",\"port_range\":[%u,%u]}]}}}",
        unsigned(ntohs(address.sin_port)), unsigned(ntohs(address.sin_port)));
    /* Only addresses belonging to this machine may pass the recovery test's
     * UDP egress guard. Do not grant arbitrary LAN/Internet destinations. */
    ifaddrs *interfaces = nullptr; CHECK(!getifaddrs(&interfaces));
    for (auto *it = interfaces; it; it = it->ifa_next) {
        if (!it->ifa_addr) continue;
        SteamNetworkingIPAddr own; own.Clear();
        if (it->ifa_addr->sa_family == AF_INET)
            own.SetIPv4(ntohl(reinterpret_cast<sockaddr_in *>(it->ifa_addr)->sin_addr.s_addr), 0);
        else if (it->ifa_addr->sa_family == AF_INET6)
            own.SetIPv6(reinterpret_cast<sockaddr_in6 *>(it->ifa_addr)->sin6_addr.s6_addr, 0);
        else continue;
        p->own_addresses.push_back(own);
    }
    freeifaddrs(interfaces);
    SteamNetworkingSockets_SetManualPollMode(true);
    p->identities[0].SetGenericString("fixture-client"); p->identities[1].SetGenericString("fixture-peer");
    SteamNetworkingErrMsg error;
    CHECK(GameNetworkingSockets_Init(&p->identities[0], error)); p->peers[0] = SteamNetworkingSockets();
    {
        SteamNetworkingGlobalLock lock("fixture second interface");
        p->second = new CSteamNetworkingSockets(static_cast<CSteamNetworkingUtils *>(SteamNetworkingUtils()));
        CHECK(p->second->BInitGameNetworkingSockets(&p->identities[1], error)); p->peers[1] = p->second;
    }
    CHECK(NSL_SDR_Configure(config, std::strlen(config)));
    CHECK(SteamNetworkingUtils()->SetGlobalConfigValueString(k_ESteamNetworkingConfig_P2P_STUN_ServerList, ""));
    CHECK(SteamNetworkingUtils()->SetGlobalConfigValueString(k_ESteamNetworkingConfig_P2P_TURN_ServerList, ""));
    return p;
}
void start(Pair *p) {
    CHECK(!p->listener && !p->connections[0]);
    /* Match production begin_connection's six options, including its 20s
     * initial timeout; keep the upstream crypto/authentication policy. */
    SteamNetworkingConfigValue_t options[6];
    options[0].SetInt32(k_ESteamNetworkingConfig_Unencrypted, 2);
    options[1].SetInt32(k_ESteamNetworkingConfig_P2P_Transport_ICE_Enable, 0x7fffffff);
    options[2].SetInt32(k_ESteamNetworkingConfig_SendRateMin, 104857600);
    options[3].SetInt32(k_ESteamNetworkingConfig_SendRateMax, 104857600);
    options[4].SetInt32(k_ESteamNetworkingConfig_TimeoutInitial, 20000);
    options[5].SetInt32(k_ESteamNetworkingConfig_P2P_Transport_ICE_Implementation, 1);
    p->listener = p->peers[1]->CreateListenSocketP2P(0, 6, options); CHECK(p->listener);
    p->connections[0] = p->peers[0]->ConnectP2PCustomSignaling(new Signaling(p,1), &p->identities[1], 0, 6, options);
    CHECK(p->connections[0]);
}
void poll(Pair *p) {
    SteamNetworkingSockets_Poll(0);
    for (;;) {
        Signal signal;
        {
            std::lock_guard<std::mutex> lock(p->queue_lock);
            if (p->pending.empty()) break;
            signal = std::move(p->pending.front()); p->pending.pop_front();
        }
        Context context(p, signal.target);
        CHECK(p->peers[signal.target]->ReceivedP2PCustomSignal(signal.bytes.data(),
            static_cast<int>(signal.bytes.size()), &context)); ++p->delivered;
    }
    for (auto *peer : p->peers) peer->RunCallbacks();
}
ISteamNetworkingSockets *sockets(Pair *p, unsigned peer) { CHECK(peer < 2); return p->peers[peer]; }
HSteamNetConnection connection(Pair *p, unsigned peer) { CHECK(peer < 2); return p->connections[peer]; }
void cold_waits(Pair *p, const long long *ages, long long *delays, size_t count) {
    SteamNetworkingGlobalLock global("fixture routing boundary");
    ConnectionScopeLock lock;
    auto *base = GetConnectionByHandle(p->connections[0], lock);
    auto *conn = base ? base->AsSteamNetworkConnectionP2P() : nullptr;
    CHECK(conn && conn->GetState() == k_ESteamNetworkingConnectionState_Connecting);
    for (size_t i = 0; i < count; ++i) {
        auto now = conn->GetTimeEnteredConnectionState() + ages[i];
        delays[i] = NSL_SDR_Wait(*conn, now) - now;
    }
}
void verify_selected_ice(Pair *p) {
    {
        SteamNetworkingGlobalLock global("fixture selected ICE transport");
        for (unsigned i = 0; i < 2; ++i) {
            ConnectionScopeLock lock;
            auto *base = GetConnectionByHandle(p->connections[i], lock);
            auto *conn = base ? base->AsSteamNetworkConnectionP2P() : nullptr;
            CHECK(conn && conn->GetState() == k_ESteamNetworkingConnectionState_Connected &&
                conn->m_pTransportICE && conn->m_pCurrentTransportP2P == conn->m_pTransportICE);
        }
    }
    for (unsigned i = 0; i < 2; ++i) {
        SteamNetConnectionInfo_t info{};
        CHECK(p->peers[i]->GetConnectionInfo(p->connections[i], &info) && info.m_identityRemote == p->identities[1-i]);
        CHECK((info.m_nFlags & k_nSteamNetworkConnectionInfoFlags_Unauthenticated) &&
            !(info.m_nFlags & (k_nSteamNetworkConnectionInfoFlags_LoopbackBuffers | k_nSteamNetworkConnectionInfoFlags_Relayed)));
    }
}
bool owns_target(const Pair *p, const sockaddr *target) {
    if (!p || !target) return false;
    SteamNetworkingIPAddr address; address.Clear();
    if (target->sa_family == AF_INET)
        address.SetIPv4(ntohl(reinterpret_cast<const sockaddr_in *>(target)->sin_addr.s_addr), 0);
    else if (target->sa_family == AF_INET6)
        address.SetIPv6(reinterpret_cast<const sockaddr_in6 *>(target)->sin6_addr.s6_addr, 0);
    else return false;
    for (const auto &own : p->own_addresses) if (address == own) return true;
    return false;
}
Counts destroy(Pair *p) {
    for (unsigned i = 0; i < 2; ++i)
        if (p->connections[i]) CHECK(p->peers[i]->CloseConnection(p->connections[i], 0, nullptr, false));
    if (p->listener) CHECK(p->peers[1]->CloseListenSocket(p->listener));
    { SteamNetworkingGlobalLock lock("fixture destroy second interface"); p->second->Destroy(); }
    GameNetworkingSockets_Kill(); SteamNetworkingSockets_SetManualPollMode(false);
    CHECK(p->objects.load() == p->released.load() && !close(p->relay));
    Counts counts{p->sent.load(),p->delivered,p->objects.load(),p->released.load(),p->accepted};
    delete p; return counts;
}
}
