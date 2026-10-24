/* Actual patched SDK custom-signaling/ICE fixture. Synthetic unsigned generic
 * identities and an owned, silent local relay are explicit inputs. No Valve
 * authentication, external STUN/relay, CM service or NAT is claimed here.
 * The private second-interface factory mirrors SDK Init/Destroy; compile it
 * against the *prepared* SDK with identical definitions and private headers. */
#include "steamnetworkingsockets/clientlib/csteamnetworkingsockets.h"
#include "steamnetworkingsockets/clientlib/steamnetworkingsockets_p2p.h"
#include "steamnetworkingsockets/clientlib/steamnetworkingsockets_p2p_ice.h"
#include <steam/steamnetworkingsockets.h>
#include <steam/steamnetworkingcustomsignaling.h>
#include "sdr_client.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <atomic>
#include <cstdlib>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

extern "C" void SteamNetworkingSockets_SetManualPollMode(bool);
extern "C" void SteamNetworkingSockets_Poll(int);
// Private SDK object layout depends on its release/debug macros. Keep NDEBUG
// exactly as on GameNetworkingSockets_s; these checks must remain active even
// in Release rather than compiling this TU with -UNDEBUG.
#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #condition); \
    std::abort(); } } while (false)
using namespace SteamNetworkingSocketsLib;
namespace {
struct Signal { unsigned target; std::vector<char> bytes; };
std::mutex queue_lock;
std::deque<Signal> pending;
std::atomic<unsigned> sent{0}, created{0}, released{0};
unsigned delivered, accepted;
ISteamNetworkingSockets *peers[2];
SteamNetworkingIdentity identities[2];
HSteamNetConnection connections[2];
class Signaling final : public ISteamNetworkingConnectionSignaling {
    unsigned target;
public:
    explicit Signaling(unsigned to) : target(to) { ++created; }
    bool SendSignal(HSteamNetConnection, const SteamNetConnectionInfo_t &,
                    const void *data, int size) override {
        CHECK(size > 0 && size <= 65536);
        std::lock_guard<std::mutex> lock(queue_lock);
        CHECK(pending.size() < 256);
        const char *bytes = static_cast<const char *>(data);
        pending.push_back({target, {bytes, bytes + size}}); ++sent;
        return true;
    }
    void Release() override { ++released; delete this; }
};
class Context final : public ISteamNetworkingSignalingRecvContext {
    unsigned local;
public:
    explicit Context(unsigned n) : local(n) {}
    ISteamNetworkingConnectionSignaling *OnConnectRequest(HSteamNetConnection conn,
            const SteamNetworkingIdentity &identity, int port) override {
        CHECK(local == 1 && identity == identities[0] && port == 0 && !connections[local]);
        connections[local] = conn;
        CHECK(peers[local]->AcceptConnection(conn) == k_EResultOK); ++accepted;
        return new Signaling(1 - local);
    }
    void SendRejectionSignal(const SteamNetworkingIdentity &, const void *, int) override {
        CHECK(false && "unexpected P2P rejection");
    }
};
Context contexts[] = {Context(0), Context(1)};
void debug(ESteamNetworkingSocketsDebugOutputType, const char *text) {
    std::fprintf(stderr, "SDK %s\n", text);
}
void pump() {
    SteamNetworkingSockets_Poll(0);
    for (;;) {
        Signal signal;
        {
            std::lock_guard<std::mutex> lock(queue_lock);
            if (pending.empty()) break;
            signal = std::move(pending.front()); pending.pop_front();
        }
        CHECK(peers[signal.target]->ReceivedP2PCustomSignal(signal.bytes.data(),
            static_cast<int>(signal.bytes.size()), &contexts[signal.target])); ++delivered;
    }
    for (auto *peer : peers) peer->RunCallbacks();
}
}
int main(int argc, char **argv) {
    CHECK(argc == 1 || (argc == 2 && !std::strcmp(argv[1], "--boundary-only")));
    int relay = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0); CHECK(relay >= 0);
    sockaddr_in address{}; address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(!bind(relay, reinterpret_cast<sockaddr *>(&address), sizeof(address)));
    socklen_t length = sizeof(address);
    CHECK(!getsockname(relay, reinterpret_cast<sockaddr *>(&address), &length));
    char config[512];
    std::snprintf(config, sizeof(config), "{\"success\":true,\"revision\":1,"
        "\"relay_public_key\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\","
        "\"pops\":{\"sin\":{\"relays\":[{\"ipv4\":\"127.0.0.1\",\"port_range\":[%u,%u]}]}}}",
        unsigned(ntohs(address.sin_port)), unsigned(ntohs(address.sin_port)));
    SteamNetworkingSockets_SetManualPollMode(true);
    SteamNetworkingUtils()->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_Msg, debug);
    identities[0].SetGenericString("fixture-client"); identities[1].SetGenericString("fixture-peer");
    SteamNetworkingErrMsg error;
    CHECK(GameNetworkingSockets_Init(&identities[0], error)); peers[0] = SteamNetworkingSockets();
    CSteamNetworkingSockets *second;
    {
        SteamNetworkingGlobalLock lock("fixture second interface");
        second = new CSteamNetworkingSockets(static_cast<CSteamNetworkingUtils *>(SteamNetworkingUtils()));
        CHECK(second->BInitGameNetworkingSockets(&identities[1], error)); peers[1] = second;
    }
    CHECK(NSL_SDR_Configure(config, std::strlen(config)));
    CHECK(SteamNetworkingUtils()->SetGlobalConfigValueString(k_ESteamNetworkingConfig_P2P_STUN_ServerList, ""));
    CHECK(SteamNetworkingUtils()->SetGlobalConfigValueInt32(k_ESteamNetworkingConfig_P2P_Transport_ICE_Enable,
        k_nSteamNetworkingConfig_P2P_Transport_ICE_Enable_All));
    /* Match begin_connection's initial timeout and transport settings, rather
     * than the upstream 10s default. */
    SteamNetworkingConfigValue_t options[6];
    options[0].SetInt32(k_ESteamNetworkingConfig_Unencrypted, 2);
    options[1].SetInt32(k_ESteamNetworkingConfig_P2P_Transport_ICE_Enable, 0x7fffffff);
    options[2].SetInt32(k_ESteamNetworkingConfig_SendRateMin, 104857600);
    options[3].SetInt32(k_ESteamNetworkingConfig_SendRateMax, 104857600);
    options[4].SetInt32(k_ESteamNetworkingConfig_TimeoutInitial, 20000);
    options[5].SetInt32(k_ESteamNetworkingConfig_P2P_Transport_ICE_Implementation, 1);
    HSteamListenSocket listener = peers[1]->CreateListenSocketP2P(0, 6, options);
    CHECK(listener != k_HSteamListenSocket_Invalid);
    connections[0] = peers[0]->ConnectP2PCustomSignaling(new Signaling(1), &identities[1], 0, 6, options);
    CHECK(connections[0] != k_HSteamNetConnection_Invalid);
    const long long ages[] = {0, 1980000, 1999999, 2000000, 6999999, 7000000};
    std::printf("{\"waits\":[");
    {
        SteamNetworkingGlobalLock global("fixture routing boundary");
        ConnectionScopeLock lock;
        auto *base = GetConnectionByHandle(connections[0], lock);
        auto *connection = base ? base->AsSteamNetworkConnectionP2P() : nullptr;
        CHECK(connection && connection->GetState() == k_ESteamNetworkingConnectionState_Connecting);
        auto entered = connection->GetTimeEnteredConnectionState();
        for (unsigned i = 0; i < sizeof(ages)/sizeof(ages[0]); ++i) {
            auto now = entered + ages[i];
            auto wait = NSL_SDR_Wait(*connection, now);
            std::printf("%s[%lld,%lld]", i ? "," : "", ages[i], wait - now);
        }
    }
    unsigned received[2]{};
    bool connected = false;
    if (argc == 1) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (std::chrono::steady_clock::now() < deadline) {
            pump();
            SteamNetConnectionInfo_t info[2]{};
            if (connections[1] && peers[0]->GetConnectionInfo(connections[0], &info[0]) &&
                peers[1]->GetConnectionInfo(connections[1], &info[1])) {
                for (unsigned i = 0; i < 2; ++i)
                    CHECK(info[i].m_eState != k_ESteamNetworkingConnectionState_ProblemDetectedLocally &&
                           info[i].m_eState != k_ESteamNetworkingConnectionState_ClosedByPeer);
                connected = info[0].m_eState == k_ESteamNetworkingConnectionState_Connected &&
                            info[1].m_eState == k_ESteamNetworkingConnectionState_Connected;
                if (connected) break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(connected && accepted == 1 && sent >= 2 && delivered >= 2);
        {
            SteamNetworkingGlobalLock global("fixture selected transport");
            for (unsigned i = 0; i < 2; ++i) {
                ConnectionScopeLock lock;
                auto *base = GetConnectionByHandle(connections[i], lock);
                auto *connection = base ? base->AsSteamNetworkConnectionP2P() : nullptr;
                CHECK(connection && connection->m_pTransportICE &&
                       connection->m_pCurrentTransportP2P == connection->m_pTransportICE);
            }
        }
        const char *payload[] = {"client datagram after actual P2P handshake", "peer datagram after actual P2P handshake"};
        for (unsigned i = 0; i < 2; ++i) {
            SteamNetConnectionInfo_t info{};
            CHECK(peers[i]->GetConnectionInfo(connections[i], &info) && info.m_identityRemote == identities[1-i]);
            CHECK((info.m_nFlags & k_nSteamNetworkConnectionInfoFlags_Unauthenticated) &&
                   !(info.m_nFlags & (k_nSteamNetworkConnectionInfoFlags_LoopbackBuffers | k_nSteamNetworkConnectionInfoFlags_Relayed)));
            CHECK(peers[i]->SendMessageToConnection(connections[i], payload[i], std::strlen(payload[i])+1,
                k_nSteamNetworkingSend_UnreliableNoNagle, nullptr) == k_EResultOK);
        }
        deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline && (!received[0] || !received[1])) {
            pump();
            for (unsigned i = 0; i < 2; ++i) {
                SteamNetworkingMessage_t *message = nullptr;
                int count = peers[i]->ReceiveMessagesOnConnection(connections[i], &message, 1);
                CHECK(count >= 0);
                if (!count) continue;
                CHECK(!received[i] && message->m_cbSize == int(std::strlen(payload[1-i])+1) &&
                       !std::memcmp(message->m_pData, payload[1-i], std::strlen(payload[1-i])+1) &&
                       !(message->m_nFlags & k_nSteamNetworkingSend_Reliable));
                message->Release(); ++received[i];
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(received[0] == 1 && received[1] == 1);
    }
    for (unsigned i = 0; i < 2; ++i) {
        if (connections[i]) CHECK(peers[i]->CloseConnection(connections[i], 0, nullptr, false));
    }
    CHECK(peers[1]->CloseListenSocket(listener));
    {
        SteamNetworkingGlobalLock lock("fixture destroy second interface"); second->Destroy();
    }
    GameNetworkingSockets_Kill(); SteamNetworkingSockets_SetManualPollMode(false);
    CHECK(released.load() == created.load() && !close(relay));
    {
        std::lock_guard<std::mutex> lock(queue_lock); pending.clear();
    }
    std::printf("],\"connected\":%u,\"accepted\":%u,\"signals\":%u,\"delivered\":%u,"
        "\"objects\":%u,\"released\":%u,\"received\":[%u,%u],\"clean\":true}\n",
        connected ? 2 : 0, accepted, sent.load(), delivered, created.load(), released.load(), received[0], received[1]);
}
