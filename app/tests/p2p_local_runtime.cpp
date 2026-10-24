/* Actual prepared SDK custom-signaling/ICE receiver; controlled local peers.
 * No Valve identity, external STUN/relay, CM service or NAT is claimed here. */
#include "local_p2p_pair.h"
#include <steam/isteamnetworkingutils.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #condition); \
    std::abort(); } } while (false)
static void debug(ESteamNetworkingSocketsDebugOutputType, const char *text) {
    std::fprintf(stderr, "SDK %s\n", text);
}
int main(int argc, char **argv) {
    CHECK(argc == 1 || (argc == 2 && !std::strcmp(argv[1], "--boundary-only")));
    SteamNetworkingUtils()->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_Msg, debug);
    auto *pair = local_p2p::create(); local_p2p::start(pair);
    const long long ages[] = {0, 1980000, 1999999, 2000000, 6999999, 7000000};
    long long delays[6]; local_p2p::cold_waits(pair, ages, delays, 6);
    std::printf("{\"waits\":[");
    for (unsigned i = 0; i < 6; ++i)
        std::printf("%s[%lld,%lld]", i ? "," : "", ages[i], delays[i]);
    unsigned received[2]{};
    bool connected = false;
    if (argc == 1) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (std::chrono::steady_clock::now() < deadline) {
            local_p2p::poll(pair);
            SteamNetConnectionInfo_t info[2]{};
            if (local_p2p::connection(pair,1) &&
                local_p2p::sockets(pair,0)->GetConnectionInfo(local_p2p::connection(pair,0), &info[0]) &&
                local_p2p::sockets(pair,1)->GetConnectionInfo(local_p2p::connection(pair,1), &info[1])) {
                for (unsigned i = 0; i < 2; ++i)
                    CHECK(info[i].m_eState != k_ESteamNetworkingConnectionState_ProblemDetectedLocally &&
                          info[i].m_eState != k_ESteamNetworkingConnectionState_ClosedByPeer);
                connected = info[0].m_eState == k_ESteamNetworkingConnectionState_Connected &&
                            info[1].m_eState == k_ESteamNetworkingConnectionState_Connected;
                if (connected) break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(connected); local_p2p::verify_selected_ice(pair);
        const char *payload[] = {"client datagram after actual P2P handshake", "peer datagram after actual P2P handshake"};
        for (unsigned i = 0; i < 2; ++i)
            CHECK(local_p2p::sockets(pair,i)->SendMessageToConnection(local_p2p::connection(pair,i),
                payload[i], std::strlen(payload[i])+1, k_nSteamNetworkingSend_UnreliableNoNagle, nullptr) == k_EResultOK);
        deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline && (!received[0] || !received[1])) {
            local_p2p::poll(pair);
            for (unsigned i = 0; i < 2; ++i) {
                SteamNetworkingMessage_t *message = nullptr;
                int count = local_p2p::sockets(pair,i)->ReceiveMessagesOnConnection(local_p2p::connection(pair,i), &message, 1);
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
    auto counts = local_p2p::destroy(pair);
    std::printf("],\"connected\":%u,\"accepted\":%u,\"signals\":%u,\"delivered\":%u,"
        "\"objects\":%u,\"released\":%u,\"received\":[%u,%u],\"clean\":true}\n",
        connected ? 2 : 0, counts.accepted, counts.signals, counts.delivered, counts.objects, counts.released, received[0], received[1]);
}
