/* Executes the same state/close policy called by the production SDK owner.
 * Only SDK results, clock and signaling object are adapters. */
#include "sns_connection_policy.h"
#include <cassert>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

struct Sdk {
    nsl::SnsConnectionView view;
    bool &owner;
    bool infoOK, quickOK;
    int sdkState;
    SteamNetworkingMicroseconds now;
    std::vector<std::string> events;
    SteamNetworkingMicroseconds GetLocalTimestamp() {
        events.emplace_back("\"time\""); return now;
    }
    bool GetConnectionInfo(HSteamNetConnection h, SteamNetConnectionInfo_t *p) {
        assert(h == 1);
        events.emplace_back("\"info\"");
        p->m_eState = static_cast<ESteamNetworkingConnectionState>(sdkState);
        p->m_eEndReason = 4321;
        return infoOK;
    }
    EResult GetConnectionRealTimeStatus(HSteamNetConnection h,
        SteamNetConnectionRealTimeStatus_t *, int lanes, void *p) {
        assert(h == 1 && lanes == 0 && p == nullptr);
        events.emplace_back("\"quick\"");
        return quickOK ? k_EResultOK : k_EResultNoConnection;
    }
    bool CloseConnection(HSteamNetConnection h, int reason, const char *p, bool linger) {
        assert(!owner && h == 1 && p == nullptr && !linger);
        events.push_back("[\"close\"," + std::to_string(reason) + "," +
                          std::to_string(view.state.load()) + "]");
        return true;
    }
};
int main() {
    unsigned programs;
    if (!(std::cin >> programs)) return 1;
    for (unsigned n = 0; n < programs; ++n) {
        unsigned state, handle, steps;
        SteamNetworkingMicroseconds last;
        assert(bool(std::cin >> state >> handle >> last >> steps));
        HSteamNetConnection h = handle;
        std::atomic<sl_sns_state> s{static_cast<sl_sns_state>(state)};
        bool owner = true;
        nsl::SnsConnectionView v{h, s, last};
        Sdk sdk{v, owner, true, true, 3, 0, {}};
        for (unsigned a = 0; a < steps; ++a) {
            assert(bool(std::cin >> sdk.now >> sdk.infoOK >> sdk.sdkState >> sdk.quickOK));
            sdk.events.clear();
            nsl::SnsConnectionObservation observation;
            bool result = nsl::CheckSnsConnection(&sdk, &sdk, v, observation, [&] { owner = false; });
            std::printf("{\"state\":%d,\"handle\":%u,\"last_check\":%lld,\"result\":%s,"
                        "\"owner_linked\":%s,\"events\":[", int(s.load()), h, (long long)last,
                        result ? "true" : "false", owner ? "true" : "false");
            for (size_t e = 0; e < sdk.events.size(); ++e)
                std::printf("%s%s", e ? "," : "", sdk.events[e].c_str());
            std::puts("]}");
        }
    }
    assert(std::cin.eof() || (std::cin >> std::ws).eof());
}
