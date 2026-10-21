/* Production policy + real IHS caller, controlled SDK methods and timestamp.
 * The final Release destructor is represented by an explicit observer. */
#include "sns_io_policy.h"
#include "sns_connection_policy.h"
#include <cassert>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>
extern "C" {
#include <ihslib.h>
void *sns_io_session(bool, bool (*)(void *, const uint8_t *, size_t), void *);
int sns_io_send(void *, uint32_t, unsigned, unsigned, uint64_t *, uint32_t *);
void sns_io_destroy(void *);
}
static std::string hex(const void *p, size_t n) {
    auto b = static_cast<const uint8_t *>(p);
    static const char digits[] = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += digits[b[i] >> 4]; s += digits[b[i] & 15]; }
    return s;
}
struct Sdk {
    HSteamNetConnection handle = 0;
    std::atomic<sl_sns_state> state{SL_SNS_CONNECTING};
    int result = 1;
    bool owner = true;
    std::vector<std::string> events;
    EResult SendMessageToConnection(HSteamNetConnection h, const void *p,
        uint32_t n, int flags, int64_t *number) {
        assert(h == handle && flags == 0x15 && !number);
        events.push_back("{\"flags\":21,\"wire\":\"" + hex(p, n) + "\"}");
        return static_cast<EResult>(result);
    }
    bool CloseConnection(HSteamNetConnection h, int reason, const char *text, bool linger) {
        assert(h == handle && !owner && !linger);
        assert(std::string(text) == "Destroyed");
        events.push_back("[\"close\"," + std::to_string(reason) + "," +
            std::to_string(state.load()) + "]");
        return true;
    }
    static bool send(void *ctx, const uint8_t *p, size_t n) {
        auto &s = *static_cast<Sdk *>(ctx);
        errno = EMSGSIZE; // Deliberately stale; production mapping must replace it.
        return nsl::SnsSendAccepted(nsl::SendSnsDatagram(&s, s.handle, s.state.load(), p, n));
    }
};
struct Utils {
    int handle, mtu, setOK, getResult, value, outSize;
    bool set = false;
    bool SetConfigValue(ESteamNetworkingConfigValue key, ESteamNetworkingConfigScope scope,
        intptr_t h, ESteamNetworkingConfigDataType type, const void *p) {
        assert(key == k_ESteamNetworkingConfig_MTU_PacketSize && scope == k_ESteamNetworkingConfig_Connection);
        assert(h == handle && type == k_ESteamNetworkingConfig_Int32 && *static_cast<const int *>(p) == mtu);
        set = true; return setOK;
    }
    ESteamNetworkingGetConfigValueResult GetConfigValue(ESteamNetworkingConfigValue key,
        ESteamNetworkingConfigScope scope, intptr_t h, ESteamNetworkingConfigDataType *type,
        void *p, size_t *n) {
        assert(set && key == k_ESteamNetworkingConfig_MTU_DataSize && scope == k_ESteamNetworkingConfig_Connection);
        assert(h == handle && type && *n == 4);
        *static_cast<int *>(p) = value; *type = k_ESteamNetworkingConfig_Int32; *n = outSize;
        return static_cast<ESteamNetworkingGetConfigValueResult>(getResult);
    }
};
static void events(const Sdk &s) {
    for (size_t n = 0; n < s.events.size(); ++n) std::printf("%s%s", n ? "," : "", s.events[n].c_str());
}
int main() {
    IHS_Init();
    char mode;
    while (std::cin >> mode) {
        if (mode == 'S') {
            Sdk s; int state, crc; unsigned steps;
            assert(bool(std::cin >> state >> s.handle >> crc >> steps));
            s.state = static_cast<sl_sns_state>(state);
            void *session = sns_io_session(crc, Sdk::send, &s);
            for (unsigned i = 0; i < steps; ++i) {
                uint32_t now, deadlines[2]; unsigned kind, size; uint64_t bytes;
                assert(bool(std::cin >> s.result >> now >> kind >> size));
                s.events.clear();
                int result = sns_io_send(session, now, kind, size, &bytes, deadlines);
                std::printf("{\"result\":%d,\"state\":%d,\"handle\":%u,\"sent_bytes\":%llu,\"deadlines\":[%u,%u],\"events\":[",
                    result, s.state.load(), s.handle, (unsigned long long)bytes, deadlines[0], deadlines[1]);
                events(s); std::puts("]}");
            }
            sns_io_destroy(session);
        } else if (mode == 'M') {
            Utils u{};
            assert(bool(std::cin >> u.handle >> u.mtu >> u.setOK >> u.getResult >> u.value >> u.outSize));
            int result = nsl::SetSnsMaximumMTU(&u, u.handle, u.mtu);
            std::printf("{\"result\":%d,\"events\":[[\"set\",%u],\"get\"]}\n", result, uint32_t(u.mtu));
        } else if (mode == 'R') {
            Sdk s; int state;
            assert(bool(std::cin >> state >> s.handle));
            s.state = static_cast<sl_sns_state>(state);
            SteamNetworkingMicroseconds last = 0;
            nsl::CloseSnsConnection(&s, {s.handle, s.state, last}, [&] { s.owner = false; },
                nsl::SnsDestroyedReason, nsl::SnsDestroyedDebug);
            std::printf("{\"result\":0,\"state\":%d,\"handle\":%u,\"owner_linked\":false,\"debug\":%s,\"events\":[",
                s.state.load(), s.handle, s.events.empty() ? "null" : "\"Destroyed\"");
            events(s); std::printf("%s\"destroy\"]}\n", s.events.empty() ? "" : ",");
        } else assert(false);
    }
    IHS_Quit();
}
