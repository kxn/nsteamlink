#include <steam/steamnetworkingsockets.h>
#include <steam/steamnetworkingcustomsignaling.h>
#include "sns_start_diagnostics.h"
#include "sdr_client.h"
#include <cassert>
#include <cerrno>
#include <cstring>
#include <string>
#include <sys/socket.h>

extern "C" void SteamNetworkingSockets_SetManualPollMode(bool);
extern "C" void SteamNetworkingSockets_Poll(int);
static bool fail_receive_buffer;
static unsigned released;
extern "C" int __real_setsockopt(int, int, int, const void *, socklen_t);
extern "C" int __wrap_setsockopt(int fd, int level, int option, const void *p, socklen_t n) {
    if (fail_receive_buffer && level == SOL_SOCKET && option == SO_RCVBUF) {
        errno = ENOBUFS;
        return -1;
    }
    return __real_setsockopt(fd, level, option, p, n);
}
class Signaling final : public ISteamNetworkingConnectionSignaling {
    bool SendSignal(HSteamNetConnection, const SteamNetConnectionInfo_t &, const void *, int) override {
        return false;
    }
    void Release() override { ++released; delete this; }
};
int main() {
    using nsl::start_failure;
    for (const char *text : {"identity=private-fixture", "Cannot create P2P connection to private-fixture. fail",
                             "Cannot create P2P connection. Error setting option 5 secret-fixture",
                             "Cannot create P2P connection. private-fixture"}) {
        auto failure = start_failure(text);
        assert(!strcmp(failure.stage, "unknown") && !failure.detail);
    }
    std::string oversized = "Cannot create P2P connection. Error setting option 5";
    oversized.append(2048, 'x');
    assert(!strcmp(start_failure(oversized.c_str()).stage, "unknown"));
    auto crypto = start_failure("Cannot create P2P connection. Crypto init error. Need a cert authority!");
    assert(!strcmp(crypto.stage, "crypto") && crypto.detail == 1);
    auto option = start_failure("Cannot create P2P connection.  Error setting option 106");
    assert(!strcmp(option.stage, "option") && option.detail == 106);

    SteamNetworkingSockets_SetManualPollMode(true);
    SteamNetworkingErrMsg error;
    SteamNetworkingIdentity identity;
    identity.SetLocalHost(); /* Synthetic unsigned localhost; no Steam identity. */
    assert(GameNetworkingSockets_Init(&identity, error));
    {
        nsl::StartDiagnostics capture(SteamNetworkingUtils());
        SteamNetworkingConfigValue_t invalid;
        invalid.SetInt32(k_ESteamNetworkingConfig_Invalid, 1);
        auto connection = SteamNetworkingSockets()->ConnectP2PCustomSignaling(
            new Signaling, nullptr, 0, 1, &invalid);
        assert(connection == k_HSteamNetConnection_Invalid);
        assert(capture.messages && !strcmp(capture.failure.stage, "option"));
        assert(capture.failure.detail == unsigned(k_ESteamNetworkingConfig_Invalid));
    }
    SteamNetworkingSockets_Poll(0);
#if NSL_ENABLE_SDR
    const char config[] = "{\"success\":true,\"revision\":1,"
        "\"relay_public_key\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\","
        "\"pops\":{\"sin\":{\"relays\":[{\"ipv4\":\"192.0.2.1\",\"port_range\":[27015,27015]}]}}}";
    assert(SteamNetworkingSocketsLib::NSL_SDR_Configure(config, sizeof(config) - 1));
    {
        fail_receive_buffer = true;
        nsl::StartDiagnostics capture(SteamNetworkingUtils());
        auto connection = SteamNetworkingSockets()->ConnectP2PCustomSignaling(
            new Signaling, nullptr, 0, 0, nullptr);
        fail_receive_buffer = false;
        assert(connection == k_HSteamNetConnection_Invalid);
        assert(capture.messages && !strcmp(capture.failure.stage, "udp_recv_buffer"));
        assert(capture.failure.detail == ENOBUFS);
    }
    SteamNetworkingSockets_Poll(0);
#endif
    GameNetworkingSockets_Kill();
    SteamNetworkingSockets_SetManualPollMode(false);
    assert(released == (NSL_ENABLE_SDR ? 2u : 1u));
    puts("PASS SDK startup errors: real SDK option/UDP failures, numeric-only capture and cleanup");
}
