#pragma once
extern "C" {
#include "sns_backend.h"
}
#include <steam/isteamnetworkingutils.h>
#include <steam/steamnetworkingsockets.h>
#include <cerrno>
#include <cstdint>
#include <limits>

namespace nsl {
/* Original 0x800224, called synchronously from Socket::Send 0x7ff300.
 * IHS has already serialized its own CRC. No queued-success substitution. */
template<class Sockets>
int SendSnsDatagram(Sockets *sockets, HSteamNetConnection handle, sl_sns_state state,
                    const uint8_t *data, size_t size) {
    if (!handle) return 3;
    if (static_cast<unsigned>(state) < 2) return 1;
    if (state == SL_SNS_FAILED) return 4;
    if (state != SL_SNS_CONNECTED) return 3;
    // C adapter validation; original packet storage always supplies these.
    if (!sockets || (size && !data) || size > std::numeric_limits<uint32_t>::max()) return 3;
    EResult result = sockets->SendMessageToConnection(handle, data,
        static_cast<uint32_t>(size), 0x15, nullptr);
    return result == k_EResultOK ? 0 :
        result == k_EResultLimitExceeded || result == k_EResultIgnored ? 1 : 3;
}

/* Existing IHS SessionSendPacketResult maps errno from its bool BaseSend.
 * Always assign on failure: stale errno must not decide an SNS result. */
inline bool SnsSendAccepted(int result) {
    if (result == 0) return true;
    errno = result == 1 ? EAGAIN : result == 3 ? EBADF : EIO;
    return false;
}

template<class Utils>
int SetSnsMaximumMTU(Utils *utils, HSteamNetConnection handle, int mtu) {
    int32_t packet = mtu;
    utils->SetConfigValue(k_ESteamNetworkingConfig_MTU_PacketSize,
        k_ESteamNetworkingConfig_Connection, handle,
        k_ESteamNetworkingConfig_Int32, &packet);
    int32_t data = 0;
    size_t size = sizeof(data);
    ESteamNetworkingConfigDataType type;
    auto result = utils->GetConfigValue(k_ESteamNetworkingConfig_MTU_DataSize,
        k_ESteamNetworkingConfig_Connection, handle, &type, &data, &size);
    return result == k_ESteamNetworkingGetConfigValue_OK ? data : -1;
}

constexpr int SnsDestroyedReason = 1001;
constexpr const char *SnsDestroyedDebug = "Destroyed";
}
