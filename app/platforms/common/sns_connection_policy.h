#pragma once
#include "sns_backend.h"
#include <steam/steamnetworkingsockets.h>
#include <atomic>
#include <cstdint>
#include <cstring>

namespace nsl {
/* Fixed original Android CheckConnection 0x800348 and SDR Close 0x800f94.
 * The port's SDK owner supplies the actual socket/clock interfaces. */
struct SnsConnectionView {
    HSteamNetConnection &handle;
    std::atomic<sl_sns_state> &state;
    SteamNetworkingMicroseconds &lastCheck;
};
enum class SnsCheckFailure { None, Info, Status, Peer, Local, Unknown };
struct SnsConnectionObservation {
    bool infoValid = false;
    SteamNetConnectionInfo_t info{};
    SnsCheckFailure failure = SnsCheckFailure::None;
    int detail = 0;
};

template <class Sockets, class BeforeClose>
void CloseSnsConnection(Sockets *sockets, SnsConnectionView v, BeforeClose beforeClose,
                        int reason, const char *debug = nullptr) {
    /* Original SDR close unlinks signaling before invoking the SDK. */
    beforeClose();
    if (v.handle) {
        if (sockets) sockets->CloseConnection(v.handle, reason, debug, false);
        v.handle = k_HSteamNetConnection_Invalid;
    }
    if (v.state.load() != SL_SNS_FAILED) v.state = SL_SNS_CLOSED;
}

template <class Sockets, class Utils, class BeforeClose>
bool CheckSnsConnection(Sockets *sockets, Utils *utils, SnsConnectionView v,
                        SnsConnectionObservation &out, BeforeClose beforeClose) {
    out = {};
    if (!v.handle) {
        if (v.state.load() != SL_SNS_FAILED) v.state = SL_SNS_CLOSED;
        return false;
    }
    SteamNetworkingMicroseconds now = utils->GetLocalTimestamp();
    // Original adds in 64 bits, then compares signed timestamps (including wrap).
    uint64_t deadlineBits = static_cast<uint64_t>(v.lastCheck) + 1000000u;
    int64_t deadline;
    std::memcpy(&deadline, &deadlineBits, sizeof(deadline));
    if (v.state.load() == SL_SNS_CONNECTED && now < deadline) return true;
    v.lastCheck = now;
    if (!sockets->GetConnectionInfo(v.handle, &out.info)) {
        v.handle = k_HSteamNetConnection_Invalid;
        v.state = SL_SNS_FAILED;
        out.failure = SnsCheckFailure::Info;
        return false; // Original invalidates without CloseConnection/unlink.
    }
    out.infoValid = true;
    switch (out.info.m_eState) {
    case k_ESteamNetworkingConnectionState_Connecting:
    case k_ESteamNetworkingConnectionState_FindingRoute:
        v.state = SL_SNS_CONNECTING;
        return true; // The caller separately checks transport == Connected.
    case k_ESteamNetworkingConnectionState_Connected: {
        SteamNetConnectionRealTimeStatus_t status{};
        EResult result = sockets->GetConnectionRealTimeStatus(v.handle, &status, 0, nullptr);
        if (result != k_EResultOK) {
            v.handle = k_HSteamNetConnection_Invalid;
            v.state = SL_SNS_FAILED;
            out.failure = SnsCheckFailure::Status;
            out.detail = static_cast<int>(result);
            return false;
        }
        v.state = SL_SNS_CONNECTED;
        return true;
    }
    case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
        v.state = SL_SNS_FAILED; // Must be visible to SDK close callbacks.
        out.failure = SnsCheckFailure::Local;
        break;
    case k_ESteamNetworkingConnectionState_ClosedByPeer:
        out.failure = SnsCheckFailure::Peer;
        break;
    default:
        out.failure = SnsCheckFailure::Unknown;
        break;
    }
    out.detail = static_cast<int>(out.info.m_eState);
    CloseSnsConnection(sockets, v, beforeClose,
        out.failure == SnsCheckFailure::Unknown ? 2001 : 0);
    return false;
}
}
