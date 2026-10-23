#pragma once
#include <steam/isteamnetworkingutils.h>
#include <cstdio>
#include <cstring>

namespace nsl {
/* Fixed-SDK startup errors only. Never retain SDK text, peer identities, or
 * certificate/signaling data. Unknown formats produce no dynamic content. */
struct StartFailure {
    const char *stage = "unknown";
    unsigned detail = 0;
};
inline bool start_error_end(const char *p) {
    return *p == 0 || (*p == '\n' && !p[1]);
}
inline StartFailure start_failure(const char *message) {
    constexpr char prefix[] = "Cannot create P2P connection. ";
    if (!message || strnlen(message, 1025) > 1024 ||
        strncmp(message, prefix, sizeof(prefix) - 1))
        return {};
    const char *p = message + sizeof(prefix) - 1;
    while (*p == ' ') ++p; /* Pinned SDK uses two spaces after the sentence. */
    unsigned value;
    int length = 0;
    if (sscanf(p, "Error setting option %u%n", &value, &length) == 1 && length &&
        start_error_end(p + length))
        return {"option", value};
    if (!strncmp(p, "Crypto init error. ", 19))
        return {"crypto", !strncmp(p + 19, "Need a cert authority!", 22) ? 1u : 0u};
    struct Entry { const char *message, *stage; };
    constexpr Entry exact[] = {
        {"We don't know our local identity.", "identity"},
        {"Unable to determine local identity.  Not logged in?", "identity"},
        {"Too many connections.", "connection_limit"},
        {"Unable to find unique connection ID", "connection_id"},
        {"SDR network configuration unavailable", "sdr_config"},
        {"SDR relay socket initialization failed", "sdr_socket"},
        {"No available P2P transports", "no_transport"},
        {"To use symmetric connect, remote identity must be specified", "symmetric_identity"},
        {"SymmetricConnect not supported", "symmetric_unsupported"},
        {"Remote identity must be known to use symmetric mode", "symmetric_identity"},
    };
    for (const auto &e : exact) {
        size_t n = strlen(e.message);
        if (!strncmp(p, e.message, n) && start_error_end(p + n))
            return {e.stage, 0};
    }
    constexpr char socket_prefix[] = "SDR socket: ";
    if (!strncmp(p, socket_prefix, sizeof(socket_prefix) - 1)) {
        p += sizeof(socket_prefix) - 1;
        constexpr Entry socket[] = {
            {"socket() call failed.  Error code 0x", "udp_socket"},
            {"Failed to set socket nonblocking mode.  Error code 0x", "udp_nonblock"},
            {"Failed to set socket send buffer size.  Error code 0x", "udp_send_buffer"},
            {"Failed to set socket recv buffer size.  Error code 0x", "udp_recv_buffer"},
            {"Failed to bind socket.  Error code 0x", "udp_bind"},
            {"getsockname failed.  Error code 0x", "udp_local_address"},
            {"epoll_ctl failed, error 0x", "udp_poll"},
        };
        for (const auto &e : socket) {
            size_t n = strlen(e.message);
            length = 0;
            if (!strncmp(p, e.message, n) &&
                sscanf(p + n, "%8x%n", &value, &length) == 1 && length) {
                const char *end = p + n + length;
                if (*end == '.') ++end;
                if (start_error_end(end)) return {e.stage, value};
            }
        }
        return {"sdr_socket", 0};
    }
    if (!strncmp(p, "Unexpected state ", 17) &&
        sscanf(p + 17, "%u%n", &value, &length) == 1 && length &&
        start_error_end(p + 17 + length))
        return {"state", value};
    return {};
}

/* Only the manual-poll owner installs this scope, around the synchronous
 * ConnectP2PCustomSignaling call. No logging in the SDK callback and no
 * background callback or retained pointer after the scope ends. */
class StartDiagnostics {
    inline static thread_local StartDiagnostics *active = nullptr;
    ISteamNetworkingUtils *utils;
    static void capture(ESteamNetworkingSocketsDebugOutputType, const char *text) {
        if (!active || active->messages == 8) return;
        ++active->messages;
        StartFailure failure = start_failure(text);
        if (strcmp(failure.stage, "unknown")) active->failure = failure;
    }
public:
    StartFailure failure;
    unsigned messages = 0;
    explicit StartDiagnostics(ISteamNetworkingUtils *u) : utils(u) {
        active = this;
        utils->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_Error, capture);
    }
    ~StartDiagnostics() {
        utils->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_None, nullptr);
        active = nullptr;
    }
    StartDiagnostics(const StartDiagnostics &) = delete;
    StartDiagnostics &operator=(const StartDiagnostics &) = delete;
};
}
