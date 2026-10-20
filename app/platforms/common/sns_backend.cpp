extern "C" {
#include "sns_backend.h"
#include "stream_bridge.h"
#include "sdr_probe.h"
#include "dns_policy.h"
}
#include <steam/steamnetworkingsockets.h>
#include <steam/steamnetworkingcustomsignaling.h>
#include <steam/isteamnetworkingutils.h>
#if NSL_DIAGNOSTICS
#include "sns_start_diagnostics.h"
#endif
#include "sns_message_queue.h"
#include <mbedtls/base64.h>
#include <curl/curl.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <vector>

/* Exported by the fixed upstream SDK, but absent from its public header. */
extern "C" void SteamNetworkingSockets_SetManualPollMode(bool);
extern "C" void SteamNetworkingSockets_Poll(int);
extern "C" void sl_gns_set_steam_link_app_id();
extern "C" bool sl_gns_import_trust(const char *, size_t);
extern "C" int sl_gns_certificate_seconds();

namespace {
/* Fixed public SDK's default RecvMaxMessageSize, not the UDP buffer limit.
 * Official SNS packet attachment preserves the entire SDK message (§12.3). */
enum { DATAGRAM_MAX = k_cbMaxSteamNetworkingSocketsMessageSizeSend, SIGNAL_COUNT = 64 };
using Message = std::vector<uint8_t>;
struct Queues {
    std::mutex mutex;
    std::condition_variable wake;
    nsl::SnsMessageQueue tx, rx;
    std::deque<Message> signals;
    std::atomic<sl_sns_state> state{SL_SNS_CONNECTING};
    bool owner = true;
};
std::atomic<bool> sdk_owned{false};
class Signaling final : public ISteamNetworkingConnectionSignaling {
    std::shared_ptr<Queues> q;
public:
    explicit Signaling(std::shared_ptr<Queues> queues) : q(std::move(queues)) {}
    bool SendSignal(HSteamNetConnection, const SteamNetConnectionInfo_t &,
                    const void *data, int size) override {
        if (!data || size <= 0 || size > 60000)
            return false;
        std::lock_guard<std::mutex> lock(q->mutex);
        if (!q->owner || q->signals.size() == SIGNAL_COUNT)
            return false;
        try {
            const uint8_t *p = static_cast<const uint8_t *>(data);
            q->signals.emplace_back(p, p + size);
            return true;
        } catch (const std::bad_alloc &) { return false; }
    }
    void Release() override { delete this; }
};
class ReceiveContext final : public ISteamNetworkingSignalingRecvContext {
public:
    ISteamNetworkingConnectionSignaling *OnConnectRequest(HSteamNetConnection,
        const SteamNetworkingIdentity &, int) override { return nullptr; }
    void SendRejectionSignal(const SteamNetworkingIdentity &, const void *, int) override {}
};
static void wipe(void *p, size_t n) {
    volatile uint8_t *q = static_cast<volatile uint8_t *>(p);
    while (n--) *q++ = 0;
}
static bool decode_cert(const char *text, Message &out) {
    if (!text)
        return false;
    size_t n = strnlen(text, 65537);
    if (!n || n > 65536 || n % 4 == 1)
        return false;
    std::string padded(text, n);
    while (padded.size() % 4)
        padded += '=';
    out.resize(padded.size());
    size_t decoded = 0;
    int ret = mbedtls_base64_decode(out.data(), out.size(), &decoded,
        reinterpret_cast<const uint8_t *>(padded.data()), padded.size());
    wipe(&padded[0], padded.size());
    if (ret || !decoded) {
        wipe(out.data(), out.size());
        out.clear();
        return false;
    }
    out.resize(decoded);
    return true;
}
}
struct sl_sns {
    std::shared_ptr<Queues> q = std::make_shared<Queues>();
    ISteamNetworkingSockets *sockets = nullptr;
    HSteamNetConnection connection = k_HSteamNetConnection_Invalid;
    sl_stream_bridge *bridge = nullptr;
    uint64_t last_check = 0;
    bool initialized = false;
    bool share_ip = true, config_ready = false;
    CURLM *http = nullptr;
    CURL *request = nullptr;
    unsigned config_attempt = 0;
    std::vector<char> config;
    Message certificate;
    int end_reason = 0;
    sl_sns_stats stats{};
#if NSL_SNS_PROBES
    sl_sdr_probe *relay_probe = nullptr;
    unsigned sdr_debug[16] = {};
    sl_sdr_loss_snapshot terminal_loss{};
    bool observe_loss = false, terminal_loss_valid = false;
#endif
};
static void close_backend(sl_sns *b, sl_sns_state state,
    sl_sns_terminal_source source = SL_SNS_TERMINAL_NONE, int detail = 0) {
    SteamNetConnectionInfo_t info{};
    bool have_info = b->connection != k_HSteamNetConnection_Invalid &&
        b->sockets->GetConnectionInfo(b->connection, &info);
    if (have_info) {
        b->stats.sdk_state = int(info.m_eState);
        if (info.m_eEndReason) b->end_reason = info.m_eEndReason;
    }
    if (b->stats.terminal_source == SL_SNS_TERMINAL_NONE && source != SL_SNS_TERMINAL_NONE) {
        b->stats.terminal_source = source;
        b->stats.terminal_detail = detail;
        b->stats.terminal_sdk_state = have_info ? int(info.m_eState) : 0;
        b->stats.terminal_end_reason = b->end_reason;
#if NSL_SNS_PROBES && NSL_ENABLE_SDR
        if (b->observe_loss && b->connection)
            b->terminal_loss_valid = sl_gns_sdr_loss_snapshot(b->connection, &b->terminal_loss);
#endif
    }
    {
        std::lock_guard<std::mutex> lock(b->q->mutex);
        if (b->q->state == SL_SNS_FAILED)
            state = SL_SNS_FAILED;
        b->q->state = state;
        b->q->tx.clear();
        b->q->rx.clear();
    }
    b->q->wake.notify_all();
    if (b->connection != k_HSteamNetConnection_Invalid) {
        // A send/receive can observe a terminal SDK state before the periodic
        // status poll. Preserve its reason before invalidating the handle.
        b->sockets->CloseConnection(b->connection, 2001, "stream transport closed", false);
        b->connection = k_HSteamNetConnection_Invalid;
    }
}
static bool receive_signal(const uint8_t *p, size_t n, void *ctx) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (!b->connection || n > INT32_MAX)
        return false;
    ReceiveContext receive;
    return b->sockets->ReceivedP2PCustomSignal(p, static_cast<int>(n), &receive);
}
static void signal_failed(void *ctx) { close_backend(static_cast<sl_sns *>(ctx), SL_SNS_FAILED, SL_SNS_TERMINAL_SIGNAL); }
static void copy_error(char *error, size_t size, const char *text) {
    if (error && size)
        snprintf(error, size, "%s", text);
}
static size_t receive_config(char *p, size_t size, size_t count, void *ctx) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (size && count > SIZE_MAX / size)
        return 0;
    size_t bytes = size * count;
    if (bytes > 1024 * 1024 - b->config.size())
        return 0;
    try {
        b->config.insert(b->config.end(), p, p + bytes);
        return bytes;
    } catch (const std::bad_alloc &) { return 0; }
}
static void config_event(sl_sns *b, const char *event, int result) {
#if NSL_DIAGNOSTICS
    long status = 0, verified = 0;
    char *remote = nullptr;
    if (b->request) {
        curl_easy_getinfo(b->request, CURLINFO_RESPONSE_CODE, &status);
        curl_easy_getinfo(b->request, CURLINFO_SSL_VERIFYRESULT, &verified);
        curl_easy_getinfo(b->request, CURLINFO_PRIMARY_IP, &remote);
    }
    char line[224];
    snprintf(line, sizeof(line), "sns_config event=%s attempt=%u curl=%d http=%ld verify=%ld ip=%.64s",
        event, b->config_attempt, result, status, verified, remote ? remote : "");
    sl_dns_policy_report(line);
#else
    (void)b; (void)event; (void)result;
#endif
}
static bool begin_config(sl_sns *b) {
    b->config.clear();
    ++b->config_attempt;
    b->request = curl_easy_init();
    if (!b->request)
        return false;
    curl_easy_setopt(b->request, CURLOPT_URL,
        "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=353380");
    curl_easy_setopt(b->request, CURLOPT_WRITEFUNCTION, receive_config);
    curl_easy_setopt(b->request, CURLOPT_WRITEDATA, b);
    curl_easy_setopt(b->request, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(b->request, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(b->request, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(b->request, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(b->request, CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    curl_easy_setopt(b->request, CURLOPT_TIMEOUT_MS, 25000L);
    config_event(b, "begin", -1);
    return curl_multi_add_handle(b->http, b->request) == CURLM_OK;
}
static bool begin_connection(sl_sns *b) {
    /* NETWORKING section 9.5. Keep explicit official rate, encryption
     * preference, timeout and message flags. The built-in GNS ICE provider is
     * a documented implementation difference from the APK's WebRTC factory. */
    SteamNetworkingConfigValue_t options[6];
    options[0].SetInt32(k_ESteamNetworkingConfig_Unencrypted, 2);
    options[1].SetInt32(k_ESteamNetworkingConfig_P2P_Transport_ICE_Enable,
                      b->share_ip ? 0x7fffffff : 0);
    options[2].SetInt32(k_ESteamNetworkingConfig_SendRateMin, 104857600);
    options[3].SetInt32(k_ESteamNetworkingConfig_SendRateMax, 104857600);
    options[4].SetInt32(k_ESteamNetworkingConfig_TimeoutInitial, 20000);
    options[5].SetInt32(k_ESteamNetworkingConfig_P2P_Transport_ICE_Implementation, 1);
#if NSL_DIAGNOSTICS
    int certificate_seconds = sl_gns_certificate_seconds();
    SteamNetAuthenticationStatus_t authentication{};
    b->sockets->GetAuthenticationStatus(&authentication);
    nsl::StartFailure failure;
    unsigned errors = 0;
    {
        nsl::StartDiagnostics capture(SteamNetworkingUtils());
        b->connection = b->sockets->ConnectP2PCustomSignaling(new Signaling(b->q), nullptr, 0, 6, options);
        failure = capture.failure;
        errors = capture.messages;
    }
    if (b->connection == k_HSteamNetConnection_Invalid) {
        char line[224];
        snprintf(line, sizeof(line), "sns_start failed_stage=%s detail=%u sdk_errors=%u auth=%d cert_seconds=%d",
            failure.stage, failure.detail, errors, int(authentication.m_eAvail), certificate_seconds);
        sl_dns_policy_report(line);
    }
#else
    b->connection = b->sockets->ConnectP2PCustomSignaling(new Signaling(b->q), nullptr, 0, 6, options);
#endif
    return b->connection != k_HSteamNetConnection_Invalid;
}
static void pump_config(sl_sns *b) {
    if (!b->request)
        return;
    int running = 0;
    CURLMcode ret = curl_multi_perform(b->http, &running);
    CURLMsg *message;
    int remaining;
    bool done = ret != CURLM_OK, success = false;
    while ((message = curl_multi_info_read(b->http, &remaining))) {
        if (message->msg != CURLMSG_DONE || message->easy_handle != b->request)
            continue;
        done = true;
        long status = 0;
        curl_easy_getinfo(b->request, CURLINFO_RESPONSE_CODE, &status);
        config_event(b, "complete", int(message->data.result));
        success = message->data.result == CURLE_OK && status == 200 &&
            sl_gns_import_trust(b->config.data(), b->config.size());
        if (message->data.result == CURLE_OK && status == 200)
            config_event(b, success ? "trust_imported" : "trust_failed", -1);
    }
    if (!done)
        return;
    curl_multi_remove_handle(b->http, b->request);
    curl_easy_cleanup(b->request);
    b->request = nullptr;
    if (success) {
        b->config_ready = true;
        SteamNetworkingErrMsg error;
        /* Public GNS returns from CertStore_CheckCert before decoding the
         * certificate if its CA is unknown. Install the network CA chain first
         * rather than treating this as an invalid host public key. */
        bool installed = b->sockets->SetCertificate(b->certificate.data(),
            static_cast<int>(b->certificate.size()), error);
        config_event(b, installed ? "certificate_installed" : "certificate_failed", -1);
        wipe(b->certificate.data(), b->certificate.size());
        b->certificate.clear();
        if (!installed) {
            b->end_reason = -2;
            close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_CERTIFICATE);
            return;
        }
        b->sockets->InitAuthentication();
        bool started = begin_connection(b);
        config_event(b, started ? "p2p_started" : "p2p_start_failed", -1);
        if (!started)
            close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_START);
    } else if (b->config_attempt >= 3 || !begin_config(b)) {
        b->end_reason = -1;
        close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_CONFIG);
    }
}
extern "C" sl_sns *sl_sns_create(const IHS_ClientConfig *config, const sl_remote_material *m,
                                  bool share_ip, char *error, size_t error_size) {
    if (!config || !m || !m->cert || !m->key_size || m->transport != 4) {
        copy_error(error, error_size, "invalid SNS connection material");
        return nullptr;
    }
    bool expected = false;
    if (!sdk_owned.compare_exchange_strong(expected, true)) {
        copy_error(error, error_size, "another stream owns the SNS instance");
        return nullptr;
    }
    sl_sns *b = nullptr;
    SteamNetworkingErrMsg err = {};
    try {
        b = new sl_sns;
        /* Manual mode precedes SDK initialization, preventing a service worker
         * from racing the caller's pump or teardown. */
        SteamNetworkingSockets_SetManualPollMode(true);
        if (!GameNetworkingSockets_Init(nullptr, err))
            goto fail;
        b->initialized = true;
        b->sockets = SteamNetworkingSockets();
        SteamNetworkingUtils()->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_None, nullptr);
        sl_gns_set_steam_link_app_id();
        b->share_ip = share_ip;
        b->sockets->ResetIdentity(nullptr);
        if (!decode_cert(m->cert, b->certificate)) {
            copy_error(err, sizeof(err), "invalid base64 SNS certificate");
            goto fail;
        }
        if (m->stun_servers && m->stun_servers[0] &&
            !SteamNetworkingUtils()->SetGlobalConfigValueString(
                k_ESteamNetworkingConfig_P2P_STUN_ServerList, m->stun_servers)) {
            copy_error(err, sizeof(err), "cannot set SNS STUN servers");
            goto fail;
        }
        sl_signal_callbacks callbacks;
        callbacks.receive = receive_signal;
        callbacks.failed = signal_failed;
        b->bridge = sl_stream_bridge_create(config, m, &callbacks, b);
        if (!b->bridge) {
            copy_error(err, sizeof(err), "cannot allocate SNS signaling bridge");
            goto fail;
        }
        b->http = curl_multi_init();
        if (!b->http || !begin_config(b)) {
            copy_error(err, sizeof(err), "cannot start SNS network configuration");
            goto fail;
        }
        return b;
    } catch (const std::bad_alloc &) { copy_error(err, sizeof(err), "SNS allocation failed"); }
fail:
    copy_error(error, error_size, err[0] ? err : "SNS initialization failed");
    if (b)
        sl_sns_destroy(b);
    else
        sdk_owned = false;
    return nullptr;
}
static bool check_connection(sl_sns *b, uint64_t now) {
    if (!b->connection)
        return false;
    if (b->q->state == SL_SNS_CONNECTED && now - b->last_check < 1000)
        return true;
    b->last_check = now;
    SteamNetConnectionInfo_t info;
    if (!b->sockets->GetConnectionInfo(b->connection, &info)) {
        close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_CONNECTION_INFO);
        return false;
    }
    b->end_reason = info.m_eEndReason;
    b->stats.sdk_state = int(info.m_eState);
    b->stats.authenticated = !(info.m_nFlags & k_nSteamNetworkConnectionInfoFlags_Unauthenticated);
    b->stats.relayed = (info.m_nFlags & k_nSteamNetworkConnectionInfoFlags_Relayed) != 0;
    switch (info.m_eState) {
    case k_ESteamNetworkingConnectionState_Connecting:
    case k_ESteamNetworkingConnectionState_FindingRoute:
        b->q->state = SL_SNS_CONNECTING;
        return false;
    case k_ESteamNetworkingConnectionState_Connected: {
        SteamNetConnectionRealTimeStatus_t status;
        EResult ret = b->sockets->GetConnectionRealTimeStatus(b->connection, &status, 0, nullptr);
        if (ret != k_EResultOK) {
            close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_STATUS, ret);
            return false;
        }
        b->q->state = SL_SNS_CONNECTED;
        return true;
    }
    case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
        close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_CONNECTION, info.m_eState);
        break;
    default:
        close_backend(b, SL_SNS_CLOSED, SL_SNS_TERMINAL_CONNECTION, info.m_eState);
        break;
    }
    return false;
}
static void update_backend(sl_sns *b, uint64_t now) {
    if (!b || !b->initialized)
        return;
    SteamNetworkingSockets_Poll(0);
#if NSL_SNS_PROBES
    sl_gns_sdr_probe_update(b->relay_probe);
#endif
    b->sockets->RunCallbacks();
    pump_config(b);
#if NSL_ENABLE_SDR && NSL_SNS_PROBES
    if (b->connection)
        sl_gns_sdr_transport_stats(b->connection, b->sdr_debug);
#endif
    bool connected = check_connection(b, now);
    {
        /* SDK callbacks only enqueue. Never hold this mutex across an SDK call
         * that might call SendSignal again. */
        std::deque<Message> signals;
        {
            std::lock_guard<std::mutex> lock(b->q->mutex);
            signals.swap(b->q->signals);
        }
        for (const auto &p : signals)
            if (!sl_stream_bridge_queue(b->bridge, p.data(), p.size())) {
                close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_SIGNAL_QUEUE);
                break;
            }
    }
    sl_stream_bridge_update(b->bridge, now,
        b->q->state == SL_SNS_CONNECTING || b->q->state == SL_SNS_CONNECTED);
    if (!connected || b->q->state != SL_SNS_CONNECTED)
        return;
    for (unsigned budget = 0; budget < 512; ++budget) {
        Message outgoing;
        {
            std::lock_guard<std::mutex> lock(b->q->mutex);
            if (b->q->tx.empty())
                break;
            outgoing = b->q->tx.take();
        }
        EResult ret = b->sockets->SendMessageToConnection(b->connection, outgoing.data(),
            static_cast<uint32_t>(outgoing.size()), 0x15, nullptr);
        if (ret == k_EResultLimitExceeded || ret == k_EResultIgnored) {
            std::lock_guard<std::mutex> lock(b->q->mutex);
            b->q->tx.retry(std::move(outgoing));
            break;
        }
        if (ret != k_EResultOK) {
            close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_SEND, ret);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(b->q->mutex);
            b->q->tx.finish(outgoing.size());
        }
        ++b->stats.datagrams_sent;
    }
    SteamNetworkingMessage_t *messages[128];
    for (unsigned batch = 0; batch < 32; ++batch) {
        int count = b->sockets->ReceiveMessagesOnConnection(b->connection, messages, 128);
        if (count < 0) {
            close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_RECEIVE, count);
            return;
        }
        bool overflow = false;
        {
            std::lock_guard<std::mutex> lock(b->q->mutex);
            for (int i = 0; i < count; ++i) {
                SteamNetworkingMessage_t *m = messages[i];
                ++b->stats.datagrams_received;
                if (!overflow && (m->m_cbSize < 0 || !b->q->rx.push(
                        static_cast<const uint8_t *>(m->m_pData),
                        static_cast<size_t>(m->m_cbSize), DATAGRAM_MAX)))
                    overflow = true;
                m->Release();
            }
        }
        b->q->wake.notify_all();
        if (overflow) {
            close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_DATAGRAM);
            return;
        }
        if (count < 128)
            break;
    }
}
extern "C" void sl_sns_update(sl_sns *b, uint64_t now) {
    try { update_backend(b, now); }
    catch (const std::bad_alloc &) {
        if (b)
            close_backend(b, SL_SNS_FAILED, SL_SNS_TERMINAL_MEMORY);
    }
}
extern "C" sl_sns_state sl_sns_get_state(const sl_sns *b) {
    return b ? b->q->state.load() : SL_SNS_CLOSED;
}
extern "C" int sl_sns_end_reason(const sl_sns *b) { return b ? b->end_reason : 0; }
extern "C" void sl_sns_get_stats(const sl_sns *b, sl_sns_stats *out) {
    if (out)
        *out = b ? b->stats : sl_sns_stats{};
}
#if NSL_SNS_PROBES
extern "C" bool sl_sns_start_relay_probe(sl_sns *b) {
    if (!b || !b->connection || b->relay_probe || b->q->state != SL_SNS_CONNECTED)
        return false;
    b->relay_probe = sl_gns_sdr_probe_create(b->connection, b->config.data(), b->config.size());
    return b->relay_probe != nullptr;
}
extern "C" void sl_sns_relay_probe_stats(const sl_sns *b, unsigned out[5]) {
    if (!out)
        return;
    sl_sdr_probe_stats s{};
    if (b)
        sl_gns_sdr_probe_stats(b->relay_probe, &s);
    out[0] = s.sent_pings;
    out[1] = s.valid_ping_replies;
    out[2] = s.requests;
    out[3] = s.established;
    out[4] = s.rejected;
}
extern "C" void sl_sns_sdr_debug(const sl_sns *b, unsigned out[16]) {
    if (b && out)
        memcpy(out, b->sdr_debug, sizeof(b->sdr_debug));
}
extern "C" bool sl_sns_test_relay_loss(sl_sns *b, int mode, unsigned out[5]) {
#if NSL_ENABLE_SDR
    bool result=b && b->connection && sl_gns_sdr_test_loss(b->connection, mode, out);
    if (result && mode>=0) b->observe_loss=mode!=0;
    return result;
#else
    (void)b; (void)mode; (void)out;
    return false;
#endif
}
extern "C" bool sl_sns_test_migration(sl_sns *b, bool start, unsigned out[6]) {
#if NSL_ENABLE_SDR
    return b && b->connection && sl_gns_sdr_test_migration(b->connection,start,out);
#else
    (void)b; (void)start; (void)out; return false;
#endif
}
extern "C" bool sl_sns_loss_snapshot(sl_sns *b, sl_sdr_loss_snapshot *out) {
#if NSL_ENABLE_SDR
    if (!b || !out) return false;
    if (b->connection && sl_gns_sdr_loss_snapshot(b->connection,out)) return true;
    if (!b->terminal_loss_valid) return false;
    *out=b->terminal_loss;
    return true;
#else
    (void)b; (void)out; return false;
#endif
}
extern "C" bool sl_sns_test_terminal(sl_sns *b, int packet_case) {
#if NSL_ENABLE_SDR
    return b && b->connection && sl_gns_sdr_test_terminal(b->connection, packet_case);
#else
    (void)b; (void)packet_case;
    return false;
#endif
}
#endif
extern "C" int sl_sns_set_mtu(sl_sns *b, int mtu) {
    if (!b || !b->connection || mtu <= 0 ||
        !SteamNetworkingUtils()->SetConnectionConfigValueInt32(b->connection,
            k_ESteamNetworkingConfig_MTU_PacketSize, mtu))
        return -1;
    int32_t result = 0;
    size_t size = sizeof(result);
    ESteamNetworkingGetConfigValueResult ret = SteamNetworkingUtils()->GetConfigValue(
        k_ESteamNetworkingConfig_MTU_DataSize, k_ESteamNetworkingConfig_Connection,
        b->connection, nullptr, &result, &size);
    return ret > 0 && size == sizeof(result) ? result : -1;
}
static bool send_datagram(void *ctx, const uint8_t *p, size_t n) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (!b)
        return false;
    std::lock_guard<std::mutex> lock(b->q->mutex);
    return b->q->state == SL_SNS_CONNECTED && b->q->tx.push(p, n, DATAGRAM_MAX);
}
static int wait_datagram(void *ctx, uint32_t wait_us) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (!b) return -1;
    std::unique_lock<std::mutex> lock(b->q->mutex);
    b->q->wake.wait_for(lock, std::chrono::microseconds(wait_us), [&] {
        return !b->q->rx.empty() || b->q->state != SL_SNS_CONNECTED;
    });
    if (b->q->state != SL_SNS_CONNECTED) return -1;
    return b->q->rx.empty() ? 0 : 1;
}
static int receive_datagram(void *ctx, uint8_t *p, size_t capacity,
                            size_t *received, uint32_t wait_us) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (!b || !p || !received) return -1;
    std::unique_lock<std::mutex> lock(b->q->mutex);
    if (wait_us)
        b->q->wake.wait_for(lock, std::chrono::microseconds(wait_us), [&] {
            return !b->q->rx.empty() || b->q->state != SL_SNS_CONNECTED;
        });
    /* Like official Recv, terminal handle state takes priority over old data. */
    if (b->q->state != SL_SNS_CONNECTED) return -1;
    if (b->q->rx.empty()) return 0;
    const Message &m = b->q->rx.front();
    if (m.size() > capacity) return -1;
    *received = m.size();
    if (*received) memcpy(p, m.data(), *received);
    b->q->rx.pop();
    return 1;
}
static size_t next_datagram_size(void *ctx) {
    sl_sns *b = static_cast<sl_sns *>(ctx);
    if (!b) return 0;
    std::lock_guard<std::mutex> lock(b->q->mutex);
    return b->q->rx.empty() ? 0 : b->q->rx.front().size();
}
extern "C" const IHS_DatagramTransport *sl_sns_datagram_transport(void) {
    static const IHS_DatagramTransport callbacks = {
        send_datagram, receive_datagram, wait_datagram, DATAGRAM_MAX, next_datagram_size};
    return &callbacks;
}
extern "C" void sl_sns_destroy(sl_sns *b) {
    if (!b)
        return;
    /* The owner first stops/joins IHS users of the datagram callbacks. Detach
     * SDK callbacks before closing the handle; their shared queue stays alive
     * until the SDK releases its signaling object. */
    {
        std::lock_guard<std::mutex> lock(b->q->mutex);
        b->q->owner = false;
    }
    close_backend(b, SL_SNS_CLOSED);
#if NSL_SNS_PROBES
    sl_gns_sdr_probe_destroy(b->relay_probe);
#endif
    if (!b->certificate.empty())
        wipe(b->certificate.data(), b->certificate.size());
    if (b->request) {
        curl_multi_remove_handle(b->http, b->request);
        curl_easy_cleanup(b->request);
    }
    if (b->http)
        curl_multi_cleanup(b->http);
    sl_stream_bridge_destroy(b->bridge);
    if (b->initialized)
        GameNetworkingSockets_Kill();
    SteamNetworkingSockets_SetManualPollMode(false);
    delete b;
    sdk_owned = false;
}
